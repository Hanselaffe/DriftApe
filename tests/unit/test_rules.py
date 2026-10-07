from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, fields, is_dataclass, replace
from pathlib import Path
from typing import Any, get_type_hints

import pytest

from driftape.diff import Change, ChangeType
from driftape.rules import (
    Finding,
    FindingSeverity,
    InvalidRuleInputError,
    evaluate_changes,
)


RULE_CASES = (
    ("DA-USR-001", "users.local_users", ChangeType.ADDED, None, None, {"id": "new"}, FindingSeverity.MEDIUM),
    ("DA-USR-002", "users.local_users", ChangeType.REMOVED, None, {"id": "old"}, None, FindingSeverity.INFO),
    ("DA-USR-003", "users.local_users", ChangeType.MODIFIED, "enabled", False, True, FindingSeverity.MEDIUM),
    ("DA-USR-004", "users.local_users", ChangeType.MODIFIED, "enabled", True, False, FindingSeverity.INFO),
    ("DA-USR-005", "users.local_users", ChangeType.MODIFIED, "name", "alice", "alice2", FindingSeverity.LOW),
    ("DA-USR-006", "users.local_users", ChangeType.MODIFIED, "principal_source", "local", "active_directory", FindingSeverity.LOW),
    ("DA-ADM-001", "users.administrators", ChangeType.ADDED, None, None, {"id": "S-1"}, FindingSeverity.HIGH),
    ("DA-ADM-002", "users.administrators", ChangeType.REMOVED, None, {"id": "S-1"}, None, FindingSeverity.INFO),
    ("DA-SVC-001", "services.services", ChangeType.ADDED, None, None, {"id": "svc"}, FindingSeverity.MEDIUM),
    ("DA-SVC-002", "services.services", ChangeType.REMOVED, None, {"id": "svc"}, None, FindingSeverity.INFO),
    ("DA-SVC-003", "services.services", ChangeType.MODIFIED, "path_name", "old.exe", "new.exe", FindingSeverity.HIGH),
    ("DA-SVC-004", "services.services", ChangeType.MODIFIED, "start_name", "LocalSystem", "svc-user", FindingSeverity.HIGH),
    ("DA-SVC-005", "services.services", ChangeType.MODIFIED, "start_mode", "manual", "auto", FindingSeverity.MEDIUM),
    ("DA-SVC-006", "services.services", ChangeType.MODIFIED, "start_mode", "auto", "disabled", FindingSeverity.LOW),
    ("DA-SVC-007", "services.services", ChangeType.MODIFIED, "display_name", "Old", "New", FindingSeverity.INFO),
    ("DA-TASK-001", "tasks.tasks", ChangeType.ADDED, None, None, {"id": "task"}, FindingSeverity.MEDIUM),
    ("DA-TASK-002", "tasks.tasks", ChangeType.REMOVED, None, {"id": "task"}, None, FindingSeverity.INFO),
    ("DA-TASK-003", "tasks.tasks", ChangeType.MODIFIED, "actions", [{"type": "Exec"}], [{"type": "ComHandler"}], FindingSeverity.HIGH),
    ("DA-TASK-004", "tasks.tasks", ChangeType.MODIFIED, "principals", [{"id": "a"}], [{"id": "b"}], FindingSeverity.HIGH),
    ("DA-TASK-005", "tasks.tasks", ChangeType.MODIFIED, "triggers", [{"type": "Boot"}], [{"type": "Logon"}], FindingSeverity.MEDIUM),
    ("DA-DEF-001", "defender.exclusions", ChangeType.ADDED, None, None, {"id": "path:c:/temp"}, FindingSeverity.HIGH),
    ("DA-DEF-002", "defender.exclusions", ChangeType.REMOVED, None, {"id": "path:c:/temp"}, None, FindingSeverity.INFO),
    ("DA-DEF-003", "defender.configuration", ChangeType.MODIFIED, "disable_realtime_monitoring", False, True, FindingSeverity.HIGH),
    ("DA-DEF-004", "defender.configuration", ChangeType.MODIFIED, "disable_realtime_monitoring", True, False, FindingSeverity.INFO),
    ("DA-DEF-005", "defender.runtime", ChangeType.MODIFIED, "real_time_protection_enabled", True, False, FindingSeverity.HIGH),
    ("DA-DEF-006", "defender.runtime", ChangeType.MODIFIED, "real_time_protection_enabled", False, True, FindingSeverity.INFO),
)

EXPECTED_TEXT = {
    "DA-USR-001": ("Local user added", "A local user account was added and should be reviewed."),
    "DA-USR-002": ("Local user removed", "A local user account was removed."),
    "DA-USR-003": ("Local user enabled", "A previously disabled local user account was enabled."),
    "DA-USR-004": ("Local user disabled", "A previously enabled local user account was disabled."),
    "DA-USR-005": ("Local username changed", "The name of an existing local user SID changed."),
    "DA-USR-006": ("Local user principal source changed", "The principal source of an existing local user SID changed."),
    "DA-ADM-001": ("Local administrator added", "Principal added to the local Administrators group; this increases local administrative access and requires review."),
    "DA-ADM-002": ("Local administrator removed", "A principal was removed from the local Administrators group."),
    "DA-SVC-001": ("Service added", "A Windows service was added and should be reviewed."),
    "DA-SVC-002": ("Service removed", "A Windows service was removed."),
    "DA-SVC-003": ("Service path changed", "The configured service executable or command path changed and requires review."),
    "DA-SVC-004": ("Service account changed", "The configured service account changed and requires review."),
    "DA-SVC-005": ("Service start mode changed to automatic", "The service start mode changed to automatic."),
    "DA-SVC-006": ("Service start mode changed", "The configured service start mode changed."),
    "DA-SVC-007": ("Service display name changed", "The service display name changed."),
    "DA-TASK-001": ("Scheduled task added", "A scheduled task was added and should be reviewed."),
    "DA-TASK-002": ("Scheduled task removed", "A scheduled task was removed."),
    "DA-TASK-003": ("Scheduled task actions changed", "The configured actions of a scheduled task changed and require review."),
    "DA-TASK-004": ("Scheduled task principals changed", "The configured execution principals of a scheduled task changed and require review."),
    "DA-TASK-005": ("Scheduled task triggers changed", "The configured triggers of a scheduled task changed."),
    "DA-DEF-001": ("Defender exclusion added", "A Microsoft Defender exclusion was added and requires review."),
    "DA-DEF-002": ("Defender exclusion removed", "A Microsoft Defender exclusion was removed."),
    "DA-DEF-003": ("Defender real-time monitoring disabled", "Microsoft Defender real-time monitoring configuration changed from enabled to disabled."),
    "DA-DEF-004": ("Defender real-time monitoring enabled", "Microsoft Defender real-time monitoring configuration changed from disabled to enabled."),
    "DA-DEF-005": ("Defender real-time protection degraded", "Microsoft Defender real-time protection state changed from enabled to disabled and requires review."),
    "DA-DEF-006": ("Defender real-time protection restored", "Microsoft Defender real-time protection state changed from disabled to enabled."),
}


def _change(
    rule_id: str,
    domain: str,
    change_type: ChangeType,
    property_name: str | None,
    old_value: object,
    new_value: object,
    *,
    change_id: str | None = None,
    object_name: str = "object-name",
) -> Change:
    return Change(
        change_id=change_id or f"change-{rule_id.lower()}",
        domain=domain,
        object_type="test-object",
        object_id=f"object-{rule_id.lower()}",
        object_name=object_name,
        change_type=change_type,
        property=property_name,
        old_value=old_value,
        new_value=new_value,
    )


def _case_change(case: tuple[Any, ...], **kwargs: object) -> Change:
    rule_id, domain, change_type, property_name, old_value, new_value, _severity = case
    return _change(rule_id, domain, change_type, property_name, old_value, new_value, **kwargs)


def _result_rule_ids(*changes: Change) -> tuple[str, ...]:
    return tuple(finding.rule_id for finding in evaluate_changes(tuple(changes)))


@pytest.mark.parametrize("case", RULE_CASES, ids=lambda case: case[0])
def test_each_frozen_rule_positive_severity_binding_and_text(case: tuple[Any, ...]) -> None:
    rule_id, domain, _change_type, _property, _old, _new, severity = case
    change = _case_change(case)
    findings = evaluate_changes((change,))
    assert len(findings) == 1, rule_id
    finding = findings[0]
    assert finding.rule_id == rule_id
    assert finding.severity is severity
    assert finding.change_ids == (change.change_id,)
    assert finding.domain == domain
    assert (finding.title, finding.message) == EXPECTED_TEXT[rule_id]


@pytest.mark.parametrize("case", RULE_CASES, ids=lambda case: case[0])
def test_each_frozen_rule_has_negative_case(case: tuple[Any, ...]) -> None:
    rule_id, domain, change_type, property_name, old_value, new_value, _severity = case
    if change_type is ChangeType.ADDED:
        negative_type = ChangeType.MODIFIED
        negative_property = "unlisted"
        negative_old = "a"
        negative_new = "b"
    elif change_type is ChangeType.REMOVED:
        negative_type = ChangeType.MODIFIED
        negative_property = "unlisted"
        negative_old = "a"
        negative_new = "b"
    elif rule_id == "DA-SVC-006":
        negative_type = ChangeType.MODIFIED
        negative_property = "start_mode"
        negative_old = "manual"
        negative_new = "auto"
    elif isinstance(old_value, bool) and isinstance(new_value, bool):
        negative_type = ChangeType.MODIFIED
        negative_property = property_name
        negative_old = old_value
        negative_new = old_value
    else:
        negative_type = ChangeType.MODIFIED
        negative_property = "unlisted"
        negative_old = old_value
        negative_new = new_value
    negative = _change(
        f"negative-{rule_id}",
        domain,
        negative_type,
        negative_property,
        negative_old,
        negative_new,
    )
    assert rule_id not in _result_rule_ids(negative)


def test_finding_model_contract_is_frozen_slotted_and_typed() -> None:
    assert is_dataclass(Finding)
    assert [field.name for field in fields(Finding)] == [
        "finding_id",
        "rule_id",
        "severity",
        "title",
        "message",
        "domain",
        "change_ids",
    ]
    hints = get_type_hints(Finding)
    assert hints["severity"] is FindingSeverity
    assert hints["change_ids"] == tuple[str, ...]
    finding = evaluate_changes((_case_change(RULE_CASES[0]),))[0]
    assert not hasattr(finding, "__dict__")
    with pytest.raises(FrozenInstanceError):
        finding.title = "changed"  # type: ignore[misc]


def test_finding_severity_exact_members_and_no_unknown() -> None:
    assert tuple(member.value for member in FindingSeverity) == ("HIGH", "MEDIUM", "LOW", "INFO")
    assert not hasattr(FindingSeverity, "UNKNOWN")


def test_all_26_rule_ids_are_unique_and_text_is_fixed_nonempty_and_neutral() -> None:
    rule_ids = [case[0] for case in RULE_CASES]
    assert len(rule_ids) == 26
    assert len(set(rule_ids)) == 26
    assert set(rule_ids) == set(EXPECTED_TEXT)
    forbidden = ("compromised", "attacker", "malware", "persistence established", "privilege escalation occurred", "defense evasion occurred", "malicious", "breach")
    for rule_id, (title, message) in EXPECTED_TEXT.items():
        assert title, rule_id
        assert message, rule_id
        lowered = message.lower()
        assert all(term not in lowered for term in forbidden), rule_id


def test_rule_isolation_across_local_users_and_administrators() -> None:
    user_added = _case_change(RULE_CASES[0])
    admin_added = _case_change(RULE_CASES[6])
    assert _result_rule_ids(user_added) == ("DA-USR-001",)
    assert _result_rule_ids(admin_added) == ("DA-ADM-001",)


def test_service_rule_isolation_and_start_mode_exclusivity() -> None:
    path_change = _case_change(RULE_CASES[10])
    account_change = _case_change(RULE_CASES[11])
    auto_change = _case_change(RULE_CASES[12])
    other_change = _case_change(RULE_CASES[13])
    assert _result_rule_ids(path_change) == ("DA-SVC-003",)
    assert _result_rule_ids(account_change) == ("DA-SVC-004",)
    assert _result_rule_ids(auto_change) == ("DA-SVC-005",)
    assert _result_rule_ids(other_change) == ("DA-SVC-006",)


def test_task_modified_properties_are_mutually_distinct() -> None:
    actions = _case_change(RULE_CASES[17])
    principals = _case_change(RULE_CASES[18])
    triggers = _case_change(RULE_CASES[19])
    assert _result_rule_ids(actions) == ("DA-TASK-003",)
    assert _result_rule_ids(principals) == ("DA-TASK-004",)
    assert _result_rule_ids(triggers) == ("DA-TASK-005",)


def test_defender_configuration_and_runtime_are_isolated() -> None:
    config = _case_change(RULE_CASES[22])
    runtime = _case_change(RULE_CASES[24])
    assert _result_rule_ids(config) == ("DA-DEF-003",)
    assert _result_rule_ids(runtime) == ("DA-DEF-005",)
    cross_config = replace(config, domain="defender.runtime")
    cross_runtime = replace(runtime, domain="defender.configuration")
    assert evaluate_changes((cross_config,)) == ()
    assert evaluate_changes((cross_runtime,)) == ()


@pytest.mark.parametrize(
    ("domain", "property_name"),
    (
        ("defender.exclusions", "value"),
        ("services.services", "name"),
        ("tasks.tasks", "task_path"),
        ("tasks.tasks", "task_name"),
        ("users.administrators", "name"),
    ),
)
def test_unlisted_modified_changes_are_unmatched(domain: str, property_name: str) -> None:
    change = _change("neutral", domain, ChangeType.MODIFIED, property_name, "old", "new")
    assert evaluate_changes((change,)) == ()


BOOLEAN_CASES = (
    RULE_CASES[2],
    RULE_CASES[3],
    RULE_CASES[22],
    RULE_CASES[23],
    RULE_CASES[24],
    RULE_CASES[25],
)


@pytest.mark.parametrize("case", BOOLEAN_CASES, ids=lambda case: case[0])
def test_boolean_rules_require_exact_transitions(case: tuple[Any, ...]) -> None:
    rule_id, domain, _change_type, property_name, old_value, new_value, _severity = case
    wrong_direction = _change(rule_id + "-reverse", domain, ChangeType.MODIFIED, property_name, new_value, old_value)
    same_values = _change(rule_id + "-same", domain, ChangeType.MODIFIED, property_name, old_value, old_value)
    string_values = _change(rule_id + "-str", domain, ChangeType.MODIFIED, property_name, str(old_value).lower(), str(new_value).lower())
    integer_values = _change(rule_id + "-int", domain, ChangeType.MODIFIED, property_name, int(old_value), int(new_value))
    for candidate in (wrong_direction, same_values, string_values, integer_values):
        assert rule_id not in _result_rule_ids(candidate), rule_id


def _expected_finding_id(rule_id: str, change_id: str) -> str:
    payload = {"rule_id": rule_id, "change_ids": [change_id]}
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(f"{canonical}\n".encode("utf-8")).hexdigest()


def test_finding_id_independently_matches_high_and_info_rules() -> None:
    high_change = _case_change(RULE_CASES[6], change_id="high-change-id")
    info_change = _case_change(RULE_CASES[7], change_id="info-change-id")
    findings = {finding.rule_id: finding for finding in evaluate_changes((high_change, info_change))}
    assert findings["DA-ADM-001"].finding_id == _expected_finding_id("DA-ADM-001", "high-change-id")
    assert findings["DA-ADM-002"].finding_id == _expected_finding_id("DA-ADM-002", "info-change-id")


def test_finding_ids_repeat_and_ignore_object_name_and_time() -> None:
    change = _case_change(RULE_CASES[10], change_id="stable-id", object_name="first")
    same_id_other_name = replace(change, object_name="second")
    first = evaluate_changes((change,))[0]
    second = evaluate_changes((change,))[0]
    renamed = evaluate_changes((same_id_other_name,))[0]
    assert first.finding_id == second.finding_id == renamed.finding_id
    assert "timestamp" not in get_type_hints(Finding)


def test_input_order_does_not_affect_finding_tuple_order() -> None:
    changes = (
        _case_change(RULE_CASES[17], change_id="c3"),
        _case_change(RULE_CASES[0], change_id="c2"),
        _case_change(RULE_CASES[6], change_id="c1"),
    )
    assert evaluate_changes(changes) == evaluate_changes(tuple(reversed(changes)))
    findings = evaluate_changes(changes)
    assert [(f.rule_id, f.change_ids[0]) for f in findings] == sorted((f.rule_id, f.change_ids[0]) for f in findings)


def test_multiple_changes_for_one_rule_sort_by_change_id() -> None:
    first = _case_change(RULE_CASES[0], change_id="z-id")
    second = _case_change(RULE_CASES[0], change_id="a-id")
    findings = evaluate_changes((first, second))
    assert [finding.change_ids[0] for finding in findings] == ["a-id", "z-id"]


def test_invalid_non_change_member_is_rejected() -> None:
    with pytest.raises(InvalidRuleInputError, match="non-Change"):
        evaluate_changes((object(),))  # type: ignore[arg-type]


def test_duplicate_change_ids_are_rejected_even_if_different_changes() -> None:
    first = _case_change(RULE_CASES[0], change_id="duplicate")
    second = _case_change(RULE_CASES[6], change_id="duplicate")
    with pytest.raises(InvalidRuleInputError, match="duplicate change_id"):
        evaluate_changes((first, second))


def test_empty_tuple_and_unsupported_valid_change_return_empty() -> None:
    unsupported = _change("unsupported", "future.domain", ChangeType.ADDED, None, None, "value")
    assert evaluate_changes(()) == ()
    assert evaluate_changes((unsupported,)) == ()


def test_rules_module_boundary_enforcement() -> None:
    source = (Path(__file__).parents[2] / "driftape" / "rules.py").read_text(encoding="utf-8")
    forbidden = (
        "Snapshot",
        "CollectorSet",
        "collect_snapshot",
        "collect_users",
        "collect_services",
        "collect_tasks",
        "collect_defender",
        "run_powershell_json",
        "compare_snapshots",
        "integrity",
        "serialization",
        "reporting",
        "argparse",
        "subprocess",
        "pathlib",
        "open(",
        "Path(",
    )
    for term in forbidden:
        assert term not in source, term
    for expected in ("Change", "ChangeType", "Finding", "FindingSeverity", "HIGH", "MEDIUM", "LOW", "INFO", "DA-USR", "DA-ADM", "DA-SVC", "DA-TASK", "DA-DEF", "hashlib", "json"):
        assert expected in source, expected
