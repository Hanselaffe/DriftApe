"""Deterministic detection-rule evaluation for canonical DriftApe changes."""

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum

from driftape.diff import Change, ChangeType


class FindingSeverity(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    rule_id: str
    severity: FindingSeverity
    title: str
    message: str
    domain: str
    change_ids: tuple[str, ...]


class InvalidRuleInputError(ValueError):
    """Raised when rule evaluation input is not a valid canonical Change tuple."""


@dataclass(frozen=True, slots=True)
class _RuleText:
    severity: FindingSeverity
    title: str
    message: str


_RULE_TEXT = {
    "DA-USR-001": _RuleText(
        FindingSeverity.MEDIUM,
        "Local user added",
        "A local user account was added and should be reviewed.",
    ),
    "DA-USR-002": _RuleText(
        FindingSeverity.INFO,
        "Local user removed",
        "A local user account was removed.",
    ),
    "DA-USR-003": _RuleText(
        FindingSeverity.MEDIUM,
        "Local user enabled",
        "A previously disabled local user account was enabled.",
    ),
    "DA-USR-004": _RuleText(
        FindingSeverity.INFO,
        "Local user disabled",
        "A previously enabled local user account was disabled.",
    ),
    "DA-USR-005": _RuleText(
        FindingSeverity.LOW,
        "Local username changed",
        "The name of an existing local user SID changed.",
    ),
    "DA-USR-006": _RuleText(
        FindingSeverity.LOW,
        "Local user principal source changed",
        "The principal source of an existing local user SID changed.",
    ),
    "DA-ADM-001": _RuleText(
        FindingSeverity.HIGH,
        "Local administrator added",
        "Principal added to the local Administrators group; this increases local administrative access and requires review.",
    ),
    "DA-ADM-002": _RuleText(
        FindingSeverity.INFO,
        "Local administrator removed",
        "A principal was removed from the local Administrators group.",
    ),
    "DA-SVC-001": _RuleText(
        FindingSeverity.MEDIUM,
        "Service added",
        "A Windows service was added and should be reviewed.",
    ),
    "DA-SVC-002": _RuleText(
        FindingSeverity.INFO,
        "Service removed",
        "A Windows service was removed.",
    ),
    "DA-SVC-003": _RuleText(
        FindingSeverity.HIGH,
        "Service path changed",
        "The configured service executable or command path changed and requires review.",
    ),
    "DA-SVC-004": _RuleText(
        FindingSeverity.HIGH,
        "Service account changed",
        "The configured service account changed and requires review.",
    ),
    "DA-SVC-005": _RuleText(
        FindingSeverity.MEDIUM,
        "Service start mode changed to automatic",
        "The service start mode changed to automatic.",
    ),
    "DA-SVC-006": _RuleText(
        FindingSeverity.LOW,
        "Service start mode changed",
        "The configured service start mode changed.",
    ),
    "DA-SVC-007": _RuleText(
        FindingSeverity.INFO,
        "Service display name changed",
        "The service display name changed.",
    ),
    "DA-TASK-001": _RuleText(
        FindingSeverity.MEDIUM,
        "Scheduled task added",
        "A scheduled task was added and should be reviewed.",
    ),
    "DA-TASK-002": _RuleText(
        FindingSeverity.INFO,
        "Scheduled task removed",
        "A scheduled task was removed.",
    ),
    "DA-TASK-003": _RuleText(
        FindingSeverity.HIGH,
        "Scheduled task actions changed",
        "The configured actions of a scheduled task changed and require review.",
    ),
    "DA-TASK-004": _RuleText(
        FindingSeverity.HIGH,
        "Scheduled task principals changed",
        "The configured execution principals of a scheduled task changed and require review.",
    ),
    "DA-TASK-005": _RuleText(
        FindingSeverity.MEDIUM,
        "Scheduled task triggers changed",
        "The configured triggers of a scheduled task changed.",
    ),
    "DA-DEF-001": _RuleText(
        FindingSeverity.HIGH,
        "Defender exclusion added",
        "A Microsoft Defender exclusion was added and requires review.",
    ),
    "DA-DEF-002": _RuleText(
        FindingSeverity.INFO,
        "Defender exclusion removed",
        "A Microsoft Defender exclusion was removed.",
    ),
    "DA-DEF-003": _RuleText(
        FindingSeverity.HIGH,
        "Defender real-time monitoring disabled",
        "Microsoft Defender real-time monitoring configuration changed from enabled to disabled.",
    ),
    "DA-DEF-004": _RuleText(
        FindingSeverity.INFO,
        "Defender real-time monitoring enabled",
        "Microsoft Defender real-time monitoring configuration changed from disabled to enabled.",
    ),
    "DA-DEF-005": _RuleText(
        FindingSeverity.HIGH,
        "Defender real-time protection degraded",
        "Microsoft Defender real-time protection state changed from enabled to disabled and requires review.",
    ),
    "DA-DEF-006": _RuleText(
        FindingSeverity.INFO,
        "Defender real-time protection restored",
        "Microsoft Defender real-time protection state changed from disabled to enabled.",
    ),
}


def _is_exact_bool_transition(old_value: object, new_value: object, old: bool, new: bool) -> bool:
    return (
        type(old_value) is bool
        and type(new_value) is bool
        and old_value is old
        and new_value is new
    )


def _match_rule(change: Change) -> str | None:
    if change.domain == "users.local_users":
        if change.change_type is ChangeType.ADDED:
            return "DA-USR-001"
        if change.change_type is ChangeType.REMOVED:
            return "DA-USR-002"
        if change.change_type is ChangeType.MODIFIED:
            if change.property == "enabled":
                if _is_exact_bool_transition(change.old_value, change.new_value, False, True):
                    return "DA-USR-003"
                if _is_exact_bool_transition(change.old_value, change.new_value, True, False):
                    return "DA-USR-004"
            if change.property == "name":
                return "DA-USR-005"
            if change.property == "principal_source":
                return "DA-USR-006"
        return None

    if change.domain == "users.administrators":
        if change.change_type is ChangeType.ADDED:
            return "DA-ADM-001"
        if change.change_type is ChangeType.REMOVED:
            return "DA-ADM-002"
        return None

    if change.domain == "services.services":
        if change.change_type is ChangeType.ADDED:
            return "DA-SVC-001"
        if change.change_type is ChangeType.REMOVED:
            return "DA-SVC-002"
        if change.change_type is ChangeType.MODIFIED:
            if change.property == "path_name":
                return "DA-SVC-003"
            if change.property == "start_name":
                return "DA-SVC-004"
            if change.property == "start_mode":
                if change.new_value == "auto":
                    return "DA-SVC-005"
                return "DA-SVC-006"
            if change.property == "display_name":
                return "DA-SVC-007"
        return None

    if change.domain == "tasks.tasks":
        if change.change_type is ChangeType.ADDED:
            return "DA-TASK-001"
        if change.change_type is ChangeType.REMOVED:
            return "DA-TASK-002"
        if change.change_type is ChangeType.MODIFIED:
            if change.property == "actions":
                return "DA-TASK-003"
            if change.property == "principals":
                return "DA-TASK-004"
            if change.property == "triggers":
                return "DA-TASK-005"
        return None

    if change.domain == "defender.exclusions":
        if change.change_type is ChangeType.ADDED:
            return "DA-DEF-001"
        if change.change_type is ChangeType.REMOVED:
            return "DA-DEF-002"
        return None

    if change.domain == "defender.configuration":
        if change.change_type is ChangeType.MODIFIED and change.property == "disable_realtime_monitoring":
            if _is_exact_bool_transition(change.old_value, change.new_value, False, True):
                return "DA-DEF-003"
            if _is_exact_bool_transition(change.old_value, change.new_value, True, False):
                return "DA-DEF-004"
        return None

    if change.domain == "defender.runtime":
        if change.change_type is ChangeType.MODIFIED and change.property == "real_time_protection_enabled":
            if _is_exact_bool_transition(change.old_value, change.new_value, True, False):
                return "DA-DEF-005"
            if _is_exact_bool_transition(change.old_value, change.new_value, False, True):
                return "DA-DEF-006"
        return None

    return None


def _finding_id(rule_id: str, change_id: str) -> str:
    payload = {"rule_id": rule_id, "change_ids": [change_id]}
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(f"{canonical}\n".encode("utf-8")).hexdigest()


def evaluate_changes(changes: tuple[Change, ...]) -> tuple[Finding, ...]:
    """Evaluate canonical changes against the frozen DriftApe v0.1 rule table."""
    seen_change_ids: set[str] = set()
    for change in changes:
        if not isinstance(change, Change):
            raise InvalidRuleInputError("rule input contains a non-Change member")
        if change.change_id in seen_change_ids:
            raise InvalidRuleInputError(f"duplicate change_id: {change.change_id}")
        seen_change_ids.add(change.change_id)

    findings: list[Finding] = []
    for change in changes:
        rule_id = _match_rule(change)
        if rule_id is None:
            continue
        rule_text = _RULE_TEXT[rule_id]
        findings.append(
            Finding(
                finding_id=_finding_id(rule_id, change.change_id),
                rule_id=rule_id,
                severity=rule_text.severity,
                title=rule_text.title,
                message=rule_text.message,
                domain=change.domain,
                change_ids=(change.change_id,),
            )
        )

    findings.sort(key=lambda finding: (finding.rule_id, finding.change_ids[0]))
    return tuple(findings)
