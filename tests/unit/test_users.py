"""WP4 local users and Administrators collector tests."""

from __future__ import annotations

import inspect
import pytest

from driftape.acquisition import powershell
from driftape.collectors import users
from driftape.models import (
    AdministratorMember,
    CollectorStatus,
    ErrorCode,
    LocalUser,
    PrincipalSource,
    UsersCollectorResult,
)


def _user(
    sid: str = "S-1-5-21-1000",
    name: str = "alice",
    enabled: object = True,
    principal_source: object = "Local",
) -> dict[str, object]:
    return {
        "SID": sid,
        "Name": name,
        "Enabled": enabled,
        "PrincipalSource": principal_source,
    }


def _administrator(
    sid: str = "S-1-5-21-1000",
    name: str = r"HOST\alice",
    object_class: object = "User",
    principal_source: object = "Local",
) -> dict[str, object]:
    return {
        "SID": sid,
        "Name": name,
        "ObjectClass": object_class,
        "PrincipalSource": principal_source,
    }


def _success_section(items: list[object]) -> dict[str, object]:
    return {"ok": True, "items": items, "error": None}


def _failed_section(
    *,
    category: object = "NotSpecified",
    message: object = "synthetic failure",
    native_code: object = -1,
) -> dict[str, object]:
    return {
        "ok": False,
        "items": None,
        "error": {
            "category": category,
            "message": message,
            "native_code": native_code,
            "fully_qualified_error_id": "SyntheticFailure",
        },
    }


def _document(
    *,
    local_users: object | None = None,
    administrators: object | None = None,
) -> dict[str, object]:
    return {
        "local_users": (
            _success_section([_user()]) if local_users is None else local_users
        ),
        "administrators": (
            _success_section([_administrator()])
            if administrators is None
            else administrators
        ),
    }


@pytest.fixture(autouse=True)
def supported_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        users.platform_windows, "require_supported_platform", lambda: None
    )


def _collect(monkeypatch: pytest.MonkeyPatch, document: object) -> UsersCollectorResult:
    monkeypatch.setattr(
        users.powershell,
        "run_powershell_json",
        lambda _script, *, timeout_seconds: document,
    )
    return users.collect_users()


def _assert_result_contract(result: UsersCollectorResult) -> None:
    full = frozenset({"local_users", "administrators"})
    if result.status is CollectorStatus.SUCCESS:
        assert result.coverage == full
    elif result.status is CollectorStatus.PARTIAL:
        assert result.coverage < full
    else:
        assert result.status is CollectorStatus.FAILED
        assert result.coverage == frozenset()

    assert ("local_users" in result.coverage) == (result.data.local_users is not None)
    assert ("administrators" in result.coverage) == (
        result.data.administrators is not None
    )


def test_t_wp4_001_success_has_exact_full_coverage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document())
    assert result.status is CollectorStatus.SUCCESS
    assert result.coverage == frozenset({"local_users", "administrators"})
    assert result.errors == ()
    _assert_result_contract(result)


def test_t_wp4_002_local_users_map_to_canonical_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document())
    assert result.data.local_users == (
        LocalUser(
            id="S-1-5-21-1000",
            name="alice",
            enabled=True,
            principal_source=PrincipalSource.LOCAL,
        ),
    )


def test_t_wp4_003_administrators_map_to_canonical_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document())
    assert result.data.administrators == (
        AdministratorMember(
            id="S-1-5-21-1000",
            name=r"HOST\alice",
            object_class="User",
            principal_source=PrincipalSource.LOCAL,
        ),
    )


def test_t_wp4_004_stable_identity_is_sid_not_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _document(
        local_users=_success_section([_user(sid="S-1-5-21-44", name="same")]),
        administrators=_success_section(
            [_administrator(sid="S-1-5-21-55", name="same")]
        ),
    )
    result = _collect(monkeypatch, document)
    assert result.data.local_users is not None
    assert result.data.administrators is not None
    assert result.data.local_users[0].id == "S-1-5-21-44"
    assert result.data.administrators[0].id == "S-1-5-21-55"


def test_t_wp4_005_enabled_state_remains_boolean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document())
    assert result.data.local_users is not None
    assert result.data.local_users[0].enabled is True
    assert isinstance(result.data.local_users[0].enabled, bool)


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("Local", PrincipalSource.LOCAL),
        ("local", PrincipalSource.LOCAL),
        ("ActiveDirectory", PrincipalSource.ACTIVE_DIRECTORY),
        ("ACTIVEDIRECTORY", PrincipalSource.ACTIVE_DIRECTORY),
        ("MicrosoftAccount", PrincipalSource.MICROSOFT_ACCOUNT),
        ("AzureAD", PrincipalSource.MICROSOFT_ENTRA),
        ("MicrosoftEntra", PrincipalSource.MICROSOFT_ENTRA),
        ("FutureSource", PrincipalSource.UNKNOWN),
        (None, PrincipalSource.UNKNOWN),
        (7, PrincipalSource.UNKNOWN),
    ],
)
def test_t_wp4_006_principal_source_mapping(
    monkeypatch: pytest.MonkeyPatch,
    source: object,
    expected: PrincipalSource,
) -> None:
    document = _document(
        local_users=_success_section([_user(principal_source=source)]),
        administrators=_success_section(
            [_administrator(principal_source=source)]
        ),
    )
    result = _collect(monkeypatch, document)
    assert result.data.local_users is not None
    assert result.data.administrators is not None
    assert result.data.local_users[0].principal_source is expected
    assert result.data.administrators[0].principal_source is expected


def test_t_wp4_007_empty_successful_local_users_is_empty_tuple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(local_users=_success_section([])),
    )
    assert result.data.local_users == ()
    assert "local_users" in result.coverage


def test_t_wp4_008_empty_successful_administrators_is_empty_tuple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(administrators=_success_section([])),
    )
    assert result.data.administrators == ()
    assert "administrators" in result.coverage


def test_t_wp4_009_local_users_are_sid_sorted_independent_of_source_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forward = [_user("S-1-5-21-100", "a"), _user("S-1-5-21-200", "b")]
    reverse = list(reversed(forward))
    first = _collect(
        monkeypatch,
        _document(local_users=_success_section(forward)),
    )
    second = _collect(
        monkeypatch,
        _document(local_users=_success_section(reverse)),
    )
    assert first.data.local_users == second.data.local_users
    assert [item.id for item in first.data.local_users or ()] == [
        "S-1-5-21-100",
        "S-1-5-21-200",
    ]


def test_t_wp4_010_administrators_are_sid_sorted_independent_of_source_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forward = [
        _administrator("S-1-5-21-100", "a"),
        _administrator("S-1-5-21-200", "b"),
    ]
    reverse = list(reversed(forward))
    first = _collect(
        monkeypatch,
        _document(administrators=_success_section(forward)),
    )
    second = _collect(
        monkeypatch,
        _document(administrators=_success_section(reverse)),
    )
    assert first.data.administrators == second.data.administrators


def test_t_wp4_011_equivalent_documents_produce_equal_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_document = _document(
        local_users=_success_section(
            [_user("S-1-5-21-100", "a"), _user("S-1-5-21-200", "b")]
        ),
        administrators=_success_section(
            [
                _administrator("S-1-5-21-100", "a"),
                _administrator("S-1-5-21-200", "b"),
            ]
        ),
    )
    second_document = _document(
        local_users=_success_section(
            [_user("S-1-5-21-200", "b"), _user("S-1-5-21-100", "a")]
        ),
        administrators=_success_section(
            [
                _administrator("S-1-5-21-200", "b"),
                _administrator("S-1-5-21-100", "a"),
            ]
        ),
    )
    assert _collect(monkeypatch, first_document) == _collect(
        monkeypatch, second_document
    )


def test_t_wp4_012_duplicate_local_user_sid_fails_only_local_users(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _document(
        local_users=_success_section(
            [_user("S-1-5-21-1", "a"), _user("S-1-5-21-1", "b")]
        )
    )
    result = _collect(monkeypatch, document)
    assert result.status is CollectorStatus.PARTIAL
    assert result.coverage == frozenset({"administrators"})
    assert result.data.local_users is None
    assert result.data.administrators is not None
    assert result.errors[0].code is ErrorCode.UNEXPECTED_OUTPUT
    assert result.errors[0].scope == "collector.users.local_users"
    _assert_result_contract(result)


def test_t_wp4_013_duplicate_administrator_sid_fails_only_administrators(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _document(
        administrators=_success_section(
            [
                _administrator("S-1-5-21-1", "a"),
                _administrator("S-1-5-21-1", "b"),
            ]
        )
    )
    result = _collect(monkeypatch, document)
    assert result.status is CollectorStatus.PARTIAL
    assert result.coverage == frozenset({"local_users"})
    assert result.data.administrators is None
    assert result.errors[0].code is ErrorCode.UNEXPECTED_OUTPUT
    assert result.errors[0].scope == "collector.users.administrators"
    _assert_result_contract(result)


def test_t_wp4_014_users_complete_admin_access_denied_is_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(
            administrators=_failed_section(
                category="PermissionDenied",
                message="Access denied.",
                native_code=-2147024891,
            )
        ),
    )
    assert result.status is CollectorStatus.PARTIAL
    assert result.coverage == frozenset({"local_users"})
    assert result.data.administrators is None
    assert result.errors[0].code is ErrorCode.ACCESS_DENIED
    assert result.errors[0].native_code == -2147024891


def test_t_wp4_015_admin_complete_local_users_failure_is_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(local_users=_failed_section()),
    )
    assert result.status is CollectorStatus.PARTIAL
    assert result.coverage == frozenset({"administrators"})
    assert result.data.local_users is None
    assert result.errors[0].code is ErrorCode.COMMAND_FAILED


def test_t_wp4_016_both_subsections_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(
            local_users=_failed_section(),
            administrators=_failed_section(),
        ),
    )
    assert result.status is CollectorStatus.FAILED
    assert result.coverage == frozenset()
    assert result.data.local_users is None
    assert result.data.administrators is None
    assert len(result.errors) == 2
    _assert_result_contract(result)


def test_t_wp4_017_failure_is_never_empty_success_tuple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(local_users=_failed_section()),
    )
    assert result.data.local_users is None
    assert result.data.local_users != ()


@pytest.mark.parametrize(
    ("exception", "expected_code", "native_code"),
    [
        (
            powershell.PowerShellUnavailableError("unavailable"),
            ErrorCode.COLLECTOR_UNAVAILABLE,
            None,
        ),
        (powershell.PowerShellTimeoutError(60), ErrorCode.COMMAND_TIMEOUT, None),
        (
            powershell.PowerShellCommandError(23, "details"),
            ErrorCode.COMMAND_FAILED,
            23,
        ),
        (
            powershell.PowerShellOutputError("broken output"),
            ErrorCode.UNEXPECTED_OUTPUT,
            None,
        ),
    ],
)
def test_t_wp4_018_to_021_transport_exception_mapping(
    monkeypatch: pytest.MonkeyPatch,
    exception: Exception,
    expected_code: ErrorCode,
    native_code: int | None,
) -> None:
    def fail(_script: str, *, timeout_seconds: float) -> object:
        raise exception

    monkeypatch.setattr(users.powershell, "run_powershell_json", fail)
    result = users.collect_users()
    assert result.status is CollectorStatus.FAILED
    assert result.coverage == frozenset()
    assert result.data.local_users is None
    assert result.data.administrators is None
    assert result.errors[0].code is expected_code
    assert result.errors[0].scope == "collector.users"
    assert result.errors[0].native_code == native_code
    assert result.errors[0].recoverable is True


def test_t_wp4_022_unsupported_platform_never_invokes_powershell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unsupported() -> None:
        raise users.platform_windows.UnsupportedPlatformError("unsupported")

    called = False

    def forbidden(_script: str, *, timeout_seconds: float) -> object:
        nonlocal called
        called = True
        return _document()

    monkeypatch.setattr(
        users.platform_windows, "require_supported_platform", unsupported
    )
    monkeypatch.setattr(users.powershell, "run_powershell_json", forbidden)
    result = users.collect_users()
    assert called is False
    assert result.status is CollectorStatus.FAILED
    assert result.coverage == frozenset()
    assert result.data.local_users is None
    assert result.data.administrators is None
    assert result.errors[0].code is ErrorCode.UNSUPPORTED_OS
    assert result.errors[0].scope == "collector.users"
    assert result.errors[0].operation == "platform check"
    assert result.errors[0].recoverable is False


def test_t_wp4_023_root_result_must_be_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, [])
    assert result.status is CollectorStatus.FAILED
    assert result.errors[0].code is ErrorCode.UNEXPECTED_OUTPUT
    assert result.errors[0].scope == "collector.users"


def test_t_wp4_024_missing_subsection_cannot_claim_coverage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        {"administrators": _success_section([_administrator()])},
    )
    assert result.status is CollectorStatus.PARTIAL
    assert result.coverage == frozenset({"administrators"})
    assert result.data.local_users is None
    assert result.errors[0].code is ErrorCode.UNEXPECTED_OUTPUT
    assert result.errors[0].scope == "collector.users.local_users"


def test_t_wp4_025_items_must_be_array(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _collect(
        monkeypatch,
        _document(local_users={"ok": True, "items": {}, "error": None}),
    )
    assert result.status is CollectorStatus.PARTIAL
    assert result.data.local_users is None
    assert result.errors[0].code is ErrorCode.UNEXPECTED_OUTPUT


@pytest.mark.parametrize("bad_sid", [None, "", "   ", 1, {}, []])
def test_t_wp4_026_sid_must_be_non_empty_string(
    monkeypatch: pytest.MonkeyPatch,
    bad_sid: object,
) -> None:
    local = _user()
    local["SID"] = bad_sid
    result = _collect(monkeypatch, _document(local_users=_success_section([local])))
    assert result.data.local_users is None
    assert result.errors[0].code is ErrorCode.UNEXPECTED_OUTPUT


@pytest.mark.parametrize("bad_name", [None, "", "   ", 1, {}, []])
def test_t_wp4_027_username_must_be_non_empty_string(
    monkeypatch: pytest.MonkeyPatch,
    bad_name: object,
) -> None:
    local = _user()
    local["Name"] = bad_name
    result = _collect(monkeypatch, _document(local_users=_success_section([local])))
    assert result.data.local_users is None
    assert result.errors[0].code is ErrorCode.UNEXPECTED_OUTPUT


@pytest.mark.parametrize("bad_enabled", ["true", "False", 1, 0, None, [], {}])
def test_t_wp4_028_enabled_rejects_non_boolean_values(
    monkeypatch: pytest.MonkeyPatch,
    bad_enabled: object,
) -> None:
    result = _collect(
        monkeypatch,
        _document(local_users=_success_section([_user(enabled=bad_enabled)])),
    )
    assert result.data.local_users is None
    assert result.errors[0].code is ErrorCode.UNEXPECTED_OUTPUT


@pytest.mark.parametrize("bad_class", [None, "", "   ", 1, {}, []])
def test_t_wp4_029_object_class_must_be_non_empty_string(
    monkeypatch: pytest.MonkeyPatch,
    bad_class: object,
) -> None:
    result = _collect(
        monkeypatch,
        _document(
            administrators=_success_section(
                [_administrator(object_class=bad_class)]
            )
        ),
    )
    assert result.data.administrators is None
    assert result.errors[0].code is ErrorCode.UNEXPECTED_OUTPUT


def test_t_wp4_030_and_031_shared_runner_and_exact_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, float]] = []

    def fake_runner(script: str, *, timeout_seconds: float) -> object:
        calls.append((script, timeout_seconds))
        return _document()

    monkeypatch.setattr(users.powershell, "run_powershell_json", fake_runner)
    result = users.collect_users()
    assert result.status is CollectorStatus.SUCCESS
    assert calls == [(users._USERS_POWERSHELL_SCRIPT, 60)]


def test_t_wp4_032_to_035_powershell_contract() -> None:
    script = users._USERS_POWERSHELL_SCRIPT
    assert "Get-LocalUser" in script
    assert "Get-LocalGroupMember" in script
    assert "S-1-5-32-544" in script
    assert "Get-LocalGroupMember -SID 'S-1-5-32-544'" in script
    assert "-Group 'Administrators'" not in script
    assert "-Group \"Administrators\"" not in script
    assert "-Group 'Administratoren'" not in script
    assert "ConvertTo-Json -Compress" in script


def test_t_wp4_036_script_contains_no_modifying_cmdlets() -> None:
    script = users._USERS_POWERSHELL_SCRIPT
    prohibited = (
        "New-LocalUser",
        "Remove-LocalUser",
        "Set-LocalUser",
        "Enable-LocalUser",
        "Disable-LocalUser",
        "Add-LocalGroupMember",
        "Remove-LocalGroupMember",
        "net user /add",
    )
    assert all(token not in script for token in prohibited)


def test_wp4_no_remote_domain_or_credential_acquisition_in_script() -> None:
    script = users._USERS_POWERSHELL_SCRIPT
    prohibited = (
        "Get-ADUser",
        "Get-ADGroup",
        "LDAP",
        "Microsoft Graph",
        "Invoke-Command",
        "New-PSSession",
        "PasswordLastSet",
        "PasswordExpires",
        "LastLogon",
        "password hash",
        "SAM",
        "LSA",
        "DPAPI",
    )
    assert all(token.casefold() not in script.casefold() for token in prohibited)


def test_wp4_users_module_has_no_direct_subprocess_or_security_interpretation() -> None:
    source = inspect.getsource(users)
    assert "import subprocess" not in source
    assert "subprocess." not in source
    for token in ("HIGH", "MEDIUM", "malicious", "persistence detected", "attacker"):
        assert token not in source


def test_wp4_result_contract_for_success_partial_and_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    success = _collect(monkeypatch, _document())
    partial = _collect(
        monkeypatch,
        _document(administrators=_failed_section()),
    )
    failed = _collect(
        monkeypatch,
        _document(
            local_users=_failed_section(),
            administrators=_failed_section(),
        ),
    )
    for result in (success, partial, failed):
        _assert_result_contract(result)


def test_malformed_failed_subsection_error_is_unexpected_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(local_users={"ok": False, "items": None, "error": None}),
    )
    assert result.status is CollectorStatus.PARTIAL
    assert result.errors[0].code is ErrorCode.UNEXPECTED_OUTPUT
    assert result.errors[0].scope == "collector.users.local_users"


def test_structured_permission_mapping_does_not_search_message_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(
            local_users=_failed_section(
                category="NotSpecified",
                message="PermissionDenied words in a message do not control mapping",
            )
        ),
    )
    assert result.errors[0].code is ErrorCode.COMMAND_FAILED


def test_boolean_native_code_is_not_persisted(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _collect(
        monkeypatch,
        _document(
            local_users=_failed_section(native_code=True),
        ),
    )
    assert result.errors[0].native_code is None
