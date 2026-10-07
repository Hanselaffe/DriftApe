"""WP6 Windows Scheduled Tasks collector tests."""

from __future__ import annotations

import inspect

import pytest

from driftape.acquisition import powershell
from driftape.collectors import tasks
from driftape.models import (
    CollectorStatus,
    ErrorCode,
    ScheduledTaskInfo,
    TaskAction,
    TaskPrincipal,
    TasksCollectorResult,
    TaskTrigger,
)

_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"


def _xml(
    *,
    principals: str = '<Principal id="Author"><UserId> DOMAIN\\Alice </UserId>'
    "<LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel>"
    "</Principal>",
    actions: str = (
        "<Exec><Command>cmd.exe</Command>"
        "<Arguments>/c echo hi</Arguments></Exec>"
    ),
    triggers: str = "<LogonTrigger><Enabled>true</Enabled></LogonTrigger>",
    namespace: str = _NS,
) -> str:
    return (
        f'<Task xmlns="{namespace}">'
        f"<Principals>{principals}</Principals>"
        f"<Triggers>{triggers}</Triggers>"
        f"<Actions>{actions}</Actions>"
        "</Task>"
    )


def _item(
    *,
    name: object = "BackupTask",
    path: object = "\\Example\\",
    export_ok: object = True,
    xml: object | None = None,
    category: object = "NotSpecified",
    message: object = "synthetic export failure",
    native_code: object = -1,
) -> dict[str, object]:
    return {
        "TaskName": name,
        "TaskPath": path,
        "export_ok": export_ok,
        "Xml": _xml() if xml is None else xml,
        "error": None
        if export_ok is True
        else {
            "category": category,
            "message": message,
            "native_code": native_code,
            "fully_qualified_error_id": "SyntheticExportFailure",
        },
    }


def _document(items: list[object]) -> dict[str, object]:
    return {"enumeration": {"ok": True, "items": items, "error": None}}


def _failed_enumeration(
    *,
    category: object = "NotSpecified",
    message: object = "synthetic enumeration failure",
    native_code: object = -1,
) -> dict[str, object]:
    return {
        "enumeration": {
            "ok": False,
            "items": None,
            "error": {
                "category": category,
                "message": message,
                "native_code": native_code,
                "fully_qualified_error_id": "SyntheticEnumerationFailure",
            },
        }
    }


@pytest.fixture(autouse=True)
def supported_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        tasks.platform_windows, "require_supported_platform", lambda: None
    )


def _collect(monkeypatch: pytest.MonkeyPatch, document: object) -> TasksCollectorResult:
    monkeypatch.setattr(
        tasks.powershell,
        "run_powershell_json",
        lambda _script, *, timeout_seconds: document,
    )
    return tasks.collect_tasks()


def _assert_partial(result: TasksCollectorResult) -> None:
    assert result.status is CollectorStatus.PARTIAL
    assert result.coverage == frozenset()
    assert result.data.tasks is not None
    assert result.errors


def _assert_failed(result: TasksCollectorResult, code: ErrorCode) -> None:
    assert result.status is CollectorStatus.FAILED
    assert result.coverage == frozenset()
    assert result.data.tasks is None
    assert result.errors[0].code is code


def test_t_wp6_001_to_006_success_identity_and_exact_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch, _document([_item(path="Example", name="BackupTask")])
    )
    assert result.status is CollectorStatus.SUCCESS
    assert result.coverage == frozenset({"tasks"})
    assert result.errors == ()
    assert result.data.tasks is not None
    task = result.data.tasks[0]
    assert isinstance(task, ScheduledTaskInfo)
    assert task.id == "\\example\\backuptask"
    assert task.task_path == "\\Example\\"
    assert task.task_name == "BackupTask"
    assert set(ScheduledTaskInfo.__dataclass_fields__) == {
        "id",
        "task_path",
        "task_name",
        "principals",
        "actions",
        "triggers",
    }


def test_t_wp6_002_zero_tasks_is_success(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _collect(monkeypatch, _document([]))
    assert result.status is CollectorStatus.SUCCESS
    assert result.coverage == frozenset({"tasks"})
    assert result.data.tasks == ()
    assert result.errors == ()


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("\\", "\\"),
        ("Example", "\\Example\\"),
        ("/Example/Sub/", "\\Example\\Sub\\"),
        ("\\\\Example\\\\Sub\\\\", "\\Example\\Sub\\"),
    ],
)
def test_t_wp6_007_to_010_task_path_normalization(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    expected: str,
) -> None:
    result = _collect(monkeypatch, _document([_item(path=source)]))
    assert result.data.tasks is not None
    assert result.data.tasks[0].task_path == expected


def test_t_wp6_010_equivalent_separator_forms_have_same_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _collect(monkeypatch, _document([_item(path="Example/Sub")]))
    second = _collect(monkeypatch, _document([_item(path="\\Example\\Sub\\")]))
    assert first.data.tasks is not None and second.data.tasks is not None
    assert first.data.tasks[0].id == second.data.tasks[0].id


@pytest.mark.parametrize("name", ["", None, 7])
def test_t_wp6_011_invalid_task_name_is_partial(
    monkeypatch: pytest.MonkeyPatch, name: object
) -> None:
    result = _collect(monkeypatch, _document([_item(name=name)]))
    _assert_partial(result)
    assert result.data.tasks == ()
    assert result.errors[0].code is ErrorCode.UNEXPECTED_OUTPUT


@pytest.mark.parametrize("name", [" BackupTask", "BackupTask ", "\tBackupTask"])
def test_t_wp6_012_whitespace_task_name_is_partial(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    result = _collect(monkeypatch, _document([_item(name=name)]))
    _assert_partial(result)


def test_t_wp6_013_to_019_principal_normalization_and_sorting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principals = (
        '<Principal id=" Zed "><GroupId> BUILTIN\\Users </GroupId>'
        '<LogonType> ServiceAccount </LogonType><RunLevel> LeastPrivilege </RunLevel>'
        "</Principal>"
        '<Principal id=" Author "><UserId> DOMAIN\\Alice </UserId>'
        "<GroupId>   </GroupId><LogonType> InteractiveToken </LogonType>"
        "<RunLevel> HighestAvailable </RunLevel></Principal>"
    )
    result = _collect(monkeypatch, _document([_item(xml=_xml(principals=principals))]))
    assert result.data.tasks is not None
    assert result.data.tasks[0].principals == (
        TaskPrincipal(
            id="author",
            user_id=r"domain\alice",
            group_id=None,
            logon_type="interactivetoken",
            run_level="highestavailable",
        ),
        TaskPrincipal(
            id="zed",
            user_id=None,
            group_id=r"builtin\users",
            logon_type="serviceaccount",
            run_level="leastprivilege",
        ),
    )


def test_t_wp6_016_empty_user_and_group_ids_become_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal = '<Principal id="a"><UserId> </UserId><GroupId></GroupId></Principal>'
    result = _collect(monkeypatch, _document([_item(xml=_xml(principals=principal))]))
    assert result.data.tasks is not None
    assert result.data.tasks[0].principals[0].user_id is None
    assert result.data.tasks[0].principals[0].group_id is None


def test_t_wp6_020_duplicate_principal_id_makes_task_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principals = '<Principal id="A"/><Principal id=" a "/>'
    result = _collect(monkeypatch, _document([_item(xml=_xml(principals=principals))]))
    _assert_partial(result)
    assert result.data.tasks == ()
    assert result.errors[0].code is ErrorCode.UNEXPECTED_OUTPUT


def test_t_wp6_021_action_has_local_type_and_canonical_xml(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document([_item()]))
    assert result.data.tasks is not None
    action = result.data.tasks[0].actions[0]
    assert isinstance(action, TaskAction)
    assert action.type == "Exec"
    assert action.xml_c14n


def test_t_wp6_022_to_024_action_c14n_is_deterministic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_xml = (
        f'<t:Task xmlns:t="{_NS}"><t:Actions>'
        "<t:Exec><!-- ignore --><t:Command> cmd.exe </t:Command></t:Exec>"
        "</t:Actions></t:Task>"
    )
    second_xml = (
        f'<x:Task xmlns:x="{_NS}">\n<x:Actions>\n'
        "<x:Exec><x:Command>cmd.exe</x:Command></x:Exec>\n"
        "</x:Actions></x:Task>"
    )
    first = _collect(monkeypatch, _document([_item(xml=first_xml)]))
    second = _collect(monkeypatch, _document([_item(xml=second_xml)]))
    assert first.data.tasks is not None and second.data.tasks is not None
    a = first.data.tasks[0].actions[0].xml_c14n
    b = second.data.tasks[0].actions[0].xml_c14n
    assert "ignore" not in a
    assert "ns0" not in a
    assert a == b


def test_t_wp6_025_to_026_action_order_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actions = (
        "<Exec><Command>a.exe</Command></Exec>"
        "<ComHandler><ClassId>x</ClassId></ComHandler>"
    )
    reverse = (
        "<ComHandler><ClassId>x</ClassId></ComHandler>"
        "<Exec><Command>a.exe</Command></Exec>"
    )
    first = _collect(monkeypatch, _document([_item(xml=_xml(actions=actions))]))
    second = _collect(monkeypatch, _document([_item(xml=_xml(actions=reverse))]))
    assert first.data.tasks is not None and second.data.tasks is not None
    assert [a.type for a in first.data.tasks[0].actions] == ["Exec", "ComHandler"]
    assert first.data.tasks[0].actions != second.data.tasks[0].actions


def test_t_wp6_027_to_031_triggers_are_canonical_and_sorted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    triggers_a = (
        "<TimeTrigger><StartBoundary>2026-01-01T00:00:00</StartBoundary></TimeTrigger>"
        "<LogonTrigger><!-- x --><Enabled>true</Enabled></LogonTrigger>"
    )
    triggers_b = (
        "<LogonTrigger><Enabled> true </Enabled></LogonTrigger>"
        "<TimeTrigger><StartBoundary>2026-01-01T00:00:00</StartBoundary></TimeTrigger>"
    )
    first = _collect(monkeypatch, _document([_item(xml=_xml(triggers=triggers_a))]))
    second = _collect(monkeypatch, _document([_item(xml=_xml(triggers=triggers_b))]))
    assert first.data.tasks is not None and second.data.tasks is not None
    triggers = first.data.tasks[0].triggers
    assert all(isinstance(trigger, TaskTrigger) for trigger in triggers)
    assert [trigger.type for trigger in triggers] == ["LogonTrigger", "TimeTrigger"]
    assert all(trigger.xml_c14n for trigger in triggers)
    assert "<!--" not in triggers[0].xml_c14n
    assert triggers == second.data.tasks[0].triggers


def test_t_wp6_032_to_034_task_order_is_deterministic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    a = _item(name="Zed", path="Folder")
    b = _item(name="Alpha", path="Folder")
    first = _collect(monkeypatch, _document([a, b]))
    second = _collect(monkeypatch, _document([b, a]))
    assert first == second
    assert first.data.tasks is not None
    assert [task.id for task in first.data.tasks] == sorted(
        task.id for task in first.data.tasks
    )


@pytest.mark.parametrize(
    "items",
    [
        [_item(name="Same", path="Folder"), _item(name="Same", path="Folder")],
        [_item(name="Same", path="Folder"), _item(name="sAME", path="folder")],
    ],
)
def test_t_wp6_035_to_036_duplicate_task_ids_fail(
    monkeypatch: pytest.MonkeyPatch, items: list[object]
) -> None:
    result = _collect(monkeypatch, _document(items))
    _assert_failed(result, ErrorCode.UNEXPECTED_OUTPUT)


def test_t_wp6_037_partial_access_denied_retains_good_task(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(
            [
                _item(name="Good"),
                _item(name="Denied", export_ok=False, category="PermissionDenied"),
            ]
        ),
    )
    _assert_partial(result)
    assert [task.task_name for task in result.data.tasks or ()] == ["Good"]
    assert result.errors[0].code is ErrorCode.ACCESS_DENIED


def test_t_wp6_038_malformed_xml_is_partial_and_good_task_remains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document([_item(name="Good"), _item(name="Bad", xml="<Task>")]),
    )
    _assert_partial(result)
    assert [task.task_name for task in result.data.tasks or ()] == ["Good"]
    assert result.errors[0].code is ErrorCode.UNEXPECTED_OUTPUT


def test_t_wp6_039_all_exports_failed_returns_empty_diagnostic_tuple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document([_item(name="A", export_ok=False), _item(name="B", export_ok=False)]),
    )
    _assert_partial(result)
    assert result.data.tasks == ()
    assert len(result.errors) == 2


@pytest.mark.parametrize(
    ("category", "expected"),
    [
        ("PermissionDenied", ErrorCode.ACCESS_DENIED),
        ("NotSpecified", ErrorCode.COMMAND_FAILED),
    ],
)
def test_t_wp6_040_to_041_structured_enumeration_failures(
    monkeypatch: pytest.MonkeyPatch, category: str, expected: ErrorCode
) -> None:
    _assert_failed(
        _collect(monkeypatch, _failed_enumeration(category=category)), expected
    )


@pytest.mark.parametrize(
    "document",
    [
        None,
        [],
        {},
        {"enumeration": None},
        {"enumeration": {"ok": "yes", "items": []}},
        {"enumeration": {"ok": True, "items": None}},
    ],
)
def test_t_wp6_042_malformed_root_or_enumeration_fails(
    monkeypatch: pytest.MonkeyPatch, document: object
) -> None:
    _assert_failed(_collect(monkeypatch, document), ErrorCode.UNEXPECTED_OUTPUT)


@pytest.mark.parametrize(
    ("exception", "expected", "native"),
    [
        (
            powershell.PowerShellUnavailableError("missing"),
            ErrorCode.COLLECTOR_UNAVAILABLE,
            None,
        ),
        (powershell.PowerShellTimeoutError(120), ErrorCode.COMMAND_TIMEOUT, None),
        (powershell.PowerShellCommandError(9, "bad"), ErrorCode.COMMAND_FAILED, 9),
        (powershell.PowerShellOutputError("bad"), ErrorCode.UNEXPECTED_OUTPUT, None),
    ],
)
def test_t_wp6_043_to_046_transport_failures(
    monkeypatch: pytest.MonkeyPatch,
    exception: Exception,
    expected: ErrorCode,
    native: int | None,
) -> None:
    def raise_error(_script: str, *, timeout_seconds: int) -> object:
        raise exception

    monkeypatch.setattr(tasks.powershell, "run_powershell_json", raise_error)
    result = tasks.collect_tasks()
    _assert_failed(result, expected)
    assert result.errors[0].native_code == native


def test_t_wp6_047_unsupported_platform_does_not_invoke_powershell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unsupported() -> None:
        raise tasks.platform_windows.UnsupportedPlatformError("unsupported")

    called = False

    def forbidden(_script: str, *, timeout_seconds: int) -> object:
        nonlocal called
        called = True
        return _document([])

    monkeypatch.setattr(
        tasks.platform_windows, "require_supported_platform", unsupported
    )
    monkeypatch.setattr(tasks.powershell, "run_powershell_json", forbidden)
    result = tasks.collect_tasks()
    _assert_failed(result, ErrorCode.UNSUPPORTED_OS)
    assert result.errors[0].recoverable is False
    assert not called


def test_t_wp6_048_to_055_powershell_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, object] = {}

    def fake(script: str, *, timeout_seconds: int) -> object:
        observed["script"] = script
        observed["timeout"] = timeout_seconds
        return _document([])

    monkeypatch.setattr(tasks.powershell, "run_powershell_json", fake)
    tasks.collect_tasks()
    script = str(observed["script"])
    assert observed["timeout"] == 120
    assert "Get-ScheduledTask" in script
    assert "Export-ScheduledTask" in script
    assert "Get-ScheduledTaskInfo" not in script
    assert "ConvertTo-Json" in script
    assert "export_ok = $false" in script
    for forbidden in (
        "Register-ScheduledTask",
        "Unregister-ScheduledTask",
        "Set-ScheduledTask",
        "Start-ScheduledTask",
        "Stop-ScheduledTask",
        "Disable-ScheduledTask",
        "Enable-ScheduledTask",
        "Invoke-Command",
        "New-PSSession",
        "New-CimSession",
        "CimSession",
        "schtasks",
    ):
        assert forbidden not in script
    source = inspect.getsource(tasks)
    assert "subprocess" not in source


@pytest.mark.parametrize(
    "bad_xml",
    [None, 7, "", "<Task>", "<NotTask />"],
)
def test_t_wp6_056_to_058_malformed_xml_is_partial(
    monkeypatch: pytest.MonkeyPatch, bad_xml: object
) -> None:
    item = _item()
    item["Xml"] = bad_xml
    result = _collect(monkeypatch, _document([item]))
    _assert_partial(result)
    assert result.data.tasks == ()
    assert result.errors[0].code is ErrorCode.UNEXPECTED_OUTPUT


@pytest.mark.parametrize(
    "principal",
    ["<Principal />", '<Principal id=""/>', '<Principal id="   "/>'],
)
def test_t_wp6_059_invalid_principal_id_is_partial(
    monkeypatch: pytest.MonkeyPatch, principal: str
) -> None:
    result = _collect(monkeypatch, _document([_item(xml=_xml(principals=principal))]))
    _assert_partial(result)
    assert result.data.tasks == ()


def test_t_wp6_060_canonical_fragments_are_non_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document([_item()]))
    assert result.data.tasks is not None
    task = result.data.tasks[0]
    assert task.actions and all(action.xml_c14n for action in task.actions)
    assert task.triggers and all(trigger.xml_c14n for trigger in task.triggers)


def test_missing_containers_are_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _collect(monkeypatch, _document([_item(xml=f'<Task xmlns="{_NS}" />')]))
    assert result.status is CollectorStatus.SUCCESS
    assert result.data.tasks is not None
    task = result.data.tasks[0]
    assert task.principals == ()
    assert task.actions == ()
    assert task.triggers == ()


def test_non_permission_export_error_maps_command_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document([_item(export_ok=False)]))
    _assert_partial(result)
    assert result.errors[0].code is ErrorCode.COMMAND_FAILED


def test_task_xml_registration_uri_does_not_override_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    xml = (
        f'<Task xmlns="{_NS}"><RegistrationInfo>'
        "<URI>\\Other\\Wrong</URI></RegistrationInfo></Task>"
    )
    result = _collect(
        monkeypatch, _document([_item(name="Right", path="Correct", xml=xml)])
    )
    assert result.data.tasks is not None
    assert result.data.tasks[0].id == "\\correct\\right"
