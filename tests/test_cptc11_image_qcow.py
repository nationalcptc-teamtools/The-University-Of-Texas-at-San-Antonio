from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import gc
import hashlib
import json
from pathlib import Path
from weakref import ref

import pytest

import testing.cptc11_benchmark.qcow as qcow_module
from testing.cptc11_benchmark.qcow import (
    MAX_EXTENT_SIZE,
    MAX_VIRTUAL_SIZE,
    QcowRejected,
    QemuImgToolPin,
    QEMU_IMG_REVIEWED_SHA256,
    ValidatedQcowInfo,
    build_qemu_img_info_command,
    build_qemu_img_map_command,
    parse_qcow_info,
    parse_qcow_map,
    parse_qcow_metadata,
)
from testing.cptc11_benchmark.staging import create_private_run_dir, validate_state_root, write_sparse_chunk


VIRTUAL_SIZE = 64 * 1024 * 1024


def _info(**changes: object) -> bytes:
    value = {
        "format": "qcow2",
        "virtual-size": VIRTUAL_SIZE,
        "actual-size": 8 * 1024 * 1024,
        "cluster-size": 65536,
        "snapshots": [],
        "format-specific": {"type": "qcow2", "data": {"compat": "1.1"}},
    }
    value.update(changes)
    return json.dumps(value).encode()


def _mapping(*extents: dict[str, object]) -> bytes:
    if not extents:
        extents = (
            {"start": 0, "length": 65536, "depth": 0, "present": True, "data": True, "zero": False, "offset": 0},
            {"start": 65536, "length": VIRTUAL_SIZE - 65536, "depth": 0, "present": False, "data": False, "zero": True},
        )
    return json.dumps(extents).encode()


def _private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _run(tmp_path: Path):
    root = validate_state_root(_private_dir(tmp_path / "state"))
    run = create_private_run_dir(root, "run-0001")
    write_sparse_chunk(run, logical_size=4096, start=0, data=b"synthetic", chunk_index=0)
    return root, run


def _tool_pin() -> QemuImgToolPin:
    path = Path("/usr/bin/qemu-img")
    if not path.is_file():
        pytest.skip("reviewed qemu-img test dependency is not installed")
    metadata = path.stat()
    return QemuImgToolPin(
        path=path,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        owner_uid=metadata.st_uid,
        mode=metadata.st_mode & 0o7777,
        package_name="qemu-img",
        package_version="11.1.1-1",
        package_origin="Arch extra signed system package",
        lock_schema="cptc11-image-tool-lock-v1",
    )


def test_qcow_parser_emits_typed_receipt_and_hashes_raw_outputs():
    info = _info()
    mapping = _mapping()
    receipt = parse_qcow_metadata(info, mapping)
    assert receipt.format == "qcow2"
    assert receipt.virtual_size == VIRTUAL_SIZE
    assert receipt.actual_allocated_size == 8 * 1024 * 1024
    assert receipt.cluster_size == 65536
    assert receipt.backing_file_present is False
    assert receipt.encryption_present is False
    assert receipt.snapshot_present is False
    assert receipt.extent_count == 2
    assert receipt.maximum_extent == VIRTUAL_SIZE - 65536
    assert receipt.raw_info_sha256 == hashlib.sha256(info).hexdigest()
    assert receipt.raw_map_sha256 == hashlib.sha256(mapping).hexdigest()


@pytest.mark.parametrize(
    ("info", "message"),
    [
        (b"{", "malformed"),
        (_info(format="raw"), "qcow2"),
        (_info(**{"backing-filename": "/tmp/base.qcow2"}), "backing"),
        (_info(encrypted=True), "encrypt"),
        (_info(**{"format-specific": {"type": "qcow2", "data": {"encrypt": {"format": "luks"}}}}), "encrypt"),
        (_info(snapshots=[{"id": "1", "name": "snap"}]), "snapshot"),
        (_info(**{"virtual-size": MAX_VIRTUAL_SIZE + 1}), "virtual size"),
        (_info(**{"actual-size": 0}), "actual size"),
        (_info(**{"cluster-size": 12345}), "cluster size"),
    ],
)
def test_qcow_info_rejects_unsafe_metadata_before_map_validation(info: bytes, message: str):
    with pytest.raises(QcowRejected, match=message):
        parse_qcow_info(info)


@pytest.mark.parametrize(
    ("mapping", "message"),
    [
        (b"{", "malformed"),
        (b"[]", "complete"),
        (_mapping({"start": -1, "length": VIRTUAL_SIZE, "depth": 0, "present": True, "data": True, "zero": False}), "extent"),
        (_mapping({"start": 0, "length": MAX_EXTENT_SIZE + 1, "depth": 0, "present": True, "data": True, "zero": False}), "oversized"),
        (_mapping({"start": VIRTUAL_SIZE - 1, "length": 2, "depth": 0, "present": True, "data": True, "zero": False}), "virtual size"),
        (_mapping({"start": 0, "length": 65536, "depth": 0, "present": True, "data": True, "zero": False}, {"start": 32768, "length": VIRTUAL_SIZE - 32768, "depth": 0, "present": False, "data": False, "zero": True}), "contiguous"),
        (_mapping({"start": 1, "length": VIRTUAL_SIZE - 1, "depth": 0, "present": True, "data": True, "zero": False}), "zero"),
        (_mapping({"start": 0, "length": VIRTUAL_SIZE - 1, "depth": 0, "present": True, "data": True, "zero": False}), "complete"),
        (_mapping({"start": 0, "length": VIRTUAL_SIZE, "depth": 1, "present": True, "data": True, "zero": False}), "depth zero"),
        (_mapping({"start": 0, "length": VIRTUAL_SIZE, "depth": 0, "present": "yes", "data": True, "zero": False}), "present.*boolean"),
        (_mapping({"start": 0, "length": VIRTUAL_SIZE, "depth": 0, "present": True, "data": 1, "zero": False}), "data.*boolean"),
        (_mapping({"start": 0, "length": VIRTUAL_SIZE, "depth": 0, "present": True, "data": True, "zero": 0}), "zero.*boolean"),
        (_mapping({"start": 0, "length": VIRTUAL_SIZE, "depth": 0, "present": True, "data": True, "zero": False, "offset": -1}), "physical offset"),
    ],
)
def test_qcow_map_requires_complete_depth_zero_typed_extents(mapping: bytes, message: str):
    with pytest.raises(QcowRejected, match=message):
        parse_qcow_map(parse_qcow_info(_info()), mapping)


def test_qemu_img_commands_require_safe_info_fixed_format_network_block_and_capabilities(tmp_path: Path):
    root, run = _run(tmp_path)
    try:
        pin = _tool_pin()
        info = build_qemu_img_info_command(run, tool_pin=pin)
        safe_info = parse_qcow_info(_info())
        mapping = build_qemu_img_map_command(run, tool_pin=pin, validated_info=safe_info)
        assert info.argv == ("/usr/bin/qemu-img", "info", "--output=json", "--force-share", "-f", "qcow2", str(run.image_path))
        assert mapping.argv == ("/usr/bin/qemu-img", "map", "--output=json", "-f", "qcow2", str(run.image_path))
        for command in (info, mapping):
            assert command.cwd == run.path
            assert command.env == {"LC_ALL": "C"}
            assert command.close_fds is True
            assert command.shell is False
            assert command.network_disabled is True
            assert 0 < command.timeout_seconds <= 60
            assert command.output_limit <= 1024 * 1024
        assert mapping.validated_info_sha256 == safe_info.raw_info_sha256
    finally:
        run.close()
        root.close()


def test_map_command_cannot_be_built_without_a_validated_safe_info_token(tmp_path: Path):
    root, run = _run(tmp_path)
    try:
        with pytest.raises((TypeError, QcowRejected)):
            build_qemu_img_map_command(run, tool_pin=_tool_pin(), validated_info=None)  # type: ignore[arg-type]
    finally:
        run.close()
        root.close()


@pytest.mark.parametrize(
    "unsafe_field",
    ["backing_file_present", "encryption_present", "snapshot_present"],
)
def test_map_rejects_a_forged_unsafe_info_token(tmp_path: Path, unsafe_field: str):
    root, run = _run(tmp_path)
    try:
        values = {
            "format": "qcow2",
            "virtual_size": VIRTUAL_SIZE,
            "actual_allocated_size": 8 * 1024 * 1024,
            "cluster_size": 65536,
            "backing_file_present": False,
            "encryption_present": False,
            "snapshot_present": False,
            "raw_info_sha256": "f" * 64,
        }
        values[unsafe_field] = True
        with pytest.raises(QcowRejected, match="parser-issued"):
            ValidatedQcowInfo(**values)

        forged = parse_qcow_info(_info())
        object.__setattr__(forged, unsafe_field, True)
        with pytest.raises(QcowRejected, match="parser-issued metadata"):
            build_qemu_img_map_command(run, tool_pin=_tool_pin(), validated_info=forged)
        with pytest.raises(QcowRejected, match="parser-issued metadata"):
            parse_qcow_map(forged, _mapping())
    finally:
        run.close()
        root.close()


@pytest.mark.parametrize(
    ("field", "changed_value"),
    [
        ("format", "raw"),
        ("virtual_size", VIRTUAL_SIZE // 2),
        ("actual_allocated_size", 7 * 1024 * 1024),
        ("cluster_size", 131072),
        ("backing_file_present", True),
        ("encryption_present", True),
        ("snapshot_present", True),
        ("raw_info_sha256", "e" * 64),
    ],
)
def test_qcow_consumers_reject_mutation_of_every_parser_bound_field(
    tmp_path: Path, field: str, changed_value: object
):
    root, run = _run(tmp_path)
    try:
        mutated = parse_qcow_info(_info())
        object.__setattr__(mutated, field, changed_value)
        with pytest.raises(QcowRejected, match="parser-issued metadata"):
            parse_qcow_map(mutated, _mapping())
        with pytest.raises(QcowRejected, match="parser-issued metadata"):
            build_qemu_img_map_command(
                run,
                tool_pin=object(),  # type: ignore[arg-type]
                validated_info=mutated,
            )
    finally:
        run.close()
        root.close()


def test_validated_qcow_info_issue_cannot_be_called_directly():
    with pytest.raises(QcowRejected, match="parser-issued"):
        ValidatedQcowInfo._issue(
            format="qcow2",
            virtual_size=VIRTUAL_SIZE,
            actual_allocated_size=8 * 1024 * 1024,
            cluster_size=65536,
            raw_info_sha256="f" * 64,
        )


def test_unregistered_object_new_info_is_rejected_by_both_consumers(tmp_path: Path):
    root, run = _run(tmp_path)
    try:
        forged = object.__new__(ValidatedQcowInfo)
        values = {
            "format": "qcow2",
            "virtual_size": VIRTUAL_SIZE,
            "actual_allocated_size": 8 * 1024 * 1024,
            "cluster_size": 65536,
            "backing_file_present": False,
            "encryption_present": False,
            "snapshot_present": False,
            "raw_info_sha256": "f" * 64,
        }
        for field, field_value in values.items():
            object.__setattr__(forged, field, field_value)
        with pytest.raises(QcowRejected, match="parser-issued"):
            parse_qcow_map(forged, _mapping())
        with pytest.raises(QcowRejected, match="parser-issued"):
            build_qemu_img_map_command(
                run,
                tool_pin=object(),  # type: ignore[arg-type]
                validated_info=forged,
            )
        assert not hasattr(qcow_module, "_PARSER_ISSUED_INFO")
    finally:
        run.close()
        root.close()


def test_parser_side_record_releases_collected_tokens():
    baseline = qcow_module._issued_info_count()
    token = parse_qcow_info(_info())
    token_reference = ref(token)
    assert qcow_module._issued_info_count() == baseline + 1

    del token
    gc.collect()

    assert token_reference() is None
    assert qcow_module._issued_info_count() == baseline


def test_parser_side_record_exposes_no_mutable_registry_through_closure():
    parser_closure = parse_qcow_info.__closure__
    validator_closure = qcow_module._validate_info_token.__closure__
    assert parser_closure is not None
    assert validator_closure is not None
    parser_state = tuple(cell.cell_contents for cell in parser_closure)
    validator_state = tuple(cell.cell_contents for cell in validator_closure)
    assert parser_state == validator_state
    parser_registries = tuple(value for value in parser_state if isinstance(value, tuple))
    assert len(parser_registries) == 1
    assert not any(isinstance(value, (dict, list, set)) for value in parser_state)


def test_parser_side_record_cleanup_is_safe_during_concurrent_issuance():
    baseline = qcow_module._issued_info_count()
    info_output = _info()

    def issue_and_release(_worker: int) -> None:
        for _ in range(1000):
            parse_qcow_info(info_output)

    with ThreadPoolExecutor(max_workers=4) as executor:
        tuple(executor.map(issue_and_release, range(4)))
    gc.collect()

    assert qcow_module._issued_info_count() == baseline


def test_map_rejects_mutation_after_its_initial_validation(monkeypatch: pytest.MonkeyPatch):
    token = parse_qcow_info(_info())
    original_validate = qcow_module._validate_info_token
    validation_count = 0

    def validate_then_mutate(candidate: object):
        nonlocal validation_count
        fields = original_validate(candidate)
        validation_count += 1
        if validation_count == 1:
            object.__setattr__(candidate, "virtual_size", VIRTUAL_SIZE // 2)
        return fields

    monkeypatch.setattr(qcow_module, "_validate_info_token", validate_then_mutate)
    with pytest.raises(QcowRejected, match="parser-issued metadata"):
        parse_qcow_map(token, _mapping())


def test_map_command_rejects_mutation_after_its_initial_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    root, run = _run(tmp_path)
    try:
        token = parse_qcow_info(_info())
        original_validate = qcow_module._validate_info_token
        validation_count = 0

        def validate_then_mutate(candidate: object):
            nonlocal validation_count
            fields = original_validate(candidate)
            validation_count += 1
            if validation_count == 1:
                object.__setattr__(candidate, "raw_info_sha256", "e" * 64)
            return fields

        monkeypatch.setattr(qcow_module, "_validate_info_token", validate_then_mutate)
        monkeypatch.setattr(qcow_module, "_verify_tool_pin", lambda _pin: None)
        with pytest.raises(QcowRejected, match="parser-issued metadata"):
            build_qemu_img_map_command(
                run,
                tool_pin=object(),  # type: ignore[arg-type]
                validated_info=token,
            )
    finally:
        run.close()
        root.close()


def test_qemu_img_builder_rejects_untrusted_path_hash_owner_mode_or_package_pin(tmp_path: Path):
    root, run = _run(tmp_path)
    try:
        pin = _tool_pin()
        cases = (
            (replace(pin, path=tmp_path / "qemu-img"), "exactly /usr/bin/qemu-img"),
            (replace(pin, sha256="0" * 64), "hash"),
            (replace(pin, owner_uid=pin.owner_uid + 1), "owner"),
            (replace(pin, mode=0o700), "mode"),
            (replace(pin, package_name="other"), "package"),
            (replace(pin, package_version="other"), "package"),
            (replace(pin, package_origin="other"), "package"),
            (replace(pin, lock_schema="untrusted"), "lock schema"),
        )
        for changed, message in cases:
            with pytest.raises(QcowRejected, match=message):
                build_qemu_img_info_command(run, tool_pin=changed)
    finally:
        run.close()
        root.close()


def test_qemu_img_rejects_a_caller_selected_valid_sha256(tmp_path: Path):
    root, run = _run(tmp_path)
    try:
        pin = replace(_tool_pin(), sha256="1" * 64)
        assert pin.sha256 != QEMU_IMG_REVIEWED_SHA256
        with pytest.raises(QcowRejected, match="reviewed digest"):
            build_qemu_img_info_command(run, tool_pin=pin)
    finally:
        run.close()
        root.close()


def test_reviewed_qemu_digest_is_bound_to_the_checked_in_inventory():
    root = Path(__file__).parents[1]
    inventory = json.loads((root / "docs/harness/THIRD-PARTY-INVENTORY.json").read_text())
    component = next(item for item in inventory["components"] if item["name"] == "QEMU image tools")
    assert any(QEMU_IMG_REVIEWED_SHA256 in obligation for obligation in component["obligations"])


def test_qemu_img_builder_rejects_an_image_not_created_by_the_run_capability(tmp_path: Path):
    root = validate_state_root(_private_dir(tmp_path / "state"))
    run = create_private_run_dir(root, "run-0001")
    try:
        run.image_path.write_bytes(b"preplaced")
        run.image_path.chmod(0o600)
        with pytest.raises(QcowRejected, match="created by this run capability"):
            build_qemu_img_info_command(run, tool_pin=_tool_pin())
    finally:
        run.close()
        root.close()
