#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import time

SCHEMA_VERSION = "aegis-p10f-host-accelerator-probe-v1"


def digest_json(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def _run(args: list[str]) -> dict[str, object]:
    try:
        result = subprocess.run(args, text=True, capture_output=True, timeout=8, check=False)
        return {
            "args": args,
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {"args": args, "returncode": -1, "stdout": "", "stderr": type(exc).__name__}


def _device_nodes() -> list[dict[str, object]]:
    nodes: list[dict[str, object]] = []
    paths = sorted(set(glob.glob("/dev/nvidia*") + glob.glob("/dev/nvidia-caps/*")))
    for raw in paths:
        path = Path(raw)
        try:
            info = path.stat()
            nodes.append(
                {
                    "path": raw,
                    "mode": stat.filemode(info.st_mode),
                    "uid": info.st_uid,
                    "gid": info.st_gid,
                    "major": os.major(info.st_rdev) if stat.S_ISCHR(info.st_mode) else None,
                    "minor": os.minor(info.st_rdev) if stat.S_ISCHR(info.st_mode) else None,
                }
            )
        except OSError as exc:
            nodes.append({"path": raw, "error": type(exc).__name__})
    return nodes


def _nvidia_pci_inventory() -> list[dict[str, object]]:
    inventory: list[dict[str, object]] = []
    root = Path("/sys/bus/pci/devices")
    if not root.exists():
        return inventory
    for device in sorted(root.iterdir()):
        try:
            vendor = (device / "vendor").read_text().strip().casefold()
        except OSError:
            continue
        if vendor != "0x10de":
            continue
        item: dict[str, object] = {"pci_bdf": device.name, "vendor": vendor}
        for name in ("device", "class", "numa_node"):
            try:
                item[name] = (device / name).read_text().strip()
            except OSError:
                item[name] = None
        link = device / "iommu_group"
        if link.exists():
            try:
                target = link.resolve()
                item["iommu_group"] = target.name
                members = target / "devices"
                item["iommu_group_members"] = sorted(p.name for p in members.iterdir())
            except OSError:
                item["iommu_group"] = None
                item["iommu_group_members"] = []
        else:
            item["iommu_group"] = None
            item["iommu_group_members"] = []
        inventory.append(item)
    return inventory


def collect_host_probe(probe_id: str = "gpu-host-probe-live") -> dict[str, object]:
    nvidia_smi = shutil.which("nvidia-smi")
    pci = _nvidia_pci_inventory()
    nodes = _device_nodes()
    commands: dict[str, object] = {}
    if nvidia_smi:
        commands["nvidia_smi_list"] = _run([nvidia_smi, "-L"])
        commands["nvidia_smi_query"] = _run(
            [
                nvidia_smi,
                "--query-gpu=uuid,pci.bus_id,name,driver_version",
                "--format=csv,noheader",
            ]
        )
        commands["nvidia_smi_mig"] = _run([nvidia_smi, "mig", "-lgi"])
    runtime_visibility = {
        key: os.environ.get(key)
        for key in (
            "CUDA_VISIBLE_DEVICES",
            "NVIDIA_VISIBLE_DEVICES",
            "NVIDIA_DRIVER_CAPABILITIES",
        )
    }
    raw = {
        "schema_version": SCHEMA_VERSION,
        "probe_id": probe_id,
        "collected_at_epoch": int(time.time()),
        "hostname": platform.node(),
        "kernel_release": platform.release(),
        "nvidia_smi_path": nvidia_smi,
        "pci_inventory": pci,
        "device_nodes": nodes,
        "runtime_visibility": runtime_visibility,
        "commands": commands,
    }
    device_inventory = {"pci_inventory": pci, "commands": commands}
    iommu_inventory = [
        {
            "pci_bdf": item["pci_bdf"],
            "iommu_group": item.get("iommu_group"),
            "iommu_group_members": item.get("iommu_group_members", []),
        }
        for item in pci
    ]
    hardware_present = bool(pci) or bool(nodes) or bool(
        commands.get("nvidia_smi_list", {}).get("stdout") if commands else False
    )
    probe_payload = {
        "schema_version": SCHEMA_VERSION,
        "probe_id": probe_id,
        "collected_at_epoch": raw["collected_at_epoch"],
        "hostname_sha256": hashlib.sha256(platform.node().encode()).hexdigest(),
        "kernel_release": platform.release(),
        "nvidia_smi_available": bool(nvidia_smi),
        "hardware_present": hardware_present,
        "device_inventory_sha256": digest_json(device_inventory),
        "device_node_inventory_sha256": digest_json(nodes),
        "iommu_inventory_sha256": digest_json(iommu_inventory),
        "runtime_visibility_sha256": digest_json(runtime_visibility),
    }
    probe = {
        **probe_payload,
        "raw_evidence_sha256": digest_json(probe_payload),
        "raw_host_evidence_sha256": digest_json(raw),
        "raw_host_evidence": raw,
        "claim_boundary": {
            "cryptographic_attestation": False,
            "physical_vram_zeroization_verified": False,
            "dma_attack_resistance_validated": False,
            "side_channel_resistance_validated": False,
        },
    }
    return probe


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect non-destructive host GPU/IOMMU/device-node evidence for the P10-F lab."
    )
    parser.add_argument("--probe-id", default="gpu-host-probe-live")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-gpu", action="store_true")
    args = parser.parse_args()
    probe = collect_host_probe(args.probe_id)
    text = json.dumps(probe, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(text + "\n")
    print(text)
    if args.require_gpu and not (
        probe["hardware_present"] and probe["nvidia_smi_available"]
    ):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
