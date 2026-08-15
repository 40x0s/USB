#!/usr/bin/env python3
"""
usbdiag.py — Windows USB / Flash Diagnostic CLI (MVP)

Focus: DETECTION & DIAGNOSTIC logic for USB flash drives / SD cards (via USB
readers) that "do not appear" or appear malfunctioning.

Scope implemented (per the engineering spec):
  * Deep Diagnostics  — read-only evidence collection from PowerShell/WMI,
                        Windows event log, PnP tree, and Storage subsystem.
  * State Comparison  — baseline vs. post-insertion snapshot diffing.
  * Decision Tree     — D0 (interrupt) -> D1 (enumeration) -> D2 (mass storage)
                        -> D3 (block device) traversal with Stop & Escalate.
  * Confidence Scoring — Naive Bayes over evidence features yielding
                        P(HARDWARE_FAILURE) vs P(METADATA_CORRUPTION).

SAFETY POLICY: This tool is STRICTLY READ-ONLY. It never opens any target
device for writing, never issues MBR/GPT/format/zero-fill commands, and never
invokes vendor mass-production tools. Repair is intentionally OUT OF SCOPE for
this MVP.

Usage:
  usbdiag.py snapshot  [--out base.json]            # capture a state snapshot
  usbdiag.py diagnose  [--control ok|failed]        # guided before/after flow
  usbdiag.py compare   --baseline a.json --post b.json
  usbdiag.py scan                                   # static check (device already in)
  usbdiag.py watch                                  # live hot-plug monitor

Reader vs card localization (card readers only) — supply cross-test results:
  --card-other-reader ok|failed   # suspect card in a KNOWN-GOOD reader
  --known-card-here   ok|failed   # known-good card in THIS reader

Windows-only for snapshot/diagnose/scan/watch; `compare` is pure JSON and
runs anywhere.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import uuid

__version__ = "0.1.0"

# --------------------------------------------------------------------------- #
#  Failure classes (Section 4.2 of spec) and confidence model constants        #
# --------------------------------------------------------------------------- #

CLASS_IDS = ["C1", "C2", "C3", "C4", "C5"]

CLASS_NAMES = {
    "C1": "HARDWARE_FAILURE",        # device / controller / NAND — permanent
    "C2": "METADATA_CORRUPTION",     # partition table / FS metadata — reversible
    "C3": "HOST_DRIVER_FAULT",       # port / driver / host configuration
    "C4": "MEDIA_NOT_PRESENT",       # empty reader / no card seated
    "C5": "NORMAL",                  # no fault detected
}

# Expert priors P(C). Field-tunable. For the "does not appear at all"
# population, hardware failure is the modal outcome.
PRIORS = {
    "C1": 0.40,
    "C2": 0.15,
    "C3": 0.20,
    "C4": 0.10,
    "C5": 0.15,
}

# P(feature = True | class) — expert-seeded likelihood rubric (spec 4.4).
# Scoring is PRESENCE-ONLY: a feature contributes only when it is an observed
# finding (True). Absent features are NOT scored, because a composite class
# (e.g. HARDWARE_FAILURE = dead controller OR dead NAND) cannot be described
# by "absent" symptoms — a dead-NAND device enumerates cleanly, so scoring
# `descriptor_error=False` would unfairly acquit it. See spec 4.6.
FEATURE_LIKELIHOODS = {
    #                                 C1     C2     C3     C4     C5
    "no_interrupt":      {"C1": 0.80, "C2": 0.02, "C3": 0.30, "C4": 0.05, "C5": 0.01},
    "control_silent":    {"C1": 0.05, "C2": 0.01, "C3": 0.85, "C4": 0.02, "C5": 0.01},
    "control_ok":        {"C1": 0.90, "C2": 0.95, "C3": 0.15, "C4": 0.90, "C5": 0.95},
    "descriptor_error":  {"C1": 0.60, "C2": 0.01, "C3": 0.30, "C4": 0.05, "C5": 0.01},
    "enum_no_storage":   {"C1": 0.45, "C2": 0.01, "C3": 0.20, "C4": 0.45, "C5": 0.02},
    "capacity_zero":     {"C1": 0.75, "C2": 0.03, "C3": 0.01, "C4": 0.30, "C5": 0.01},
    "medium_not_present":{"C1": 0.10, "C2": 0.01, "C3": 0.01, "C4": 0.85, "C5": 0.01},
    "raw_visible":       {"C1": 0.05, "C2": 0.85, "C3": 0.01, "C4": 0.01, "C5": 0.01},
    "gpt_backup_valid":  {"C1": 0.02, "C2": 0.90, "C3": 0.01, "C4": 0.01, "C5": 0.02},
    "io_error_growth":   {"C1": 0.70, "C2": 0.25, "C3": 0.05, "C4": 0.05, "C5": 0.02},
    "works_other_host":  {"C1": 0.02, "C2": 0.05, "C3": 0.90, "C4": 0.05, "C5": 0.50},
    "fails_other_host":  {"C1": 0.70, "C2": 0.20, "C3": 0.05, "C4": 0.10, "C5": 0.05},
    "driver_problem":    {"C1": 0.10, "C2": 0.01, "C3": 0.90, "C4": 0.05, "C5": 0.01},
    "healthy_present":   {"C1": 0.05, "C2": 0.02, "C3": 0.10, "C4": 0.02, "C5": 0.85},
    "reader_like":       {"C1": 0.10, "C2": 0.01, "C3": 0.05, "C4": 0.55, "C5": 0.05},
    "reader_no_media":   {"C1": 0.15, "C2": 0.01, "C3": 0.05, "C4": 0.85, "C5": 0.01},
}

# Windows ConfigManager error codes that indicate a driver/bind problem.
DRIVER_PROBLEM_CODES = {10, 28, 43}

# Kernel-PnP event ids: 410 = device start, 400 = config, 430 = removal.
PNP_EVENT_IDS = {400, 410, 430}
DISK_ERROR_IDS = {7, 51, 153}

DESCRIPTOR_ERROR_RE = re.compile(
    r"device descriptor (request )?failed|device descriptor read|"
    r"unknown usb device|device not recognized|set address failed",
    re.IGNORECASE,
)
MEDIUM_ABSENT_RE = re.compile(
    r"medium not present|no media|no medium|not ready|unit attention",
    re.IGNORECASE,
)

# Card-reader bridge naming patterns (SD/MMC, CF, MS, xD, Multi-Card, ...).
# A USB flash *stick* never carries these names; a card reader almost always
# does (the bridge presents itself as e.g. "Generic- SD/MMC USB Device").
READER_NAME_RE = re.compile(
    r"SD/MMC|SD\s?MMC|MMC/SD|Card\s?Reader|CardReader|Multi[- ]Card|"
    r"Compact\s?Flash|CF\s?Reader|SmartMedia|Memory\s?Stick|Micro\s?SD|"
    r"MicroSD|SDHC|SDXC|All-?In-?One|MS\s?Pro|xD\s?Picture",
    re.IGNORECASE,
)

VID_PID_RE = re.compile(r"VID_([0-9A-Fa-f]{4})", re.IGNORECASE)
PID_RE = re.compile(r"PID_([0-9A-Fa-f]{4})", re.IGNORECASE)


# --------------------------------------------------------------------------- #
#  Small utilities                                                             #
# --------------------------------------------------------------------------- #

def snake(s: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", s).lower()


def snakeize(o):
    if isinstance(o, dict):
        return {snake(k): snakeize(v) for k, v in o.items()}
    if isinstance(o, list):
        return [snakeize(i) for i in o]
    return o


def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def ensure_windows():
    if platform.system() != "Windows":
        sys.exit("ERROR: this command requires Windows (PowerShell/WMI). "
                 "Only `compare` runs cross-platform.")


def is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def vid_pid(instance_id: str):
    if not instance_id:
        return (None, None)
    v = VID_PID_RE.search(instance_id)
    p = PID_RE.search(instance_id)
    return (v.group(1).upper() if v else None, p.group(1).upper() if p else None)


def looks_like_reader(obj):
    """Heuristic: does this device object look like a card-reader bridge?"""
    for f in ("friendly_name", "model", "name"):
        v = obj.get(f)
        if v and READER_NAME_RE.search(str(v)):
            return True
    return False


# --------------------------------------------------------------------------- #
#  PowerShell runner                                                           #
# --------------------------------------------------------------------------- #

_PS_EXE = None

def ps_exe() -> str | None:
    global _PS_EXE
    if _PS_EXE is None:
        _PS_EXE = shutil.which("pwsh") or shutil.which("powershell")
    return _PS_EXE


_PS_PREAMBLE = (
    "$OutputEncoding = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n"
    "$ErrorActionPreference = 'SilentlyContinue'\n"
)


def run_ps(script: str, timeout: int = 120):
    exe = ps_exe()
    if not exe:
        return (1, "", "PowerShell executable not found on PATH")
    try:
        proc = subprocess.run(
            [exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
             _PS_PREAMBLE + script],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout,
        )
        return (proc.returncode, proc.stdout or "", proc.stderr or "")
    except subprocess.TimeoutExpired:
        return (124, "", "PowerShell command timed out")
    except Exception as exc:  # pragma: no cover - defensive
        return (1, "", str(exc))


def ps_json(script: str, timeout: int = 120):
    """Run a PowerShell expression that emits JSON on stdout; return parsed."""
    rc, out, _err = run_ps(script, timeout)
    if rc != 0:
        return None
    out = out.strip().lstrip("\ufeff")
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


# --------------------------------------------------------------------------- #
#  Evidence collectors (Section 3.1 of spec)                                  #
# --------------------------------------------------------------------------- #

def collect_usb_pnp():
    """USB-class PnP devices with ConfigManager problem codes."""
    script = r"""
$devs = Get-PnpDevice -Class USB -ErrorAction SilentlyContinue
$out = foreach ($d in $devs) {
  $ce = $null
  try {
    $ce = (Get-PnpDeviceProperty -InstanceId $d.InstanceId -KeyName 'DEVPKEY_Device_ConfigManagerErrorCode' -ErrorAction SilentlyContinue).Data
  } catch { $ce = $null }
  [pscustomobject]@{
    Status = [string]$d.Status
    Class = [string]$d.Class
    FriendlyName = [string]$d.FriendlyName
    InstanceId = [string]$d.InstanceId
    Present = [bool]$d.Present
    ProblemCode = [int]$ce
  }
}
if ($out) { $out | ConvertTo-Json -Compress -Depth 4 }
"""
    return snakeize(as_list(ps_json(script)))


def collect_pnp_entities():
    """USB devices from Win32_PnPEntity (includes USBSTOR / UASPStor services)."""
    script = r"""
Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue |
  Where-Object { $_.PNPDeviceID -match '^USB\\' } |
  ForEach-Object {
    [pscustomobject]@{
      Name = [string]$_.Name
      DeviceID = [string]$_.PNPDeviceID
      Status = [string]$_.Status
      ConfigManagerErrorCode = [int]$_.ConfigManagerErrorCode
      Service = [string]$_.Service
    }
  } | ConvertTo-Json -Compress -Depth 4
"""
    return snakeize(as_list(ps_json(script)))


def collect_disks():
    """Get-Disk — includes offline / uninitialized / 0-size disks."""
    script = r"""
Get-Disk -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{
    Number = [int]$_.Number
    FriendlyName = [string]$_.FriendlyName
    SerialNumber = [string]$_.SerialNumber
    BusType = [string]$_.BusType
    Size = [long]$_.Size
    PartitionStyle = [string]$_.PartitionStyle
    OperationalStatus = [string]($_.OperationalStatus -join ',')
    HealthStatus = [string]$_.HealthStatus
    IsBoot = [bool]$_.IsBoot
    IsSystem = [bool]$_.IsSystem
    IsReadOnly = [bool]$_.IsReadOnly
    IsOffline = [bool]$_.IsOffline
    FirmwareVersion = [string]$_.FirmwareVersion
    Model = [string]$_.Model
    Path = [string]$_.Path
  }
} | ConvertTo-Json -Compress -Depth 4
"""
    return snakeize(as_list(ps_json(script)))


def collect_partitions():
    script = r"""
Get-Partition -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{
    DiskNumber = [int]$_.DiskNumber
    PartitionNumber = [int]$_.PartitionNumber
    Size = [long]$_.Size
    Type = [string]$_.Type
    IsActive = [bool]$_.IsActive
    IsBoot = [bool]$_.IsBoot
  }
} | ConvertTo-Json -Compress -Depth 4
"""
    return snakeize(as_list(ps_json(script)))


def collect_volumes():
    script = r"""
Get-Volume -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{
    DriveLetter = [string]$_.DriveLetter
    FileSystemLabel = [string]$_.FileSystemLabel
    FileSystem = [string]$_.FileSystem
    HealthStatus = [string]$_.HealthStatus
    Size = [long]$_.Size
    SizeRemaining = [long]$_.SizeRemaining
    DriveType = [string]$_.DriveType
  }
} | ConvertTo-Json -Compress -Depth 4
"""
    return snakeize(as_list(ps_json(script)))


def collect_physical_disks():
    script = r"""
Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{
    FriendlyName = [string]$_.FriendlyName
    SerialNumber = [string]$_.SerialNumber
    BusType = [string]$_.BusType
    MediaType = [string]$_.MediaType
    Size = [long]$_.Size
    HealthStatus = [string]$_.HealthStatus
    OperationalStatus = [string]($_.OperationalStatus -join ',')
    DeviceId = [string]$_.DeviceId
    CanPool = [bool]$_.CanPool
  }
} | ConvertTo-Json -Compress -Depth 4
"""
    return snakeize(as_list(ps_json(script)))


_EVENTS_SCRIPT = r"""
$since = (Get-Date).AddMinutes(-__MIN__)
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$since} -MaxEvents __MAX__ -ErrorAction SilentlyContinue |
  Where-Object { $_.ProviderName -match 'Kernel-PnP|^disk$|Ntfs|Kernel-Power|stor|usb|USBSTOR|volmgr|partmgr|WudfRd|WPD' } |
  ForEach-Object {
    [pscustomobject]@{
      TimeCreated = [string]$_.TimeCreated
      Id = [int]$_.Id
      Provider = [string]$_.ProviderName
      Level = [string]$_.LevelDisplayName
      Message = [string]$_.Message
    }
  } | ConvertTo-Json -Compress -Depth 3
"""


def collect_events(minutes: int = 30, max_events: int = 800):
    script = _EVENTS_SCRIPT.replace("__MIN__", str(max(1, int(minutes)))) \
                          .replace("__MAX__", str(max_events))
    events = snakeize(as_list(ps_json(script)))
    for e in events:
        msg = e.get("message") or ""
        if len(msg) > 500:
            e["message"] = msg[:500] + "…"
    return events


def collect_diskpart():
    """Best-effort `list disk` via diskpart (admin only). Parsed text."""
    if not is_admin():
        return []
    script = r"$raw = cmd /c \"echo list disk | diskpart\" 2>$null; $raw"
    rc, out, _ = run_ps(script, timeout=20)
    if rc != 0:
        return []
    rows = []
    for line in out.splitlines():
        m = re.match(r"\s*Disk\s+(\d+)\s+(\S+)\s+(.+?)\s*$", line)
        if m:
            rows.append({
                "disk": int(m.group(1)),
                "status": m.group(2),
                "size": m.group(3).strip(),
            })
    return rows


def probe_sensor() -> bool:
    """Verify the event listener is live (evidence-of-absence requires it)."""
    rc, out, _ = run_ps(
        "(Get-WinEvent -LogName System -MaxEvents 1 -ErrorAction SilentlyContinue | Measure-Object).Count",
        timeout=30,
    )
    return rc == 0 and out.strip().isdigit()


# --------------------------------------------------------------------------- #
#  Snapshot                                                                    #
# --------------------------------------------------------------------------- #

def capture_snapshot(minutes: int = 30, label: str = "snapshot") -> dict:
    return {
        "meta": {
            "snapshot_id": uuid.uuid4().hex,
            "label": label,
            "captured_at": now_iso(),
            "hostname": platform.node(),
            "os": platform.system(),
            "os_version": platform.platform(),
            "is_admin": is_admin(),
            "sensor_active": probe_sensor(),
            "tool_version": __version__,
        },
        "usb_pnp": collect_usb_pnp(),
        "pnp_entities": collect_pnp_entities(),
        "disks": collect_disks(),
        "partitions": collect_partitions(),
        "volumes": collect_volumes(),
        "physical_disks": collect_physical_disks(),
        "events": collect_events(minutes),
        "diskpart": collect_diskpart(),
    }


# --------------------------------------------------------------------------- #
#  State comparison (diff)                                                     #
# --------------------------------------------------------------------------- #

def _key_usb(d):
    return d.get("instance_id") or d.get("friendly_name") or "?"


def _key_disk(d):
    return "|".join(str(d.get(k)) for k in ("number", "serial_number", "friendly_name"))


def _key_pnp(d):
    return d.get("device_id") or d.get("name") or "?"


def _key_event(e):
    return (e.get("time_created"), e.get("id"), e.get("provider"))


def _diff_collection(base, post, key_fn, change_fields):
    base_idx = {key_fn(d): d for d in base}
    post_idx = {key_fn(d): d for d in post}
    added = [post_idx[k] for k in post_idx if k not in base_idx]
    removed = [base_idx[k] for k in base_idx if k not in post_idx]
    changed = []
    for k in base_idx.keys() & post_idx.keys():
        b, p = base_idx[k], post_idx[k]
        if any(b.get(f) != p.get(f) for f in change_fields):
            changed.append({"key": k, "before": base_idx[k], "after": post_idx[k]})
    return added, removed, changed


def diff_snapshots(base: dict, post: dict) -> dict:
    usb_added, usb_removed, usb_changed = _diff_collection(
        base.get("usb_pnp", []), post.get("usb_pnp", []),
        _key_usb, ("status", "problem_code", "present"),
    )
    disk_added, disk_removed, disk_changed = _diff_collection(
        base.get("disks", []), post.get("disks", []),
        _key_disk, ("size", "partition_style", "operational_status", "is_offline"),
    )
    pnp_added, pnp_removed, _ = _diff_collection(
        base.get("pnp_entities", []), post.get("pnp_entities", []),
        _key_pnp, ("status", "config_manager_error_code"),
    )
    base_events = {_key_event(e) for e in base.get("events", [])}
    events_new = [e for e in post.get("events", []) if _key_event(e) not in base_events]

    return {
        "usb_added": usb_added,
        "usb_removed": usb_removed,
        "usb_changed": usb_changed,
        "disk_added": disk_added,
        "disk_removed": disk_removed,
        "disk_changed": disk_changed,
        "pnp_added": pnp_added,
        "pnp_removed": pnp_removed,
        "events_new": events_new,
        "any_change": bool(usb_added or usb_removed or usb_changed
                           or disk_added or disk_removed or disk_changed
                           or pnp_added or pnp_removed or events_new),
    }


# --------------------------------------------------------------------------- #
#  Feature extraction (feeds the confidence model)                            #
# --------------------------------------------------------------------------- #

def _usb_disks(post: dict):
    return [d for d in post.get("disks", [])
            if str(d.get("bus_type", "")).upper() == "USB"]


def _storage_appeared(diff, post):
    if diff.get("disk_added"):
        return True
    for p in diff.get("pnp_added", []):
        blob = f"{p.get('service', '')} {p.get('device_id', '')}"
        if re.search(r"USBSTOR|UASPStor|USB Mass Storage", blob, re.IGNORECASE):
            return True
    return False


def _encrypted_volume(post):
    """Heuristic: BitLocker (or similar) signature on a RAW volume."""
    return any(
        "bitlocker" in ((v.get("file_system_label") or "") + " " +
                        (v.get("file_system") or "")).lower()
        for v in post.get("volumes", [])
    )


def assess_media_source(post, card_other_reader, known_card_here):
    """Localize the fault: card reader vs SD card.

    Physical reality: to the USB bridge, a *dead card* and an *empty slot* are
    electrically identical ("no media"). Software alone CANNOT separate them.
    This module therefore combines bridge identification with the operator's
    two cross-tests:

      * card_other_reader — the suspect card tested in a KNOWN-GOOD reader
                            ("ok" = it reads, "failed" = it doesn't).
      * known_card_here   — a KNOWN-GOOD card tested in THIS reader
                            ("ok" = it reads, "failed" = it doesn't).

    Returns None when no card reader is identifiable (e.g. a USB stick, which
    has no separate reader) — the macro failure class then covers it.
    """
    disks = post.get("disks", [])
    pnp = list(post.get("pnp_entities", [])) + list(post.get("usb_pnp", []))
    reader_hits = [d for d in list(disks) + pnp if looks_like_reader(d)]
    if not reader_hits:
        return None

    # De-duplicate reader identities by name, merging in any VID/PID found on
    # whichever object carries it (disk vs pnp vs usb_pnp).
    by_name, order = {}, []
    for d in reader_hits:
        vid, pid = vid_pid(d.get("instance_id") or d.get("device_id"))
        name = (d.get("friendly_name") or d.get("name") or d.get("model") or "").strip()
        key = name or f"__anon_{vid}_{pid}__"
        if key not in by_name:
            by_name[key] = {"vid": vid, "pid": pid, "name": name}
            order.append(key)
        else:
            if not by_name[key]["vid"] and vid:
                by_name[key]["vid"] = vid
            if not by_name[key]["pid"] and pid:
                by_name[key]["pid"] = pid
    identities = [by_name[k] for k in order]

    usb_disks = _usb_disks(post)
    media_present = any((d.get("size") or 0) > 0 for d in usb_disks)

    if media_present:
        return {"reader_detected": True, "media": "present",
                "source": "NONE", "confidence": 1.0,
                "reason": "Reader presents a card-backed disk; card is readable.",
                "identities": identities}

    # Media not presented: run the cross-test matrix (ordered, decisive first).
    if known_card_here == "failed":
        return {"reader_detected": True, "media": "absent",
                "source": "READER", "confidence": 0.95,
                "reason": "A known-good card ALSO fails in this reader -> "
                          "reader slot / contacts / bridge at fault.",
                "identities": identities}
    if known_card_here == "ok" and card_other_reader == "failed":
        return {"reader_detected": True, "media": "absent",
                "source": "CARD", "confidence": 0.95,
                "reason": "Known-good card works here AND the suspect card fails "
                          "in another reader -> the card itself is at fault.",
                "identities": identities}
    if card_other_reader == "ok" and known_card_here == "ok":
        return {"reader_detected": True, "media": "absent",
                "source": "CONTACT", "confidence": 0.70,
                "reason": "Both card and reader test OK individually yet no media "
                          "appears here -> seating / contact / intermittent fault "
                          "(re-seat card, clean contacts, retry).",
                "identities": identities}
    if card_other_reader == "ok":
        return {"reader_detected": True, "media": "absent",
                "source": "READER", "confidence": 0.85,
                "reason": "Suspect card works in another reader -> this reader "
                          "is the fault.",
                "identities": identities}
    if known_card_here == "ok":
        return {"reader_detected": True, "media": "absent",
                "source": "CARD", "confidence": 0.60,
                "reason": "Known-good card works in this reader -> reader OK, "
                          "suspect card at fault (or card not seated).",
                "identities": identities}
    if card_other_reader == "failed":
        return {"reader_detected": True, "media": "absent",
                "source": "CARD", "confidence": 0.55,
                "reason": "Suspect card fails in another reader too -> card "
                          "likely at fault (reader not fully excluded).",
                "identities": identities}

    return {"reader_detected": True, "media": "absent",
            "source": "UNKNOWN", "confidence": 0.0,
            "reason": "Card reader detected but no media presented. A dead card "
                      "and an empty/dead slot are electrically identical over "
                      "USB — run BOTH cross-tests to localize the fault.",
            "required_tests": ["--card-other-reader", "--known-card-here"],
            "identities": identities}


def _empty_features():
    return {
        "no_interrupt": None,
        "control_silent": None,
        "control_ok": None,
        "descriptor_error": None,
        "enum_no_storage": None,
        "capacity_zero": None,
        "medium_not_present": None,
        "raw_visible": None,
        "gpt_backup_valid": None,   # reserved: requires raw GPT backup header read
        "io_error_growth": None,
        "works_other_host": None,
        "fails_other_host": None,
        "driver_problem": None,
        "healthy_present": None,
        "reader_like": None,
        "reader_no_media": None,
    }


def extract_features(base, post, diff, control_result, works_other_host):
    """Extract evidence features.

    Scoring rule (spec 4.6): a feature is scored as present/absent ONLY when
    its precondition is met; otherwise it is `None` (unknown) and contributes
    nothing — so trivial "absent" facts cannot distort the posterior.
    """
    f = _empty_features()
    notes = []

    new_usb = diff.get("usb_added", [])
    new_disks = diff.get("disk_added", [])
    new_pnp = diff.get("pnp_added", [])
    events = diff.get("events_new", [])
    sensor_active = bool(post.get("meta", {}).get("sensor_active", False))

    def any_msg(regex):
        return any(regex.search(e.get("message", "") or "") for e in events)

    # D0 — interrupt observed. A descriptor failure IS an interrupt-triggered
    # event (the port saw activity), so it counts as enumeration evidence.
    kpnp = [e for e in events if e.get("id") in PNP_EVENT_IDS]
    descriptor_msg = any_msg(DESCRIPTOR_ERROR_RE) if (sensor_active or events) else False
    interrupt = bool(new_usb or new_disks or new_pnp or kpnp or descriptor_msg)

    if sensor_active:
        f["no_interrupt"] = not interrupt
    else:
        notes.append("Event sensor inactive: absence-of-evidence NOT usable; "
                     "run as Administrator if the System log is unreadable.")

    # Control-device probe (host-path discrimination).
    if control_result == "failed":
        f["control_silent"] = True
    elif control_result == "ok":
        f["control_ok"] = True

    usb_appeared = bool(new_usb or new_pnp)
    storage_appeared = _storage_appeared(diff, post)
    usb_disks = _usb_disks(post)

    # D1 — enumeration failure signature (only when enumeration was attempted).
    if interrupt:
        f["descriptor_error"] = descriptor_msg

    # D2 — enumerated but no mass storage presented.
    if usb_appeared:
        f["enum_no_storage"] = not storage_appeared

    # D3 — block device: capacity and partition state.
    if storage_appeared:
        if usb_disks:
            sizes = [d.get("size") or 0 for d in usb_disks]
            f["capacity_zero"] = max(sizes) <= 0
            pos = [d for d in usb_disks if (d.get("size") or 0) > 0]
            if pos:
                styles = {str(d.get("partition_style", "")).upper() for d in pos}
                if styles & {"RAW", ""}:
                    f["raw_visible"] = True
                else:
                    f["healthy_present"] = True
        else:
            # MSC bound but no Get-Disk record at all -> no block device.
            f["capacity_zero"] = True

    # SCSI-level sense only applies once mass storage is presented.
    if storage_appeared:
        f["medium_not_present"] = any_msg(MEDIUM_ABSENT_RE)

    # Reader identification: is this a card-reader bridge, and does it have
    # media behind it? (reader-like name + no card-backed disk = reader w/o media)
    reader_like = (any(looks_like_reader(d) for d in post.get("disks", []))
                   or any(looks_like_reader(d) for d in post.get("pnp_entities", []))
                   or any(looks_like_reader(d) for d in post.get("usb_pnp", [])))
    if reader_like:
        f["reader_like"] = True
        if not usb_disks or max((d.get("size") or 0) for d in usb_disks) <= 0:
            f["reader_no_media"] = True

    # Disk I/O errors only meaningful when a USB disk exists to error on.
    if usb_disks:
        disk_errors = [e for e in events if e.get("id") in DISK_ERROR_IDS]
        f["io_error_growth"] = len(disk_errors) >= 2

    # Driver bind problem (ConfigManager codes 10/28/43).
    if new_usb:
        f["driver_problem"] = any(d.get("problem_code") in DRIVER_PROBLEM_CODES
                                  for d in new_usb)

    # Encryption guard: never classify an encrypted RAW volume as corruption.
    if _encrypted_volume(post):
        notes.append("Possible BitLocker-encrypted volume detected — RAW does NOT "
                     "imply corruption; user key/passphrase required.")
        f["raw_visible"] = None

    # Cross-host / cross-port evidence (only when the operator supplies it).
    if works_other_host == "yes":
        f["works_other_host"] = True
    elif works_other_host == "no":
        f["fails_other_host"] = True

    return f, notes


# --------------------------------------------------------------------------- #
#  Confidence scoring (Naive Bayes, log-space) — Section 4                      #
# --------------------------------------------------------------------------- #

def posterior(features: dict) -> dict:
    """Presence-only Naive Bayes in log space (spec 4.3/4.6).

    Only observed findings (feature is True) contribute P(finding | class);
    absent/unknown features are skipped so they cannot distort the posterior.
    """
    logp = {c: math.log(PRIORS[c]) for c in CLASS_IDS}
    for fname, val in features.items():
        if val is not True:
            continue
        lik = FEATURE_LIKELIHOODS.get(fname)
        if lik is None:
            continue
        for c in CLASS_IDS:
            p = min(max(lik[c], 1e-4), 1.0 - 1e-4)
            logp[c] += math.log(p)
    m = max(logp.values())
    exps = {c: math.exp(v - m) for c, v in logp.items()}
    total = sum(exps.values())
    return {c: exps[c] / total for c in CLASS_IDS}


def confidence_tier(posterior_dist: dict) -> str:
    ranked = sorted(CLASS_IDS, key=lambda c: -posterior_dist[c])
    top, second = posterior_dist[ranked[0]], posterior_dist[ranked[1]]
    margin = top - second
    if top >= 0.90 or margin >= 0.30:
        return "HIGH"
    if top >= 0.60:
        return "MEDIUM"
    return "LOW"


def confidence_summary(posterior_dist: dict) -> dict:
    p_hw = posterior_dist["C1"]
    p_meta = posterior_dist["C2"]
    p_other = sum(posterior_dist[c] for c in ("C3", "C4", "C5"))
    denom = (p_hw + p_meta) or 1e-12
    ranked = sorted(CLASS_IDS, key=lambda c: -posterior_dist[c])
    return {
        "posterior": posterior_dist,
        "top_class": ranked[0],
        "top_class_name": CLASS_NAMES[ranked[0]],
        "tier": confidence_tier(posterior_dist),
        "p_hardware_failure": p_hw,
        "p_metadata_corruption": p_meta,
        "p_other": p_other,
        "p_hw_two_way": p_hw / denom,
        "p_meta_two_way": p_meta / denom,
    }


# --------------------------------------------------------------------------- #
#  Decision tree interpreter (Section 2) — diff-based path                      #
# --------------------------------------------------------------------------- #

def decision_tree(base, post, diff, features, control_result):
    trace = []
    new_usb = diff.get("usb_added", [])
    new_disks = diff.get("disk_added", [])
    new_pnp = diff.get("pnp_added", [])
    events = diff.get("events_new", [])
    kpnp = [e for e in events if e.get("id") in PNP_EVENT_IDS]
    sensor_active = bool(post.get("meta", {}).get("sensor_active", False))

    def add(node, outcome, note=""):
        trace.append({"node": node, "outcome": outcome, "note": note})

    # A descriptor failure IS an interrupt-triggered event (the port saw the
    # device), so it counts as enumeration evidence even with no device node.
    descriptor_msg = bool(events) and any(
        DESCRIPTOR_ERROR_RE.search(e.get("message", "") or "") for e in events)
    interrupt = bool(new_usb or new_disks or new_pnp or kpnp or descriptor_msg)

    # --- D0 ----------------------------------------------------------------
    if not interrupt:
        add("D0", "NO INTERRUPT", "no PnP/disk/device change after insertion")
        if control_result == "failed":
            add("D0.1", "HOST PATH FAULT",
                "control device also silent -> dead port/hub/controller")
            return (trace, "HOST-DRIVER", False,
                    "Host path (port/hub) — not the device.")
        if control_result == "ok":
            add("D0.2", "DEVICE ELECTRICALLY DEAD",
                "control enumerates, target silent -> no D+/D- pull-up")
            return (trace, "HW-FAIL", True,
                    "Device draws no response; dead controller/interconnect (LAB).")
        add("D0.3", "UNKNOWN",
            "control probe not run; run a known-good device to confirm host path")
        return (trace, "UNKNOWN", False,
                "Cannot assert hardware failure without a control-device probe.")
    add("D0", "INTERRUPT", f"{len(new_usb)} USB / {len(new_disks)} disk / "
                            f"{len(new_pnp)} pnp new; {len(kpnp)} PnP events")

    # --- D1 ----------------------------------------------------------------
    if not new_usb and not new_pnp:
        if descriptor_msg or features.get("descriptor_error"):
            add("D1", "ENUMERATION FAILED", "descriptor read error in event log")
            return (trace, "HW-FAIL", True,
                    "Unresponsive controller (descriptor failure). Escalate.")
        add("D1", "NO NEW USB DEVICE",
            "events fired but no persistent USB node (transient/power)")
        return (trace, "UNKNOWN", False,
                "Transient event without device node — retry on another port.")
    add("D1", "ENUMERATION OK",
        f"{len(new_usb)} USB PnP device(s), {len(new_pnp)} PnP entit(y/ies) added")

    # --- D2 ----------------------------------------------------------------
    storage_appeared = _storage_appeared(diff, post)
    if not storage_appeared:
        problem_codes = {d.get("problem_code") for d in new_usb}
        if problem_codes & DRIVER_PROBLEM_CODES:
            add("D2", "MSC BIND FAILED",
                f"driver problem code {sorted(problem_codes & DRIVER_PROBLEM_CODES)}")
            return (trace, "HOST-DRIVER", False,
                    "USB device enumerated but mass-storage driver failed to load.")
        add("D2", "NO MASS STORAGE",
            "device enumerated without MSC interface (recovery PID / firmware)")
        return (trace, "VENDOR", True,
                "Recovery-mode firmware or empty reader. Escalate to vendor tool / check media.")
    add("D2", "MASS STORAGE PRESENTED", "MSC interface bound (USBSTOR/UAS)")

    # --- D3 ----------------------------------------------------------------
    usb_disks = _usb_disks(post)
    if not usb_disks:
        add("D3", "NO BLOCK DEVICE", "MSC bound but no Get-Disk record")
        return (trace, "HW-FAIL", True,
                "Mass storage presented but no block device (FTL/NAND). Forbid writes.")

    sizes = [d.get("size") or 0 for d in usb_disks]
    if max(sizes) <= 0:
        readerish = (any(looks_like_reader(d) for d in usb_disks)
                     or any(looks_like_reader(d) for d in new_usb)
                     or any(looks_like_reader(d) for d in new_pnp))
        if readerish:
            add("D3", "READER PRESENT, NO MEDIA",
                "card-reader bridge, no card-backed capacity")
            return (trace, "MEDIA-ABSENT", False,
                    "Card reader without media; cross-tests localize reader vs card.")
        add("D3", "CAPACITY ZERO", "USB disk reports 0 bytes")
        return (trace, "HW-FAIL", True,
                "READ CAPACITY = 0 -> NAND/FTL failure. ALL WRITES FORBIDDEN.")

    raw = [d for d in usb_disks
           if str(d.get("partition_style", "")).upper() in ("RAW", "")]
    if raw:
        add("D3", "BLOCK DEVICE OK, PARTITION RAW",
            "valid capacity but partition table/FS unidentified")
        return (trace, "METADATA-CORRUPTION", False,
                "Eligible for non-destructive MBR/GPT repair ONLY after full imaging.")

    add("D3", "BLOCK DEVICE + PARTITION OK", "USB disk with MBR/GPT partition table")
    add("D4", "FILESYSTEM CLASSIFICATION (terminal)", "out of MVP diagnostic scope")
    return trace, "NORMAL", False, "No storage fault detected at this layer."


# --------------------------------------------------------------------------- #
#  Static classification (device already inserted) — scan mode                 #
# --------------------------------------------------------------------------- #

# Empty diff used by the static path, which has no baseline to compare against.
_EMPTY_DIFF = {
    "usb_added": [], "usb_removed": [], "usb_changed": [],
    "disk_added": [], "disk_removed": [], "disk_changed": [],
    "pnp_added": [], "pnp_removed": [], "events_new": [], "any_change": False,
}


def classify_static(post, works_other_host, card_other_reader=None,
                    known_card_here=None):
    trace = []
    sensor_active = bool(post.get("meta", {}).get("sensor_active", False))
    usb_disks = _usb_disks(post)
    usb_devs = [d for d in post.get("usb_pnp", [])
                if d.get("problem_code") not in (None, 0)]
    events = post.get("events", [])

    def any_msg(regex):
        return any(regex.search(e.get("message", "") or "") for e in events)

    def finalize(disposition, escalate, reason):
        return _finalize(post, post, _EMPTY_DIFF, f, notes, trace,
                         disposition, escalate, reason,
                         card_other_reader, known_card_here)

    f = _empty_features()
    notes = []
    if not sensor_active:
        notes.append("Event sensor inactive; run as Administrator for full evidence.")

    if sensor_active:
        f["descriptor_error"] = any_msg(DESCRIPTOR_ERROR_RE)
        f["medium_not_present"] = any_msg(MEDIUM_ABSENT_RE)
        disk_errors = [e for e in events if e.get("id") in DISK_ERROR_IDS]
        f["io_error_growth"] = len(disk_errors) >= 2

    if works_other_host == "yes":
        f["works_other_host"] = True
    elif works_other_host == "no":
        f["fails_other_host"] = True

    # USB device present with a problem code and no disk -> enumeration ok,
    # storage failed to present (driver bind problem).
    if usb_devs:
        f["driver_problem"] = any(d.get("problem_code") in DRIVER_PROBLEM_CODES
                                  for d in usb_devs)
        f["enum_no_storage"] = not usb_disks

    # Reader identification (static path).
    reader_like = (any(looks_like_reader(d) for d in post.get("disks", []))
                   or any(looks_like_reader(d) for d in post.get("pnp_entities", []))
                   or any(looks_like_reader(d) for d in post.get("usb_pnp", [])))
    if reader_like:
        f["reader_like"] = True
        if not usb_disks or max((d.get("size") or 0) for d in usb_disks) <= 0:
            f["reader_no_media"] = True

    if not usb_disks and not usb_devs:
        if reader_like:
            trace.append({"node": "SCAN", "outcome": "READER PRESENT, NO MEDIA",
                          "note": "card-reader bridge detected, no disk"})
            return finalize("MEDIA-ABSENT", False,
                            "Card reader present but no media/card detected — "
                            "see media-source analysis (cross-tests localize reader vs card).")
        trace.append({"node": "SCAN", "outcome": "NO USB STORAGE DETECTED",
                      "note": "no USB-bus disk and no USB problem device on this host"})
        return finalize("UNKNOWN", False, "No USB mass-storage device found to diagnose.")

    if usb_disks:
        sizes = [d.get("size") or 0 for d in usb_disks]
        if max(sizes) <= 0:
            if reader_like:
                # A card reader reports 0 bytes when no card is seated or the
                # card is dead — NOT a NAND/FTL failure of a USB stick.
                trace.append({"node": "SCAN", "outcome": "READER PRESENT, NO MEDIA",
                              "note": "card-reader bridge present, no card-backed capacity"})
                return finalize("MEDIA-ABSENT", False,
                                "Card reader present but no media/card detected — "
                                "see media-source analysis (cross-tests localize reader vs card).")
            f["capacity_zero"] = True
            trace.append({"node": "SCAN", "outcome": "CAPACITY ZERO",
                          "note": "USB disk reports 0 bytes"})
            return finalize("HW-FAIL", True,
                            "READ CAPACITY = 0 -> NAND/FTL failure. ALL WRITES FORBIDDEN.")
        pos = [d for d in usb_disks if (d.get("size") or 0) > 0]
        if any(str(d.get("partition_style", "")).upper() in ("RAW", "") for d in pos):
            if _encrypted_volume(post):
                notes.append("Possible BitLocker-encrypted volume detected — RAW does "
                             "NOT imply corruption; user key/passphrase required.")
                trace.append({"node": "SCAN", "outcome": "RAW / ENCRYPTED",
                              "note": "RAW volume carries encryption signature"})
                return finalize("UNKNOWN", False,
                                "Encrypted volume detected; key/passphrase required.")
            f["raw_visible"] = True
            trace.append({"node": "SCAN", "outcome": "RAW / UNALLOCATED",
                          "note": "valid capacity, partition table unidentified"})
            return finalize("METADATA-CORRUPTION", False,
                            "Partition/FS metadata fault; non-destructive repair after imaging.")
        f["healthy_present"] = True
        trace.append({"node": "SCAN", "outcome": "USB DISK HEALTHY",
                      "note": "USB-bus disk present with MBR/GPT partition table"})
        return finalize("NORMAL", False, "No storage fault detected at this layer.")

    # No USB disk, but USB device(s) with problem codes.
    codes = {d.get("problem_code") for d in usb_devs}
    if codes & DRIVER_PROBLEM_CODES:
        trace.append({"node": "SCAN", "outcome": "DRIVER PROBLEM",
                      "note": f"problem codes {sorted(codes & DRIVER_PROBLEM_CODES)}"})
        return finalize("HOST-DRIVER", False,
                        "USB device enumerated but mass-storage driver failed to load.")
    trace.append({"node": "SCAN", "outcome": "NO STORAGE BEHIND USB DEVICE",
                  "note": "USB node present, no disk (reader w/o media or firmware state)"})
    return finalize("VENDOR", True, "Recovery firmware or empty reader. Escalate / check media.")


# --------------------------------------------------------------------------- #
#  Result assembly                                                             #
# --------------------------------------------------------------------------- #

def escalation_record(post, diff, reason):
    return {
        "reason": reason,
        "captured_at": post.get("meta", {}).get("captured_at"),
        "usb_devices_new": [
            {"instance_id": d.get("instance_id"),
             "friendly_name": d.get("friendly_name"),
             "vid": vid_pid(d.get("instance_id"))[0],
             "pid": vid_pid(d.get("instance_id"))[1],
             "problem_code": d.get("problem_code")}
            for d in diff.get("usb_added", [])
        ],
        "disks_new": [
            {"number": d.get("number"), "model": d.get("model"),
             "serial": d.get("serial_number"), "size": d.get("size"),
             "partition_style": d.get("partition_style"),
             "bus_type": d.get("bus_type")}
            for d in diff.get("disk_added", [])
        ],
        "relevant_events": [
            e for e in diff.get("events_new", [])
            if e.get("id") in PNP_EVENT_IDS | DISK_ERROR_IDS
            or DESCRIPTOR_ERROR_RE.search(e.get("message", "") or "")
            or MEDIUM_ABSENT_RE.search(e.get("message", "") or "")
        ][:20],
    }


def _finalize(base, post, diff, features, notes, trace, disposition,
              escalate, reason, card_other_reader=None, known_card_here=None):
    post_dist = posterior(features)
    conf = confidence_summary(post_dist)
    media_source = assess_media_source(post, card_other_reader, known_card_here)
    # Zero findings -> posterior reflects priors only -> INCONCLUSIVE.
    if not any(v is True for v in features.values()):
        conf["top_class_name"] = "INCONCLUSIVE"
        conf["tier"] = "LOW"
        notes.append("No positive findings — posterior reflects priors only; "
                     "verdict is INCONCLUSIVE.")
    # Coherence cross-check: a HW-FAIL disposition with dominant metadata
    # probability (or vice versa) downgrades the tier.
    if disposition == "HW-FAIL" and conf["p_metadata_corruption"] > conf["p_hardware_failure"]:
        conf["tier"] = min(conf["tier"], "MEDIUM") if conf["tier"] == "HIGH" else conf["tier"]
        notes.append("Layer coherence check failed — disposition and score disagree; "
                     "treat verdict with caution.")
    return {
        "features": features,
        "notes": notes,
        "decision_tree": trace,
        "disposition": disposition,
        "escalate": escalate,
        "escalation_reason": reason,
        "escalation_record": escalation_record(post, diff, reason) if escalate else None,
        "media_source": media_source,
        "confidence": conf,
        "diff": {
            k: diff[k] for k in
            ("usb_added", "usb_removed", "disk_added", "disk_removed",
             "pnp_added", "events_new", "any_change")
        },
    }


def classify_diff(base, post, control_result, works_other_host,
                  card_other_reader=None, known_card_here=None):
    diff = diff_snapshots(base, post)
    features, notes = extract_features(base, post, diff, control_result,
                                       works_other_host)
    trace, disposition, escalate, reason = decision_tree(
        base, post, diff, features, control_result)
    return _finalize(base, post, diff, features, notes, trace, disposition,
                     escalate, reason, card_other_reader, known_card_here)


# --------------------------------------------------------------------------- #
#  Reporting                                                                   #
# --------------------------------------------------------------------------- #

def _pct(x):
    return f"{x * 100:.1f}%"


def _fmt_feature(name, val):
    if val is None:
        return "unknown "
    if val is True:
        return "PRESENT "
    return "absent  "


def render_report(result: dict) -> str:
    conf = result["confidence"]
    lines = []
    a = lines.append
    a("=" * 78)
    a("USB/FLASH DIAGNOSTIC REPORT")
    a("=" * 78)
    a(f"  Verdict        : {conf['top_class_name']}  (tier {conf['tier']})")
    a(f"  Disposition    : {result['disposition']}")
    a(f"  Escalate       : {'YES — ' + result['escalation_reason'] if result['escalate'] else 'no'}")
    a("")
    a("  Confidence (Naive Bayes posterior):")
    a(f"    P(HARDWARE_FAILURE)     = {_pct(conf['p_hardware_failure'])}")
    a(f"    P(METADATA_CORRUPTION)  = {_pct(conf['p_metadata_corruption'])}")
    a(f"    P(OTHER: host/media/ok) = {_pct(conf['p_other'])}")
    a(f"    Two-way  HW : META      = {_pct(conf['p_hw_two_way'])} : {_pct(conf['p_meta_two_way'])}")
    a("")
    a("  Decision tree trace:")
    for t in result["decision_tree"]:
        a(f"    [{t['node']:>5}] {t['outcome']:<34} {t['note']}")
    a("")
    a("  Evidence features:")
    for name, val in sorted(result["features"].items()):
        a(f"    {name:<18} {_fmt_feature(name, val)}")
    for n in result["notes"]:
        a(f"    NOTE: {n}")
    a("")
    d = result["diff"]
    a("  State diff (baseline -> post):")
    a(f"    USB devices added/removed : {len(d['usb_added'])} / {len(d['usb_removed'])}")
    for dev in d["usb_added"][:10]:
        v, p = vid_pid(dev.get("instance_id"))
        a(f"        + {dev.get('friendly_name')}  [VID:{v or '?'} PID:{p or '?'} "
          f"code={dev.get('problem_code')}]")
    a(f"    Disks added/removed       : {len(d['disk_added'])} / {len(d['disk_removed'])}")
    for disk in d["disk_added"][:10]:
        a(f"        + #{disk.get('number')} {disk.get('friendly_name')} "
          f"size={disk.get('size')} style={disk.get('partition_style')} "
          f"bus={disk.get('bus_type')}")
    a(f"    New events in window      : {len(d['events_new'])}")
    ms = result.get("media_source")
    if ms:
        a("")
        a("  Media-source analysis (card reader vs SD card):")
        a(f"    Reader detected : {'yes' if ms['reader_detected'] else 'no'}")
        a(f"    Media           : {ms['media']}")
        a(f"    Fault source    : {ms['source']}  (confidence {ms['confidence']:.0%})")
        a(f"    Reason          : {ms['reason']}")
        for i in ms.get("identities", []):
            a(f"      - VID:{i['vid'] or '?'} PID:{i['pid'] or '?'} {i['name']}")
        if ms.get("required_tests"):
            a(f"    To localize     : {', '.join(ms['required_tests'])}")
    if result["escalate"] and result["escalation_record"]:
        er = result["escalation_record"]
        a("")
        a("  ESCALATION RECORD (hand to recovery specialist):")
        a(f"    captured_at  : {er['captured_at']}")
        a(f"    reason       : {er['reason']}")
        a(f"    usb devices  : {json.dumps(er['usb_devices_new'])}")
        a(f"    disks        : {json.dumps(er['disks_new'])}")
    a("=" * 78)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
#  CLI                                                                         #
# --------------------------------------------------------------------------- #

def _write_snapshot(snap: dict, path: str):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(snap, fh, indent=2, ensure_ascii=False)
    print(f"Snapshot written to {path}")


def _load_snapshot(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def cmd_snapshot(args):
    ensure_windows()
    snap = capture_snapshot(minutes=args.minutes, label=args.label)
    m = snap["meta"]
    print(f"Captured {m['label']} snapshot @ {m['captured_at']}")
    print(f"  host={m['hostname']}  admin={m['is_admin']}  sensor={m['sensor_active']}")
    print(f"  usb_pnp={len(snap['usb_pnp'])}  disks={len(snap['disks'])}  "
          f"events={len(snap['events'])}")
    if args.out:
        _write_snapshot(snap, args.out)
    else:
        print(json.dumps(snap, indent=2, ensure_ascii=False))


def cmd_compare(args):
    base = _load_snapshot(args.baseline)
    post = _load_snapshot(args.post)
    result = classify_diff(base, post, args.control, args.works_other_host,
                           args.card_other_reader, args.known_card_here)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(render_report(result))


def _prompt(msg):
    try:
        return input(msg)
    except EOFError:
        return ""


def cmd_diagnose(args):
    ensure_windows()
    if args.baseline and args.post:
        base = _load_snapshot(args.baseline)
        post = _load_snapshot(args.post)
    elif args.baseline or args.post:
        sys.exit("ERROR: --baseline and --post must be supplied together.")
    else:
        print("Capturing BASELINE snapshot (target device must be UNPLUGGED)...")
        base = capture_snapshot(minutes=args.minutes, label="baseline")
        print(f"  baseline captured (sensor_active={base['meta']['sensor_active']})")
        if args.save_dir:
            os.makedirs(args.save_dir, exist_ok=True)
            _write_snapshot(base, os.path.join(args.save_dir, "baseline.json"))
        _prompt("\nINSERT the target device now, then press Enter...")
        print(f"Waiting {args.settle}s for enumeration to settle...")
        time.sleep(args.settle)
        print("Capturing POST-INSERTION snapshot...")
        post = capture_snapshot(minutes=args.minutes, label="post")
        if args.save_dir:
            os.makedirs(args.save_dir, exist_ok=True)
            _write_snapshot(post, os.path.join(args.save_dir, "post.json"))

    result = classify_diff(base, post, args.control, args.works_other_host,
                           args.card_other_reader, args.known_card_here)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print()
        print(render_report(result))


def cmd_scan(args):
    ensure_windows()
    print("Capturing static snapshot (device already inserted)...")
    post = capture_snapshot(minutes=args.minutes, label="scan")
    result = classify_static(post, args.works_other_host,
                             args.card_other_reader, args.known_card_here)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print()
        print(render_report(result))


def cmd_watch(args):
    ensure_windows()
    print("Live hot-plug monitor (read-only). Ctrl+C to stop.\n")
    seen_events = set()
    last_usb = {_key_usb(d) for d in collect_usb_pnp()}
    last_disks = {_key_disk(d) for d in collect_disks()}
    try:
        while True:
            time.sleep(args.interval)
            events = collect_events(minutes=2, max_events=200)
            for e in events:
                k = _key_event(e)
                if k not in seen_events:
                    seen_events.add(k)
                    print(f"[{e.get('time_created')}] {e.get('provider')} "
                          f"id={e.get('id')}: {(e.get('message') or '')[:120]}")
            usb = {_key_usb(d) for d in collect_usb_pnp()}
            disks = {_key_disk(d) for d in collect_disks()}
            if usb - last_usb:
                print(f"  USB DEVICE ADDED: {sorted(usb - last_usb)}")
            if last_usb - usb:
                print(f"  USB DEVICE REMOVED: {sorted(last_usb - usb)}")
            if disks - last_disks:
                print(f"  DISK ADDED: {sorted(disks - last_disks)}")
            if last_disks - disks:
                print(f"  DISK REMOVED: {sorted(last_disks - disks)}")
            last_usb, last_disks = usb, disks
    except KeyboardInterrupt:
        print("\nStopped.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="usbdiag",
        description="Windows USB/Flash diagnostic CLI (read-only) — "
                    "detects and classifies non-mounting USB drives / SD cards.",
        epilog="Read-only by default. No repair/write operations are performed.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("snapshot", help="Capture a system state snapshot")
    s.add_argument("--out", help="Write JSON to this file")
    s.add_argument("--label", default="snapshot")
    s.add_argument("--minutes", type=int, default=30,
                   help="event-log lookback window (default 30)")
    s.set_defaults(func=cmd_snapshot)

    c = sub.add_parser("compare", help="Diff two snapshots and classify")
    c.add_argument("--baseline", required=True)
    c.add_argument("--post", required=True)
    c.add_argument("--control", choices=["ok", "failed", "unknown"], default="unknown",
                   help="result of a known-good control-device probe")
    c.add_argument("--works-other-host", choices=["yes", "no"], default=None)
    c.add_argument("--card-other-reader", choices=["ok", "failed"], default=None,
                   help="suspect card tested in a known-good reader")
    c.add_argument("--known-card-here", choices=["ok", "failed"], default=None,
                   help="known-good card tested in THIS reader")
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=cmd_compare)

    d = sub.add_parser("diagnose", help="Guided before/after insertion diagnosis")
    d.add_argument("--baseline", help="pre-insertion snapshot JSON")
    d.add_argument("--post", help="post-insertion snapshot JSON")
    d.add_argument("--settle", type=int, default=6,
                   help="seconds to wait for enumeration (default 6)")
    d.add_argument("--minutes", type=int, default=30)
    d.add_argument("--control", choices=["ok", "failed", "unknown"], default="unknown")
    d.add_argument("--works-other-host", choices=["yes", "no"], default=None)
    d.add_argument("--card-other-reader", choices=["ok", "failed"], default=None,
                   help="suspect card tested in a known-good reader")
    d.add_argument("--known-card-here", choices=["ok", "failed"], default=None,
                   help="known-good card tested in THIS reader")
    d.add_argument("--save-dir", help="write baseline/post snapshots here")
    d.add_argument("--json", action="store_true")
    d.set_defaults(func=cmd_diagnose)

    sc = sub.add_parser("scan", help="Static diagnosis of an already-inserted device")
    sc.add_argument("--minutes", type=int, default=30)
    sc.add_argument("--works-other-host", choices=["yes", "no"], default=None)
    sc.add_argument("--card-other-reader", choices=["ok", "failed"], default=None,
                    help="suspect card tested in a known-good reader")
    sc.add_argument("--known-card-here", choices=["ok", "failed"], default=None,
                    help="known-good card tested in THIS reader")
    sc.add_argument("--json", action="store_true")
    sc.set_defaults(func=cmd_scan)

    w = sub.add_parser("watch", help="Live hot-plug event monitor")
    w.add_argument("--interval", type=float, default=2.0)
    w.set_defaults(func=cmd_watch)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
