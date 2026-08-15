# Engineering Specification — No-Detection Diagnostics for USB Flash Drives & SD Cards

**Document class:** Technical design & logic specification (pre-implementation)
**Audience:** Systems / storage engineering
**Scope:** Python-based CLI diagnostic tool. No code is specified in this document.
**Constraint honored:** Design and logic only.

---

## 0. Scope, Objectives, and Non-Goals

### 0.1 Objectives

The tool must, with **zero destructive behavior by default**, classify and diagnose removable flash media (USB mass-storage devices and SD cards via USB readers) that present in one of four failure modes:

1. **S1 — Zero hardware events:** physical insertion occurs, but the OS records no hot-plug interrupt, no port-status change, and no change in VBUS current draw.
2. **S2 — Enumerated, no mass-storage presentation:** the USB device is assigned an address and descriptor (VID/PID visible), but the Mass Storage Class (MSC, bInterfaceClass `08h`) interface fails to bind or no LUN is presented.
3. **S3 — Presented, no block device:** the storage device responds to INQUIRY but `READ CAPACITY` returns 0, or a block device is never created.
4. **S4 — Visible but RAW/unallocated:** a block device with valid capacity exists, but partitions are RAW (Windows), unallocated (GPT), or filesystem-unidentified (Linux/macOS).

### 0.2 Primary deliverable focus

Deep read-only diagnostics and **before/after insertion state comparison** are the MVP core (Section 6). The tool's central question is: *"Given that the user says the device 'does not appear,' is the failure on the host path, the device controller, the NAND, or the filesystem metadata?"*

### 0.3 Non-Goals (explicit exclusions)

- File/data carving and recovery of user content.
- Firmware reflashing of device controllers (vendor mass-production tools are referenced only as escalation artifacts).
- Board-level repair, reflow, NAND chip-off, or cleanroom work.
- Live performance benchmarking or wear endurance forecasting beyond SMART/health telemetry already exposed.

### 0.4 Privilege model

Deep diagnostics require elevated privilege for raw device and bus access (Linux `root`/`CAP_SYS_RAWIO` for `sg3_utils`/`sdparm`; Windows Administrator for `diskpart`/WMI storage root; macOS `root` for full `ioreg`/`IOStorage` access). The tool must detect and declare its privilege tier, and degrade gracefully to unprivileged read-only reporting when elevation is refused.

---

## 1. Failure Classification Matrix

### 1.1 Symptom → Root Cause

| ID | Observable symptom | Root-cause hypotheses (ranked by likelihood) | OS evidence signature | Disposition |
|----|--------------------|----------------------------------------------|------------------------|-------------|
| S1 | No hot-plug interrupt; no port-status change; no VBUS draw delta | (1) Dead USB bridge/controller IC — D+ pull-up never asserted; (2) severed D+/D− trace or connector; (3) VBUS/GND open (device unpowered); (4) host port dead/overcurrent/hub fault; (5) USB controller disabled in firmware/BIOS or driver not loaded | No udev/WMI/IOKit event with an **active, verified** listener; control device also silent on same port if host-side | See 1.2 |
| S2 | Enumeration OK (VID/PID, address); no `08h` MSC interface or driver bind failure | (1) Controller in recovery/DFU state presenting a non-MSC PID; (2) firmware corruption; (3) host driver missing/conflicted (Windows problem codes 10/28/43); (4) UAS↔BOT transport incompatibility; (5) reader present but **no media seated** | `lsusb -v` shows vendor/HID/DFU class; Windows `ConfigManagerErrorCode` ≠ 0; `uas`/`usb-storage` bind log | SW-FIX (driver/quirk) or ESCALATE (firmware) |
| S3 | INQUIRY OK; `READ CAPACITY` = 0 or fails; no `/dev/sdX` created | (1) NAND unusable / all-planes dead; (2) FTL (logical-to-physical map) corruption; (3) reader with **no card** → `MEDIUM NOT PRESENT`; (4) controller panic → `MEDIUM ERROR` / `NOT READY` | `sg_readcap` returns 0; `dmesg`: `sd: READ CAPACITY failed`; `UNIT ATTENTION / NOT READY / MEDIUM NOT PRESENT` sense | HW-FAIL (permanent) or no-media |
| S4 | Block device with valid capacity; partitions RAW/unallocated/unknown FS | (1) MBR/GPT header corruption (primary GPT lost, backup intact); (2) boot sector / superblock loss; (3) volume encrypted (BitLocker/FileVault/VeraCrypt) → misread as RAW; (4) user quick-format/wipe; (5) intermittent read errors driving OS to mark volume dirty/RAW | `blkid` returns no FS; GPT primary header CRC mismatch but backup valid; Windows `RAW` filesystem label | SW-FIX (metadata) — highest fixability |

### 1.2 Fixability Partition

| Disposition | Meaning | Tool action | Examples |
|-------------|---------|-------------|----------|
| **SW-FIX (non-destructive)** | Host or metadata fault reversible without touching user data regions | Propose gated repair (Section 5) | Driver conflict (S2), UAS quirk (S2), GPT-primary-from-backup (S4), MBR rebuild (S4), backup boot sector restore (S4) |
| **SW-FIX (host remediation)** | Host-side configuration only | Report remediation steps; tool never writes the device | Enable disabled USB controller, change port/hub, disable selective suspend |
| **VENDOR** | Recoverable only via vendor mass-production/reflash tooling | Stop & Escalate; emit device identity + VID/PID for the vendor tool | Recovery-mode PID, FTL rebuild |
| **HW-FAIL (permanent)** | Dead controller, dead NAND, severed interconnect | Stop & Escalate to lab; **block all writes** | No D+ pull-up, `READ CAPACITY`=0, persistent `MEDIUM ERROR` |
| **LAB (board-level)** | Recoverable only with rework/cleanroom | Stop & Escalate | Broken traces, connector reflow |

### 1.3 Cardinal rules derived from the matrix

- **Zero hardware events is never a software-fixable device fault.** S1 with a verified-active listener and a working control device on the same port is, by construction, a hardware failure of device or port.
- **A device that enumerates but fails to present MSC is controller/firmware, not user data loss.** The data is not "lost"; the translation layer or host binding is broken.
- **`READ CAPACITY` = 0 is a NAND/FTL condition, not a partition problem.** No metadata repair can help; writes would accelerate failure.
- **RAW/unallocated is the only category where the tool's write operations are ever justified.**

---

## 2. Diagnostic Decision Tree

Entry condition: user inserts device. The tool must have a **pre-insertion baseline snapshot** and a **verified-active event listener** (Section 6, Phase 2) before this tree is meaningful.

### 2.1 Node definitions

- **D0** — "Did the OS interrupt trigger?" (hot-plug event observed)
- **D1** — USB enumeration (device descriptor, address assignment)
- **D2** — Mass-storage presentation (MSC interface bind, SCSI LUN)
- **D3** — Block device creation (READ CAPACITY, partition table)
- **D4** — Filesystem/mount (out of primary scope, terminal classification only)

### 2.2 Logic flow

```
D0: Did the OS interrupt trigger on insertion?
├─ NO ──────────────────────────────────────────────────────────────
│   Verify sensor active + control device behavior:
│   ├─ Control device ALSO silent on same port
│   │   └─ Host-path fault: check USB controller enabled (BIOS/OS), driver loaded,
│   │      port power, hub. → HOST remediation (SW-FIX). If all ports dead → LAB.
│   └─ Control device enumerates normally
│       └─ Device-side fault. Measure VBUS current draw:
│           ├─ No draw  → unpowered/dead bridge → STOP & ESCALATE (HW-FAIL, permanent)
│           └─ Draw, no enumeration → D+/D− open / no pull-up
│               → STOP & ESCALATE (HW-FAIL / LAB)
│
└─ YES ──────────────────────────────────────────────────────────────
    D1: Enumeration
    ├─ Device descriptor read FAILS (error -71/-110, "device descriptor read/64, error")
    │   └─ Retry on alternate port / powered hub (power-integrity check).
    │       ├─ Recovers → power delivery issue → HOST remediation (SW-FIX)
    │       └─ Persists → unresponsive controller → STOP & ESCALATE (HW-FAIL)
    └─ Device descriptor read OK (VID/PID captured)
        D2: Mass-storage presentation
        ├─ No bInterfaceClass 08h (vendor/HID/DFU class observed)
        │   └─ Controller in recovery/firmware state → STOP & ESCALATE (VENDOR)
        ├─ MSC present but driver bind FAILS (usb-storage/uas/usbstor)
        │   ├─ Problem code 10/28/43 or uas bind failure
        │   │   └─ Try BOT fallback / driver reinstall → SW-FIX; if bind persists → ESCALATE
        │   └─ (removable reader) no media detected
        │       └─ Test card in known-good reader → card fault → ESCALATE
        └─ MSC bound; issue REPORT LUNS / INQUIRY
            ├─ INQUIRY fails: NOT READY / MEDIUM NOT PRESENT / UNIT ATTENTION
            │   └─ No-media vs dead-NAND discrimination (reader vs fixed media)
            │       → STOP & ESCALATE (NOMEDIA → physical check; else HW-FAIL)
            └─ INQUIRY OK
                D3: Block device creation
                ├─ READ CAPACITY = 0 or FAILS (MEDIUM/HARDWARE ERROR)
                │   └─ NAND/FTL failure → STOP & ESCALATE (HW-FAIL, permanent). BLOCK ALL WRITES.
                └─ READ CAPACITY > 0 → block device created
                    ├─ Partition table valid → D4: FS/mount classification (terminal)
                    └─ Partition table invalid / RAW / unallocated
                        └─ S4 path: METADATA_CORRUPTION → eligible for non-destructive repair,
                            ONLY after full imaging and hardware-health gate (Section 5).
```

### 2.3 Stop & Escalate points (explicit)

1. **No interrupt + control device works on same port** → device is electrically dead. No tool action can restore it. Escalate to lab.
2. **No VBUS current draw** → device never powered. Escalate (board-level power/connector).
3. **Device descriptor read error persists across ports/hubs** → controller unresponsive. Escalate.
4. **Enumerates with non-MSC PID (recovery/DFU)** → firmware state. Escalate to vendor tooling with captured VID/PID.
5. **INQUIRY fails with `NOT READY` / `MEDIUM NOT PRESENT` after media cross-check** → dead NAND or absent media. Escalate.
6. **`READ CAPACITY` = 0 or fails with `MEDIUM ERROR`** → FTL/NAND failure. Escalate; **forbid all writes**.
7. **Persistent, monotonically increasing I/O errors during read-only probing** → failing NAND. Abort probing, escalate.

Each escalate point must emit a **structured escalation record**: device identity (VID/PID/serial/model), captured descriptor dump, sense-key/ASC/ASCQ, timestamped evidence bundle, and the recommended disposition (VENDOR vs LAB vs HW-FAIL).

---

## 3. OS Evidence Sources

The tool must programmatically query the following sources. Every collector returns a normalized, timestamped evidence record (JSON) so cross-OS diffing and scoring are uniform.

### 3.1 Windows (WMI / PowerShell / event log)

| Evidence source | Reveals | Maps to |
|-----------------|---------|---------|
| `Get-PnpDevice -Class USB` + `ConfigManagerErrorCode` | PnP device tree, problem codes 10/28/43 (driver failure) | S2 |
| `Get-PnpDeviceProperty` (`DEVPKEY_Device_*`) | Instance state, driver, parent bus | S1, S2 |
| `Get-Disk`, `Get-Partition`, `Get-Volume`, `Get-PhysicalDisk` | Disk/partition/volume enumeration; `BusType=USB`; health status | S3, S4 |
| `Get-WmiObject Win32_DiskDrive` / `Win32_DiskPartition` / `Win32_USBControllerDevice` / `Win32_PnPEntity` / `Win32_USBHub` | Legacy enumeration + USB↔device association | S2, S3 |
| `Get-WinEvent` System log — `Kernel-PnP` (410 = start, 400 = config, 430 = removal, 442 = device), `disk` (51, 153 = retry/IO), `Ntfs` (55, 98), `Kernel-Power` (41) | Hot-plug events, surprise removal, disk/FS errors | S1–S4 |
| `diskpart` → `list disk` / `detail disk` | Low-level disk presence independent of mount | S3 |
| `pnputil /enum-devices /connected` | Driver inventory and status | S2 |
| `devcon status` (Windows SDK) | Device state strings | S2 |
| **USBView.exe** (`C:\Program Files (x86)\Windows Kits\...\usbview.exe`) | Full descriptor + topology tree (endpoints, interfaces) | S2 |
| `C:\Windows\INF\setupapi.dev.log` | Driver install/bind failure history | S2 |
| `Get-StorageReliabilityCounter` / SMART via `Get-PhysicalDisk` | Wear, reallocations, ECC errors | S3 |

### 3.2 Linux (`dmesg` / `lsblk` / `udev` / `sysfs` / `sg3_utils`)

| Evidence source | Reveals | Maps to |
|-----------------|---------|---------|
| `dmesg -w` / `journalctl -k -f` | `usb 1-2: new SuperSpeed USB device`, `device descriptor read/64, error -71/-110`, `usb-storage`/`uas` bind, `sd 0:0:0:0` attach, `READ CAPACITY failed`, I/O errors | S1–S3 |
| `lsusb -t` / `lsusb -v` | Topology, `bDeviceClass`, `bInterfaceClass` (08h = MSC), endpoints | S2 |
| `lsblk -f -o NAME,SIZE,FSTYPE,LABEL,MODEL,TRAN` | Block devices, capacity, FS identity, transport | S3, S4 |
| `udevadm monitor --kernel --udev --property` | Raw hot-plug events (zero-event detection ground truth) | S1 |
| `udevadm info -a -n /dev/sdX` | Device attribute chain | S2, S3 |
| `/sys/bus/usb/devices/*` (`idVendor`, `idProduct`, `bDeviceClass`, `bInterfaceClass`) | Post-enumeration device state | S2 |
| `/sys/block/*/size`, `/sys/block/*/removable` | Capacity sectors, removable flag | S3 |
| `sg_inq`, `sg_vpd --page=0x80/0x83`, `sg_luns`, `sg_readcap`, `sg_opcodes` (sg3_utils) | SCSI INQUIRY, vital-product-data, LUN report, READ CAPACITY | S3 |
| `blockdev --getsize64 /dev/sdX` | Raw capacity | S3 |
| `blkid` / `lsblk -f` | Filesystem detection | S4 |
| `cat /proc/scsi/scsi` | SCSI host/target/LUN registration | S3 |
| `smartctl -a` (USB/ATA bridges that pass SAT) | Wear, reallocation, media errors | S3 |
| `sdparm --all` / `sdparm --get=WCE` | Mode pages, write-protect state | S3 |

### 3.3 macOS (`diskutil` / `system_profiler` / `ioreg` / unified log)

| Evidence source | Reveals | Maps to |
|-----------------|---------|---------|
| `system_profiler SPUSBDataType -json` | USB tree, "not configured"/error states | S1, S2 |
| `system_profiler SPStorageDataType -json` | Storage inventory | S3, S4 |
| `diskutil list` / `diskutil info -plist /dev/diskN` | Disks, partitions, FS, `Whole`/`Internal`/`Removable` | S3, S4 |
| `ioreg -l -p IOUSB` / `-p IOStorage` / `-c IOMedia` | IOKit registry (device attach, IOMedia creation) | S1–S3 |
| `log show --last 30m --predicate 'subsystem == "com.apple.iokit.IOUSB"'` / `log stream --predicate 'eventMessage CONTAINS "USB"'` | Hot-plug/unplug and power events in unified log | S1, S2 |
| `/dev/disk*` + Disk Arbitration notifications (`diskarbitrationd`) | Media appear/disappear events | S1, S3 |
| `kextstat | grep -i usb` | Loaded USB/MSC kernel extensions | S2 |
| `DiagnosticReports` / `system_profiler SPLogsDataType` | Kernel panics / IOKit crashes | S1–S3 |

### 3.4 Capture strategy (uniform across OS)

1. **Baseline snapshot** (pre-insertion): capture all enumerations above into a normalized JSON evidence bundle.
2. **Live listener** (during insertion): capture raw event stream with microsecond timestamps.
3. **Post-insertion snapshot**: recapture the same enumerations.
4. **Delta computation**: diff baseline vs post-snapshot; a **null delta with a verified-active listener is itself the key S1 diagnostic signal** (evidence-of-absence, validated via a control device probe).

---

## 4. Confidence Scoring Model

### 4.1 Objective

Compute, from gathered evidence, a calibrated posterior over failure classes, and specifically the requested marginal:

- **P(HARDWARE_FAILURE)** — permanent device/controller/NAND failure
- **P(METADATA_CORRUPTION)** — reversible filesystem/partition-table fault

The model is a **Naive Bayes classifier over independent evidence features**, computed in log space to avoid underflow.

### 4.2 Classes

| Class | Label | Write-gate |
|-------|-------|------------|
| C1 | HARDWARE_FAILURE (device/controller/NAND) | **All writes forbidden** |
| C2 | METADATA_CORRUPTION (partition/FS metadata) | Non-destructive repair eligible |
| C3 | HOST_DRIVER_FAULT (port/driver/config) | No device write; host remediation |
| C4 | MEDIA_NOT_PRESENT (empty reader/no card) | Physical check; no write |
| C5 | NORMAL (no fault) | — |

### 4.3 Model

```
P(C|E) ∝ P(C) · Πᵢ P(Eᵢ|C)
log P(C|E) = log P(C) + Σᵢ log P(Eᵢ|C)   (then normalize to a distribution)
```

- **Priors P(C):** expert-seeded field priors (e.g., HARDWARE_FAILURE is the modal outcome for "does not appear at all," METADATA_CORRUPTION modal for "visible but RAW"). Stored as configurable, Dirichlet-smoothed values.
- **Likelihoods P(Eᵢ|C):** expert-encoded per evidence feature; MVP uses a table of pre-set likelihood vectors (below), later replaced by frequency counts from labeled field data.

### 4.4 Evidence feature → likelihood rubric (excerpt)

| Evidence feature Eᵢ | P(Eᵢ\|C1 HW) | P(Eᵢ\|C2 META) | P(Eᵢ\|C3 HOST) | P(Eᵢ\|C4 NOMEDIA) |
|---|---|---|---|---|
| No interrupt, listener active, control device works | HIGH | vLOW | LOW | LOW |
| No interrupt, control device **also** silent on same port | LOW | vLOW | HIGH | vLOW |
| Device descriptor read error -71/-110 (persists across ports) | HIGH | vLOW | MED | LOW |
| Enumeration OK, no `08h` interface, recovery PID | HIGH | vLOW | LOW | LOW |
| MSC bound, INQUIRY OK, `READ CAPACITY` = 0 | HIGH | LOW | vLOW | MED |
| `MEDIUM NOT PRESENT` on a removable reader | MED | vLOW | vLOW | HIGH |
| Block device present, valid capacity, `blkid` empty / RAW | LOW | HIGH | vLOW | vLOW |
| GPT primary header CRC bad, backup header valid | vLOW | HIGH | vLOW | vLOW |
| Monotonic I/O error growth during read-only probe | HIGH | MED | LOW | vLOW |
| Same device works on another host | vLOW | vLOW | HIGH | vLOW |
| Works on another port/hub | vLOW | vLOW | HIGH | vLOW |

### 4.5 Outputs and thresholds

1. **Full posterior distribution** over C1–C5 (normalized).
2. **Two-way marginal** for the headline metric:
   - `P(HARDWARE_FAILURE) = P(C1)`
   - `P(METADATA_CORRUPTION) = P(C2)`
   - Remainder reported as `P(OTHER) = P(C3)+P(C4)+P(C5)`; a second normalized two-way `P(HW|¬OTHER) vs P(META|¬OTHER)` is emitted for the user-facing verdict.
3. **Confidence tiers** (based on top-class probability and margin over runner-up):

| Tier | Rule | Action |
|------|------|--------|
| HIGH | top-class ≥ 0.90 **or** margin ≥ 0.30 | Assert verdict; authorize gated actions |
| MEDIUM | top-class ≥ 0.60 | Assert verdict with caveats; require additional probes |
| LOW | otherwise | Refuse write actions; request more evidence / escalation |

4. **Coherence cross-check:** independent layers must agree. If the block-device layer contradicts the SCSI layer (e.g., `/dev/sdX` exists but `sg_readcap` reports 0), flag an incoherence and **downgrade confidence by one tier** rather than trust either source.

### 4.6 Absence-of-evidence vs evidence-of-absence

A negative observation (e.g., "no interrupt fired") is only valid likelihood evidence if the sensor is **proven active**. The tool therefore:
1. Verifies the event listener is live before insertion (self-test).
2. Probes a **known-good control device** to confirm the host path and listener are functioning.
3. Only then treats a null delta as evidence of device-side hardware failure.

Without steps 1–2, a null delta is `UNKNOWN`, not evidence.

---

## 5. Safety & Repair Framework

### 5.1 Default policy (non-negotiable)

> **The tool is read-only by default.** No write I/O to the target device is permitted unless (a) the user explicitly escalates through a tiered consent gate, and (b) all preconditions in 5.4 are satisfied.

Enforcement layers:
- **Kernel/OS write-lock** where available: `blockdev --setro`, `mount -o ro`, Windows storage read-only policy (`Set-Disk`/`diskpart attributes disk set readonly`), macOS `hdiutil`/Disk Arbitration read-only attach.
- **Hardware write-protect**: instruct the user to set the SD card's physical WP switch; treat its state as authoritative where detectable.
- **Tool-internal guard**: refuse any code path that opens the device `O_RDWR`/with write flags unless the active repair gate permits it.

### 5.2 Repair categorization

| Repair | Class | Bytes written | Risk | Preconditions |
|--------|-------|---------------|------|---------------|
| MBR rebuild (LBA 0) | **Non-destructive** | 512 B (partition table only) | Low | Full image + original LBA0 saved |
| GPT repair: primary ← backup header | **Non-destructive** | GPT header + entries | Low | Backup header CRC-valid |
| Partition table reconstruction (scan-based) | **Non-destructive** | Table sectors only | Medium | Full image + saved original table |
| NTFS: restore `$Boot` from backup boot sector | **Non-destructive** | 1 boot sector | Low | Backup sector valid |
| FAT/exFAT: restore backup boot sector | **Non-destructive** | 1 boot sector | Low | Backup sector valid |
| ext: restore backup superblock | **Non-destructive** | 1 superblock | Low | Backup superblock valid |
| `chkdsk /f` / `fsck -y` (write-mode repair) | **Non-destructive-ish** | FS metadata (may alter data) | Medium | Full image first |
| Zero-fill / ATA Secure Erase / Sanitize | **Destructive** | Entire device | High (total data loss) | Image + explicit consent + HW-health gate |
| Reformat (`mkfs`/format) | **Destructive** | FS metadata + data region reset | High | Consent + HW-health gate |
| TRIM/discard (FTL reset) | **Destructive** | FTL-level, non-reversible | High | Consent + HW-health gate |

### 5.3 Destructive vs non-destructive boundary

- **Non-destructive** writes touch only *container metadata* (partition table, boot sector, superblock) and preserve all data regions. They are reversible when the pre-write sector image is retained.
- **Destructive** writes touch data regions or the FTL. They are irreversible and require the highest gate tier.

### 5.4 Safeguards (ordered, mandatory)

1. **Mandatory forensic image first.** A sector-level image (logical copy of all readable sectors) is taken before *any* write, including non-destructive metadata writes. Image is hashed (e.g., SHA-256) and readback-verified.
2. **Pre-write sector backup.** Original sectors about to be overwritten (LBA0, GPT header, boot sector, superblock) are saved verbatim to a rollback file before modification.
3. **Hardware-health gate.** All writes are **blocked if P(HARDWARE_FAILURE) ≥ 0.50**. Writing to failing NAND accelerates data loss and can permanently destroy recoverable content; such devices are routed to escalation.
4. **Target identity lock.** Before any write, the tool re-verifies target identity (serial/model/size hash) against the evidence bundle recorded at diagnosis, and refuses if it changed (device swapped mid-session).
5. **System-disk exclusion.** Only devices flagged `removable` / `BusType=USB` / `Whole disk` are eligible; internal/system disks are never targets regardless of flags.
6. **Tiered human confirmation gates.**

| Gate tier | Applies to | Required confirmation |
|-----------|------------|-----------------------|
| G0 | Read-only diagnostics | None |
| G1 | Non-destructive metadata write | Explicit `--repair` flag + typed device serial |
| G2 | `chkdsk /f`/`fsck` write mode | Explicit flag + serial + acknowledgment of risk |
| G3 | Destructive (zero-fill/reformat/erase) | Explicit flag + serial + typed confirmation phrase + cooldown |

7. **Dry-run.** Every repair supports `--dry-run`, which reports exact planned writes (LBA, length, purpose) without executing, in a diffable format.
8. **Write-verify-readback.** Every metadata write is followed by a readback comparison; mismatch aborts the session.
9. **Encryption check before RAW classification.** A RAW volume must first be probed for BitLocker/FileVault/VeraCrypt/LUKS signatures; if present, the tool prompts for the key/passphrase and **never** treats an encrypted volume as corruption.
10. **Provenance log.** Full evidence + actions + hashes are written to an audit JSON, enabling reconstruction and accountability.

---

## 6. MVP Execution Plan

**Core principle:** build **Deep Diagnostics (Phase 1)** and **State Comparison (Phase 2)** first — these answer "does not appear at all" with zero write risk. Repair and scoring polish come later.

| Phase | Deliverable focus | Key outputs | Exit criteria |
|-------|-------------------|-------------|---------------|
| **P0 — Foundations** (wk 1) | Cross-platform host abstraction: OS detection, privilege check, subprocess wrapper, evidence JSON schema, structured logging, config/prior table | Normalized evidence schema v1; privilege-tier reporting | Tool snapshots a host on all three OSes; schema versioned |
| **P1 — Deep Diagnostics, read-only** (wk 2–4) | Collectors for all Section 3 sources; hierarchical interpreter implementing the Section 2 decision tree; escalation-record generator | Evidence bundle + classification + escalation records | Known-good and known-dead control devices produce correct D0–D3 traversal and disposition |
| **P2 — State Comparison** (wk 5–6) | Pre/post-insertion snapshot diffing; verified-active event listener; control-device port probe; zero-event (S1) detection | Insertion delta report; S1 classification with listener self-test | Reliably detects S1; null-delta only reported when listener is proven active |
| **P3 — Confidence Scoring** (wk 7–8) | Naive Bayes engine with expert priors; coherence cross-check; tiering; JSON/HTML/text reports | P(HW) vs P(META) verdicts with tiers | Stable, coherent scores; LOW tier correctly refuses writes |
| **P4 — Non-destructive repair** (wk 9–10) | Imaging, pre-write sector backup, MBR/GPT/boot-sector/superblock repairs behind G1 gate | Guided repair for S4 | S4 devices recovered without data-region writes; rollback works |
| **P5 — Destructive operations** (wk 11–12, optional) | Zero-fill / secure erase / reformat behind G3 gate with full consent workflow | Gated destructive path | Destructive ops execute only through full gate chain |

### 6.1 Test matrix (must be reproducible)

| Case | Expected tool behavior |
|------|------------------------|
| Known-good device | C5 NORMAL, full enumeration, no delta anomalies |
| Dead controller (no pull-up) | S1 → HW-FAIL, HIGH confidence, writes blocked |
| Reader with no card | C4 MEDIA_NOT_PRESENT, physical-check prompt |
| Enumerates as recovery PID | S2 → VENDOR escalation with VID/PID |
| READ CAPACITY = 0 device | S3 → HW-FAIL, all writes forbidden |
| RAW GPT device (backup valid) | S4 → METADATA_CORRUPTION, non-destructive repair proposed |
| Host port dead (control also silent) | S1 → HOST remediation path, no device write |
| Encrypted RAW volume | Prompt for key; never classified as corruption |

### 6.2 Risk register (top items)

| Risk | Mitigation |
|------|-----------|
| Unprivileged run yields empty evidence → misclassified as S1 | Privilege-tier detection; refuse to assert S1 without active-listener proof |
| Writes to failing NAND destroy recoverable data | Hardware-health gate (P(HW) ≥ 0.5 ⇒ no writes); escalation routing |
| Device swapped between diagnosis and repair | Target identity lock (serial/size-hash re-verify) |
| Tool touches system disk | Removable/USB-whole-disk allowlist |
| Expert priors miscalibrated | Dirichlet smoothing; field-data recalibration in P3+ |
| OS blocks raw device access (macOS TCC, Windows policy) | Graceful degradation; emit explicit access-failure evidence, not a false verdict |

---

## 7. Summary of the No-Detection Logic

1. **Prove the sensor is live** (listener self-test + control-device probe) *before* trusting any "no event" observation.
2. **Walk the OS stack in order** — interrupt → enumeration → mass-storage → block device — and stop at the first layer that fails; the failing layer determines the disposition class.
3. **Never attempt metadata repair below the block-device layer.** No block device (S3) and no enumeration (S1/S2) are controller/NAND/host faults, not filesystem faults.
4. **Score, then gate.** Writes are permitted only when P(METADATA_CORRUPTION) dominates and P(HARDWARE_FAILURE) is below threshold, after a full forensic image and tiered consent.
5. **Escalate with a complete evidence bundle** at every hardware boundary — the escalation record (identity, descriptors, sense data, timestamps) is the deliverable that makes professional recovery possible.
