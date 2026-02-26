# Advanced TPM Hooking & NVRAM Sanitization Driver

> **Inspired by SamuelTulach** this project builds on that foundation but introduces **heavy architectural improvements** focused on stealth, tighter interception scope, safer kernel memory handling, and expanded TPM response sanitization.

---

## Overview

This repository provides a kernel-mode TPM interception driver with an emphasis on:

- **In-module code cave hosting** (no suspicious executable allocations)
- **Trampoline-based redirection** (pointer remains inside `tpm.sys`)
- **MDL-backed protected-memory patching**
- **Targeted** `IRP_MJ_DEVICE_CONTROL` interception (no full dispatch table overwrite)
- **Expanded spoofing scope**, including **NVRAM read sanitization**
- **Tagged allocations** and **hardware-driven entropy** for runtime variability

---

## Architecture Diagram



<img width="1137" height="584" alt="image" src="https://github.com/user-attachments/assets/f4725155-7465-46b4-a284-cf7f032f3e45" />


## Advanced Features & Architectural Improvements

### 1) Advanced Stealth & Trampoline Hooking

#### Code Cave Injection

The driver dynamically scans the legitimate `tpm.sys` image (typically `.text` and/or `PAGE` sections) to locate unused regions that are commonly filled with:

- `0x00`
- `0xCC`
- `0x90`

These regions are repurposed to host the hook payload **inside** the target module, avoiding suspicious standalone executable allocations.

**Refs:** [R1], [R2]

---

#### Trampoline Execution (12-byte)

Instead of bluntly overwriting multiple pointers or patching a large code span, this implementation writes a **custom 12-byte assembly trampoline** into the discovered code cave. The dispatch pointer continues to point to a **valid address within** `tpm.sys`, while execution is redirected through the trampoline to the custom handler.

This approach preserves superficial “pointer-in-module” expectations and reduces detection surface.

**Refs:** [R1], [R2]

---

#### MDL Memory Protection Bypass (Controlled Mapping)

To write into pages that may be read-only, the driver uses an MDL-based workflow:

- `IoAllocateMdl`
- `MmProbeAndLockPages`
- `MmProtectMdlSystemAddress`

This enables writing the trampoline with a controlled mapping rather than globally flipping protections.

**Refs:** [R3], [R4], [R5]

---

#### Targeted Pointer Modification (Low Noise)

The interception scope is intentionally limited to **only** `IRP_MJ_DEVICE_CONTROL`, avoiding the high-noise and easily detectable pattern of overwriting the full `MajorFunction` array.

**Refs:** [R6]

---

### 2) Expanded Spoofing Scope

#### NVRAM Interception — `TPM_CC_NV_Read`

Beyond common `TPM_CC_ReadPublic` (e.g., EK-related) response manipulation, this implementation also intercepts **Non-Volatile Memory read** requests (`TPM_CC_NV_Read`) and sanitizes the response by **zeroing** the returned data buffer.

This reduces the value of deeper hardware identity queries that rely on NV indices.

**Refs:** [R7]

---

### 3) Kernel-Safe Memory & Entropy

#### Tagged Allocations

Deprecated allocation patterns are dropped in favor of **tagged pool allocations** via:

- `ExAllocatePoolWithTag`

This improves kernel memory hygiene, makes allocations auditable, and supports clean lifecycle management.

**Refs:** [R8]

---

#### Hardware-Driven Entropy

Runtime variability uses processor-driven inputs combined with Windows RNG primitives:

- `__rdtsc` (timestamp counter)
- `RtlRandomEx`

These are combined to dynamically randomize strings and spoofed values to reduce static fingerprints.

**Refs:** [R9], [R10]

---

## Design Goals

- Keep redirection **in-module** where possible
- Minimize surface area: **one dispatch major** (`IRP_MJ_DEVICE_CONTROL`)
- Prefer **controlled MDL mappings** over broad protection changes
- Maintain clean memory discipline via **pool tags**
- Ensure spoofing is not trivially static via **runtime entropy**

---

## References

- **[R1]** Samuel Tulach — public TPM-related kernel research/code (inspiration reference).
- **[R2]** Microsoft Learn — PE/driver/module fundamentals and kernel driver development concepts (general background for module sectioning and kernel execution context).
- **[R3]** Microsoft Learn — `IoAllocateMdl` documentation.
- **[R4]** Microsoft Learn — `MmProbeAndLockPages` documentation.
- **[R5]** Microsoft Learn — `MmProtectMdlSystemAddress` documentation.
- **[R6]** Microsoft Learn — IRP major function codes (`IRP_MJ_DEVICE_CONTROL`) and dispatch routine concepts.
- **[R7]** Trusted Computing Group (TCG) — TPM 2.0 Library Specification (command codes including `TPM_CC_ReadPublic` and `TPM_CC_NV_Read`).
- **[R8]** Microsoft Learn — `ExAllocatePoolWithTag` documentation.
- **[R9]** Microsoft documentation — `RtlRandomEx` documentation.
- **[R10]** Compiler/CPU intrinsic documentation — `__rdtsc` intrinsic reference.

