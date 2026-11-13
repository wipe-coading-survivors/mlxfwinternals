# mlxfwinternals

Firmware research workbench for NVIDIA/Mellanox ConnectX network adapters
(InfiniBand/Ethernet HCA cards): reference documentation of firmware image
formats, tooling for image inspection and patching, driverless PCIe access
for live hardware experiments, and a reverse-engineered ISA definition of
the firmware's internal CPU.

## What's inside

| Path | What |
|---|---|
| `docs/` | Numbered reference documentation, index in `docs/TOC.md`: image formats (FS2–FS4 flash layouts, section tables, hashes, burn order), signing & secure-firmware gates, boot chain, cable/transceiver gates, iRISC ISA research notes |
| `mlxfwutil.py` | Python toolkit: inspect, diff, patch, re-sign and verify FS3/FS4 firmware images, incl. baked-in port configurations and personalities |
| `crates/mlxdirect` | Rust library: driverless PCIe (VFIO) access to the adapter — CR-space registers, firmware command queues (CMDQ), identity-mapped DMA window, icmd/mailbox transport |
| `crates/mlxscope` | Rust CLI on top of `mlxdirect`: hardware trace-buffer control (arm/drain), CR-reserve dump cycles, flow-table command sequences, on-device fuzz-vector batteries |
| `scripts/` | Experiment and probe builders used to produce the research recorded in `docs/` |
| `.github/` | CI for the published repository: cargo workspace tests plus a bare pytest run on every change to the `public` branch |
| `skills/` | Agent workflow skill (opencode) used in our research process |

## Documentation layout

`docs/TOC.md` is the entry point. Shelves by role: `010-roadmap`
(initiative maps), `050-hardware` (hardware facts), `150-external`
(walkthroughs of external artifacts), `250-re` (reverse-engineered facts:
formats, signing, boot chain, iRISC), `550-poc` (tool specs),
`750-exp` (experiment records), `850-howto` (verified recipes).
Updates land via reviewed snapshot PRs onto the `public` branch.

## Reproducible checkout

Two kinds of files are intentionally not stored in git: the full iRISC
`.slaspec` definition (derived: `make slaspec-gen` applies the tracked
patch `scripts/irisc/iRISC.slaspec.patch` to the pinned upstream file,
verifying sha256 of both) and the local hardware registry
(`hardware.local.md`, schema documented in `hardware.local.md.example`).
Tests that depend on them are skipped, not failed, when they are absent.

## Warning

These tools research and modify firmware of real hardware. Using them on
your cards can render them inoperative and may void warranties. Flash at
your own risk. This project is not affiliated with NVIDIA/Mellanox;
"ConnectX", "Mellanox" and "NVIDIA" are trademarks of their respective
owners.

## License

GPL-3.0-or-later (see `LICENSE`).
