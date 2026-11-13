# SerDes decompilation corpus (roadmap 190, arc A)

One-command reproducible corpus of decompilation artifacts over the
md5-pinned firmware images of the corpus manifest
([`manifest.py`](manifest.py), tiers T1/T2/T3). Spec:
`docs/superpowers/specs/2026-11-11-serdes-corpus-a-design.md` (§3 layout,
§7 tools, §8 criteria).

## Make targets

```
make corpus        # build build/corpus/ from refs/ (cleanup via scripts/safe-rm)
make corpus-check  # rebuild into a tmp dir + byte-diff artifacts and manifest
```

CLI (what the targets call):

```
python3 -m scripts.corpus.build_corpus [--refs ROOT] [--out ROOT]
    [--manifest PATH] [--t3] [--only FAMILY/VER/SKU] [--jobs N] [--check]
```

`--jobs N` (default `min(cpu_count, 8)`): per-image process pool;
`--jobs 1` is the plain serial loop. Parallel output is byte-identical
to serial (sorted assembly of the summary manifest after join).

## Pipeline stages

1. **Manifest + md5 gate** (`manifest.py`): resolve T1+T2 (`--t3` adds T3)
   refs, verify md5 per image. Drift or a missing file refuses the whole
   build (exit 2).
2. **Extraction** (`extract.py`): ITOC header/entry CRC gate, per-section
   payload (de-clcrc when cl=1), domain prior (iRISC / PHY / ROM / data),
   instance classifier check on iRISC candidates — a prior/instance
   disagreement raises `PriorDisagreement` and is a hard stop (exit 3).
3. **Domain dispatch** (`build_corpus.py`):
   - **iRISC** (0x02–0x07, 0x0D, 0x0E, 0x15): full set — `disasm.txt`
     (census-annotated via the family profile; absent profile → plain
     disasm + `profile.status = "absent"`, no crash), `funcs.tsv`,
     `calls.tsv`, `xref.tsv`, `consts.tsv`, `strings.txt`, `pseudo.md`.
     Section load base = ITOC `param0`; function entries = `param1` +
     direct call targets; `calls.tsv` resolves `target_section` via the
     param0-based windows of the image's code sections.
   - **PHY** (0x0A/0x0B/0x0C): `slots.tsv` — 16-byte slot table parsed by
     `scripts/phyuc/phyuc_dis.py:slots` (chosen over
     `phyuc_diff.load_slots`: in-memory payload, no strict 6-zero-byte
     invariant → a malformed payload is a per-section ERROR, not a build
     crash). No disasm.
   - **ROM** (0x18): raw + md5 + minimal signature sniff (`55 AA` →
     `pci_oprom`, `MZ` → `pe_mz`, else `unknown`) in `meta.json` /
     manifest. No disasm.
   - **data** (everything else): raw + md5 only.
4. **Summary manifest** (`corpus_manifest.json`, committed next to this
   README; placeholder until the Task 9 full build).

## Layout

```
build/corpus/<family>/<ver>/<sku>/sections/<TYPE>/
    raw.bin dc.bin meta.json          # every section
    disasm.txt funcs.tsv calls.tsv xref.tsv consts.tsv strings.txt pseudo.md
                                       # iRISC domain only
    slots.tsv                          # PHY domain only
```

`TYPE` is the two-digit uppercase hex ITOC type. `dc.bin` is empty when
there is no decoded payload (zipped / cl-error).

## Statuses

- Per-section: `OK` / `SKIPPED` (reason: `zipped`) /
  `ERROR` (reason: clcrc line CRC, malformed PHY slot table, ...).
  A section-level ERROR is recorded and the build continues; 0-ERROR on
  T1 images is a Task 9 gate, not code.
- Per-image: `OK` / `ERROR` (reason: parse failure, ITOC CRC mismatch).
- Build-level hard stops: md5 drift / missing image (refuse), and
  `PriorDisagreement` (classifier contradicts the domain prior).

## Artifact formats

- `funcs.tsv`: `entry_dc end_dc size_words frame n_callers`
- `calls.tsv`: `site_dc target_dc target_section` (`-` when unresolved)
- `xref.tsv`: `dc kind value` (kind ∈ call_target / jump_target /
  ram_word / abs_addr); `dc` is the site's absolute dc address, and
  call_target / jump_target values are absolute dc addresses too;
  `ram_word` is the CR word address formed as imm<<2 (LD_I) and
  `abs_addr` the register-relative LD_D/ST_D offset (s14<<2 / store
  offset) — neither of those two is a dc address
- `consts.tsv`: `kind value count` — `imm` rows are the imm histogram,
  `table` rows are dense nonzero-word tables (value = absolute dc start)
- `strings.txt`: `dc string` (absolute dc offset, ASCII ≥ 4)
- `slots.tsv`: `idx op a b c d class asm`
- `pseudo.md`: skeleton, header `<!-- SKELETON: mechanical, untrusted -->`

## Summary manifest schema (`corpus_manifest.json`)

```json
{
  "schema": 1,
  "images": [
    {
      "path": "...", "md5": "...", "tier": 1,
      "family": "cx5", "ver": "16_35_4030", "sku": "MCX516A-CDA",
      "status": "OK", "status_reason": "",
      "sections": [
        {
          "type": "02", "domain": "iRISC", "status": "OK",
          "status_reason": "", "size": 0, "cl": false, "zipped": false,
          "words": 0, "md5_raw": "...", "md5_dc": "..." ,
          "metrics": {"words_in_bounds_ratio": 0.0,
                       "call_targets_on_prologue_ratio": 1.0,
                       "n_funcs": 0, "n_blocks": 0},
          "profile": {"name": "cx5", "status": "ok", "drift": false}
        }
      ]
    }
  ]
}
```

`md5_dc` is `null` when there is no decoded payload. `metrics` and
`profile` are non-null only for OK iRISC sections (`profile.status`:
`ok` or `absent`). `n_slots` appears in the per-section `meta.json` of
PHY sections, `rom_signature` in that of ROM sections. The manifest is
timestamp-free: a rerun must reproduce it byte-for-byte (`--check`
depends on it). Images are sorted by (family, ver, sku), sections by
type, JSON keys sorted.

## Modules

- `manifest.py` — pinned image refs, md5 gate, profile name mapping
- `extract.py` — ITOC section extraction, domain priors, classifier gate
- `disasm_build.py` — disasm lines/text, census annotation, profile drift
- `gen_profile.py` — one-off provisional profile generator (Task 9)
- `boundaries.py` — function boundary detection
- `indexes.py` — calls/xref/consts/strings trust-layer indexes
- `skeleton.py` — pseudo-code skeleton
- `build_corpus.py` — orchestrator + CLI (this README's subject)
