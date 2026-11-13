import argparse
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import mlxfwutil
import irisc_dis
import profiles

CLASSES = ('decoder_bug', 'documented', 'data', 'outside_slaspec')

UPSTREAM_SLASPEC = HERE / 'iRISC.upstream.slaspec'
UPSTREAM_SLASPEC_SHA256 = (
    '8762506f9bd718f0d39154c2a67afecc23652f4ab64bf5565e5cf3e492cf1009')

GHIDRA_IMAGE_DEFAULT = 'mlxini-ghidra-irisc'
GHIDRA_CONTAINER_DIR_DEFAULT = ROOT.parent / 'ghidra-container'
GHIDRA_LANG_DIR = '/opt/ghidra/Ghidra/Processors/iRISC/data/languages'
SLEIGH_COMPILE = (
    'cd /opt/ghidra/Ghidra/Processors/iRISC/data && '
    '/opt/jdk21/bin/java -Xmx2048M -cp '
    '"/opt/ghidra/Ghidra/Framework/SoftwareModeling/lib/*:'
    '/opt/ghidra/Ghidra/Framework/Generic/lib/*:'
    '/opt/ghidra/Ghidra/Framework/Utility/lib/*" '
    'ghidra.pcodeCPort.slgh_compile.SleighCompile '
    '-DBaseDir=/opt/ghidra/ -i sleighArgs.txt -a ./languages')

CROSS_DUMP_JAVA = '''import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import java.io.BufferedWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class CrossDump extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Path out = Paths.get(args[0]);
        Program prog = getCurrentProgram();
        Address base = prog.getImageBase();
        long size = prog.getMemory().getBlock(base).getSize();
        Disassembler dis = Disassembler.getDisassembler(prog, getMonitor(),
            DisassemblerMessageListener.IGNORE);
        AddressSet range = new AddressSet(base, base.add(size - 4));
        dis.disassemble(range, null, false);
        int n = 0;
        int unk = 0;
        try (BufferedWriter w = Files.newBufferedWriter(out)) {
            for (Instruction i : prog.getListing().getInstructions(range, true)) {
                String s = i.toString();
                w.write(i.getAddress() + "  " + s);
                w.newLine();
                n++;
                if (s.startsWith("unk")) {
                    unk++;
                }
            }
        }
        println("CROSSDUMP insns=" + n + " unk=" + unk);
        println("DONE");
    }
}
'''

CC_NAME_TO_HEX = {
    'eq32': 0x00, 'gt32': 0x01, 'lt32': 0x02, 'ugt32': 0x03, 'ult32': 0x04,
    'neg32': 0x0c, 'pos32': 0x0d, 'cmpres': 0x0a,
    'eq64': 0x10, 'gt64': 0x11, 'lt64': 0x12, 'ugt64': 0x13, 'ult64': 0x14,
    'neg64': 0x1c, 'pos64': 0x1d,
}

DATA_TAIL_RE = re.compile(r'version tail|data-side|table zones', re.I)
_DUMP_LINE_RE = re.compile(r'^([0-9a-fA-F]{8})\s\s+(.+?)\s*$')
_REG_RE = re.compile(r'^r(\d+)[lh]?$')
_CSR_RE = re.compile(r'^csr(?:0x)?([0-9a-fA-F]+)$')
_CSR_BLOCK_RE = re.compile(
    r'define register offset=(0x[0-9a-fA-F]+) size=(\d+) \[([^\]]*)\]')


def _csr_names(path):
    names = {}
    text = path.read_text()
    for m in _CSR_BLOCK_RE.finditer(text):
        base = int(m.group(1), 0)
        step = int(m.group(2), 10)
        for i, nm in enumerate(m.group(3).split()):
            off = base + i * step
            if 0x40000 <= off < 0x42000 and (off - 0x40000) % 4 == 0:
                names[nm] = (off - 0x40000) >> 2
    return names


_CSR_NAMES = None


def csr_names():
    global _CSR_NAMES
    if _CSR_NAMES is None:
        _CSR_NAMES = _csr_names(HERE / 'iRISC.slaspec')
    return _CSR_NAMES


def resolve_cre():
    return 'podman-remote' if os.path.exists('/run/.containerenv') else 'podman'


def ghidra_container_rev(container_dir=None):
    d = Path(container_dir) if container_dir is not None \
        else GHIDRA_CONTAINER_DIR_DEFAULT
    if not d.is_dir():
        return None
    try:
        r = subprocess.run(
            ['git', '-C', str(d), 'rev-parse', '--short', 'HEAD'],
            capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return r.stdout.strip() or None


def stamp_ghidra_container_rev(report, container_dir=None):
    rev = ghidra_container_rev(container_dir)
    if rev:
        report['ghidra_container_rev'] = rev


def host_path(p):
    s = str(p)
    if s.startswith('/run/host/'):
        s = s[len('/run/host/'):]
    return s


def data_tail_ops(census):
    out = set()
    for op, entry in census.items():
        note = entry.get('note', '') if isinstance(entry, dict) else ''
        if note and DATA_TAIL_RE.search(note):
            out.add(int(op, 16))
    return out


def _mnem_hex_suffix(m):
    return int(m, 16)


def _canon_ours_mnem(m):
    if m.startswith('op0x'):
        return 'op0x%02x' % int(m[4:], 16)
    if m.startswith('alu.0x'):
        return 'alu.0x%02x' % int(m[6:], 16)
    parts = m.split('.')
    if len(parts) == 3 and parts[0] == 'b' and parts[1] in ('t', 'f'):
        return 'b.%s.0x%02x' % (parts[1], _mnem_hex_suffix(parts[2]))
    return m


def _canon_ghidra_mnem(m, raw_ops):
    parts = m.split('.')
    if parts[0] == 'unk':
        return 'op0x%02x' % _mnem_hex_suffix(parts[1])
    if len(parts) == 4 and parts[0] == 'b' and parts[1] in ('t', 'f') \
            and parts[2] == 'unk':
        return 'b.%s.0x%02x' % (parts[1], _mnem_hex_suffix(parts[3]))
    if len(parts) == 3 and parts[0] == 'b' and parts[1] in ('t', 'f') \
            and parts[2] in CC_NAME_TO_HEX:
        return 'b.%s.0x%02x' % (parts[1], CC_NAME_TO_HEX[parts[2]])
    if parts[0] == 'alu' and len(parts) == 2:
        return 'alu.0x%02x' % _mnem_hex_suffix(parts[1])
    if m == 'shr' and len(raw_ops) > 1 and raw_ops[1].endswith('h'):
        return 'shrh'
    return m


def _tok(t):
    t = t.strip()
    if t.startswith('imm='):
        t = t[4:]
    if not t:
        return None
    if t in ('zero', 'zerol', 'zeroh'):
        return 0
    names = csr_names()
    if t in names:
        return names[t]
    m = _REG_RE.match(t)
    if m:
        return 'r%d' % int(m.group(1))
    m = _CSR_RE.match(t)
    if m:
        return int(m.group(1), 16)
    if t == 'retaddr':
        return 0xbc
    m = re.fullmatch(r'<BAD_register_(\d+):4>', t)
    if m:
        return (int(m.group(1)) - 0x40000) >> 2
    if t.startswith('0x-'):
        t = '-0x' + t[3:]
    if re.fullmatch(r'-?0x[0-9a-fA-F]+', t):
        return int(t, 16)
    if re.fullmatch(r'-?\d+', t):
        return int(t, 10)
    if re.fullmatch(r'-?[0-9a-fA-F]+', t):
        return int(t, 16)
    return None


def _normalize(text, canon_mnem):
    if text is None:
        return None
    head = text.split(None, 1)
    if not head:
        return None
    mnem = head[0]
    rest = head[1] if len(head) > 1 else ''
    rest = rest.replace(' imm=', ',imm=')
    raw_ops = [t.strip() for t in rest.split(',')] if rest else []
    cm = canon_mnem(mnem, raw_ops)
    ops = [_tok(t) for t in raw_ops]
    if any(o is None and t not in ('',) for o, t in zip(ops, raw_ops)):
        return None
    return (cm, ops)


def normalize_ours(text):
    return _normalize(text, lambda m, _: _canon_ours_mnem(m))


def normalize_ghidra(text):
    return _normalize(text, _canon_ghidra_mnem)


def _regnum(op):
    if isinstance(op, str) and op.startswith('r') and op[1:].isdigit():
        return int(op[1:])
    return None


def _documented(o, g):
    om, oops = o
    gm, gops = g
    if om == 'or' and gm == 'mv' and len(gops) == 2 and len(oops) == 3 \
            and gops[0] == oops[0] and gops[1] == oops[2] \
            and oops[1] == oops[2]:
        return True
    if om == 'andmsk.hi' and gm == 'or' and len(oops) == 3 \
            and len(gops) == 3 and oops == gops:
        return True
    if om.startswith('alu.0x') and gm == 'lw.r.zx' \
            and int(om[6:], 16) == 0x18 and oops == gops:
        return True
    if om == 'alu.0x85' and gm == 'shr.85' and len(oops) == 3 \
            and len(gops) == 3 and oops[:2] == gops[:2] \
            and _regnum(oops[2]) is not None and _regnum(oops[2]) == gops[2]:
        return True
    if om == 'ret.r' and gm == 'jalr' and len(gops) == 1 and len(oops) == 3 \
            and gops[0] == oops[2]:
        return True
    if om == gm == 'st.i' and len(oops) == 2 and len(gops) == 2 \
            and oops[1] == gops[1]:
        return True
    if om == 'csr.w' and gm.startswith('csr.w.') and len(gops) == 3 \
            and oops == gops:
        return True
    if om == 'csr.w' and gm.startswith('csr.w.') and len(gops) == 2 \
            and len(oops) == 3 and gops[1] == oops[2] \
            and gops[0] in oops[:2]:
        return True
    if om in ('st.q.1e', 'ld.q.17') and om == gm and len(oops) == 3 \
            and len(gops) == 3 and oops[:2] == gops[:2] \
            and oops[2] == (gops[2] & ~7):
        return True
    m = re.fullmatch(r'jump\.(?:0x)?([0-9a-fA-F]+)', gm)
    if m and oops == gops \
            and om == ('call' if int(m.group(1), 16) & 1 == 0 else 'jump'):
        return True
    if om == gm in ('and', 'xor') and len(oops) == 3 and len(gops) == 3 \
            and oops[:2] == gops[:2] and isinstance(oops[2], int) \
            and isinstance(gops[2], int) \
            and (oops[2] & 0xffff) == (gops[2] & 0xffff):
        return True
    return False


class Classifier:
    def __init__(self, data_tail_ops, census_ops):
        self.data_tail_ops = set(data_tail_ops)
        self.census_ops = set(census_ops)

    def classify(self, ours, ghidra):
        o = normalize_ours(ours)
        if o is None:
            return None
        g = normalize_ghidra(ghidra)
        if g is None:
            return None
        if o[0].startswith('op0x'):
            if g[0] != o[0]:
                return 'outside_slaspec'
            op = int(o[0][4:], 16)
            if op in self.data_tail_ops or op not in self.census_ops:
                return 'data'
            return 'outside_slaspec'
        if g[0].startswith('op0x'):
            return 'outside_slaspec'
        if o == g:
            return 'none'
        if _documented(o, g):
            return 'documented'
        return 'decoder_bug'


def parse_dump_line(line):
    m = _DUMP_LINE_RE.match(line)
    if not m:
        return None
    return (int(m.group(1), 16), m.group(2))


def parse_dump(text):
    out = {}
    for line in text.splitlines():
        parsed = parse_dump_line(line)
        if parsed:
            out[parsed[0]] = parsed[1]
    return out


def unclassified(report):
    bad = []
    for cfg in report.get('configs', []):
        for d in cfg.get('diffs', []):
            if d.get('class') not in CLASSES:
                bad.append(d)
    return bad


def class_counts(report):
    counts = {}
    for cfg in report.get('configs', []):
        for d in cfg.get('diffs', []):
            c = d.get('class')
            if c in CLASSES:
                counts[c] = counts.get(c, 0) + 1
    return counts


def report_pass(report):
    ok = not unclassified(report)
    return ok and class_counts(report).get('decoder_bug', 0) == 0


def infer_profile(image_path):
    n = str(image_path).lower()
    if 'connectx5' in n or 'cx-5' in n or 'cx5' in n:
        return 'cx5'
    if 'connectx4lx' in n or 'cx-4' in n or 'cx4lx' in n:
        return 'cx4lx'
    return None


def load_census(name):
    if not name:
        return {}
    return profiles.load_profile(name).census


def run_ghidra_config(cre, ghidra_image, slaspec, workdir, cfg):
    workdir = workdir.resolve()
    proj = workdir / ('proj-%s' % cfg)
    proj.mkdir(parents=True, exist_ok=True)
    dump = workdir / ('ghidra-%s.txt' % cfg)
    inner = '/work-build/' + workdir.name
    headless = (
        '/opt/ghidra/support/analyzeHeadless %s/proj-%s crosscheck '
        '-overwrite -import %s/code.bin '
        '-processor iRISC:BE:32:default -noanalysis '
        '-scriptPath %s -postScript CrossDump.java %s/%s' % (
            inner, cfg, inner, inner, inner, dump.name))
    cmd = [cre, 'run', '--rm',
           '-v', '%s:/work-build:z' % host_path(workdir.parent),
           '-v', '%s:%s/iRISC.slaspec' % (host_path(slaspec), GHIDRA_LANG_DIR),
           '--entrypoint', 'sh', ghidra_image, '-c',
           '%s && %s' % (SLEIGH_COMPILE, headless)]
    print('+ %s' % ' '.join(cmd), flush=True)
    r = subprocess.run(cmd)
    if r.returncode != 0:
        raise SystemExit('crosscheck: ghidra run failed (config %s, rc=%d)'
                         % (cfg, r.returncode))
    if not dump.is_file():
        raise SystemExit('crosscheck: ghidra dump missing: %s' % dump)
    return parse_dump(dump.read_text(errors='replace'))


def walk_words(code, dump, classifier):
    diffs = []
    total = len(code) // 4
    for i in range(total):
        dc = i * 4
        w = struct.unpack_from('>I', code, dc)[0]
        ours = irisc_dis.dis(w, dc)
        ghidra = dump.get(dc)
        cls = classifier.classify(ours, ghidra)
        if cls == 'none':
            continue
        diffs.append({'dc': dc, 'word': '0x%08x' % w, 'ours': ours,
                      'ghidra': ghidra, 'class': cls})
    return total, diffs


def build_config_report(cfg, code, dump, classifier):
    total, diffs = walk_words(code, dump, classifier)
    counts = {}
    for d in diffs:
        counts[d['class']] = counts.get(d['class'], 0) + 1
    print('config %-8s words_total=%d diffs=%d counts=%s'
          % (cfg, total, len(diffs), json.dumps(counts, sort_keys=True)),
          flush=True)
    return {'config': cfg, 'words_total': total, 'counts': counts,
            'diffs': diffs}


def preflight(cre, image, ghidra_image):
    if not image.is_file():
        raise SystemExit('crosscheck: firmware image not found: %s' % image)
    try:
        subprocess.run([cre, '--version'], capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        raise SystemExit('crosscheck: container tool %r not available' % cre)
    r = subprocess.run([cre, 'image', 'exists', ghidra_image],
                       capture_output=True)
    if r.returncode != 0:
        raise SystemExit('crosscheck: image %r missing: build it in '
                         '~/git/IMPLEMENTATION/ghidra-container '
                         '(make image)' % ghidra_image)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--image', required=True)
    ap.add_argument('--slaspec', choices=['repo', 'upstream', 'both'],
                    default='both')
    ap.add_argument('--out', default='build/irisc-crosscheck.json')
    ap.add_argument('--ghidra-image', default=GHIDRA_IMAGE_DEFAULT)
    ap.add_argument('--profile', choices=['cx5', 'cx4lx'])
    ap.add_argument('--section', default='0x03')
    args = ap.parse_args(argv)

    cre = resolve_cre()
    image = Path(args.image)
    preflight(cre, image, args.ghidra_image)

    profile = args.profile or infer_profile(image)
    if not profile:
        print('crosscheck: WARNING: profile not inferred for %s; census '
              'empty (all unknown ops -> data)' % image.name)
    census = load_census(profile)
    tail_ops = data_tail_ops(census)
    census_ops = {int(op, 16) for op in census}
    classifier = Classifier(tail_ops, census_ops)
    print('crosscheck: profile=%s data_tail_ops=%s' % (
        profile, sorted('%#x' % o for o in tail_ops)), flush=True)

    img = mlxfwutil.Image(image.read_bytes(), str(image))
    raw = mlxfwutil.extract_section(img, int(args.section, 0))
    code, tail = mlxfwutil.clcrc_unwrap(raw)
    print('crosscheck: section %s raw=%d code=%d tail=%d'
          % (args.section, len(raw), len(code), len(tail)), flush=True)

    workdir = ROOT / 'build' / 'irisc-crosscheck'
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / 'code.bin').write_bytes(code)
    (workdir / 'CrossDump.java').write_text(CROSS_DUMP_JAVA)

    cfgs = ['repo', 'upstream'] if args.slaspec == 'both' else [args.slaspec]
    slaspecs = {'repo': HERE / 'iRISC.slaspec',
                'upstream': UPSTREAM_SLASPEC}
    config_reports = []
    for cfg in cfgs:
        dump = run_ghidra_config(cre, args.ghidra_image, slaspecs[cfg],
                                 workdir, cfg)
        print('crosscheck: config %s dump entries=%d' % (cfg, len(dump)),
              flush=True)
        config_reports.append(
            build_config_report(cfg, code, dump, classifier))

    report = {
        'image': str(image),
        'profile': profile,
        'section': args.section,
        'code_bytes': len(code),
        'tail_bytes': len(tail),
        'data_tail_ops': sorted(tail_ops),
        'configs': config_reports,
    }
    stamp_ghidra_container_rev(report)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=1))

    counts = class_counts(report)
    bad = unclassified(report)
    print('crosscheck: report %s' % out)
    print('crosscheck: counts=%s' % json.dumps(counts, sort_keys=True))
    print('crosscheck: unclassified=%d %s' % (len(bad), bad[:5]))
    for cfg in config_reports:
        bugs = [d for d in cfg['diffs'] if d['class'] == 'decoder_bug']
        if bugs:
            print('crosscheck: ERROR config %s decoder_bug=%d, first:'
                  % (cfg['config'], len(bugs)))
            for d in bugs[:10]:
                print('  dc=%#x word=%s ours=%r ghidra=%r'
                      % (d['dc'], d['word'], d['ours'], d['ghidra']))
    return 0 if report_pass(report) else 1


if __name__ == '__main__':
    sys.exit(main())
