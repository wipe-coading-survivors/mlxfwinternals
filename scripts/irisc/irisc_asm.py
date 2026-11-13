import argparse
import re
import struct
import sys
from pathlib import Path

try:
    from .irisc_dis import dis
    from .profiles import Profile, load_profile
except ImportError:
    from irisc_dis import dis
    from profiles import Profile, load_profile


class AsmError(Exception):
    pass


def _chk(cond, msg):
    if not cond:
        raise AsmError(msg)


def _rng(v, lo, hi, what):
    _chk(lo <= v <= hi, '%s out of range [%d..%d]: %r' % (what, lo, hi, v))
    return v


_REG_RE = re.compile(r'r([0-9]+)$')
_NUM_RE = re.compile(r'[+-]?(0[xX][0-9a-fA-F]+|[0-9]+)|0[xX]-[0-9a-fA-F]+')


def _is_reg(tok):
    return tok == 'zero' or _REG_RE.fullmatch(tok) is not None


def _is_num(tok):
    return _NUM_RE.fullmatch(tok) is not None


def _reg(tok):
    if tok == 'zero':
        return 0
    m = _REG_RE.fullmatch(tok)
    if not m:
        raise AsmError('bad register %r' % tok)
    return _rng(int(m.group(1)), 0, 31, 'register')


def _num(tok):
    if not _is_num(tok):
        raise AsmError('bad number %r' % tok)
    if tok[:2].lower() == '0x' and tok[2] == '-':
        tok = '-0x' + tok[3:]
    return int(tok, 0)


def _regname(v):
    return 'zero' if v == 0 else 'r%d' % v


def _chk_align(off, mult, what):
    _chk(off % mult == 0, '%s 0x%x not %d-byte aligned' % (what, off, mult))
    return off


def _imm_enc(op):
    def enc(f, pos):
        return (op << 26) | (f['rs'] << 21) | (f['rd'] << 16) | (f['imm'] & 0xffff)
    return enc


def _alu_enc(funct):
    def enc(f, pos):
        return (0x3f << 26) | (f['rs'] << 21) | (f['rd'] << 16) | (f['rt'] << 11) | funct
    return enc


def _alu_sh_enc(funct):
    def enc(f, pos):
        return (0x3f << 26) | (f['rs'] << 21) | (f['rd'] << 16) | (f['shamt'] << 11) | funct
    return enc


def _ldi_enc(f, pos):
    return (0x12 << 26) | (1 << 25) | (f['rd'] << 16) | (f['imm'] & 0xffff)


def _csrr_enc(f, pos):
    return (0x12 << 26) | (f['rd'] << 16) | (f['csr'] & 0x7ff)


def _sti_enc(f, pos):
    return (0x13 << 26) | (f['rs'] << 21) | (0x1b << 16) | (f['imm'] & 0x7ff)


def _csrw_enc(f, pos):
    return (0x13 << 26) | (f['rs'] << 21) | (f['rt'] << 11) | (f['imm'] & 0x7ff)


def _ld17_enc(twobits):
    def enc(f, pos):
        _chk_align(f['off'], 4, 'ld.d.17 offset')
        return ((0x17 << 26) | (f['rs'] << 21) | (f['rd'] << 16)
                | (((f['off'] >> 2) & 0x3fff) << 2) | twobits)
    return enc


def _load_enc(op, kind):
    def enc(f, pos):
        off = f['off']
        if kind == 'b':
            lo = off & 0xffff
        elif kind == 'w':
            _chk_align(off, 2, 'ld.w offset')
            lo = (((off >> 1) & 0x7fff) << 1) | 1
        else:
            _chk_align(off, 4, 'ld.%s offset' % kind)
            lo = (((off >> 2) & 0x3fff) << 2) | (2 if kind == 'd' else 0)
        return (op << 26) | (f['rs'] << 21) | (f['rd'] << 16) | lo
    return enc


def _store_enc(op, kind):
    def enc(f, pos):
        off = f['off']
        hi = (off >> 11) & 0x1f
        if kind == 'b':
            lo = off & 0x7ff
        elif kind == 'w':
            _chk_align(off, 2, 'st.w offset')
            lo = (((off >> 1) & 0x3ff) << 1) | 1
        else:
            _chk_align(off, 4, 'st.%s offset' % kind)
            lo = (((off >> 2) & 0x1ff) << 2) | (2 if kind == 'd' else 0)
        return (op << 26) | (f['rs'] << 21) | (hi << 16) | (f['rt'] << 11) | lo
    return enc


def _rel32(tgt, pos):
    rel = (tgt - pos) & 0xffffffff
    if rel >= 0x80000000:
        rel -= 0x100000000
    return rel


def _jmp_enc(is_jump):
    def enc(f, pos):
        rel = _rel32(f['tgt'], pos)
        _chk(rel % 4 == 0, 'unaligned jump/call target 0x%x from 0x%x' % (f['tgt'], pos))
        _rng(rel // 4, -0x800000, 0x7fffff, 'rel24')
        return (0x25 << 26) | ((1 << 24) if is_jump else 0) | ((rel // 4) & 0xffffff)
    return enc


def _br_enc(op):
    def enc(f, pos):
        rel = _rel32(f['tgt'], pos)
        _chk(rel % 4 == 0, 'unaligned branch target 0x%x from 0x%x' % (f['tgt'], pos))
        _rng(rel // 4, -0x8000, 0x7fff, 'rel16')
        return (op << 26) | (f['rs'] << 21) | ((f['cc'] & 0x1f) << 16) | ((rel // 4) & 0xffff)
    return enc


def _bbit_enc(op):
    def enc(f, pos):
        rel = _rel32(f['tgt'], pos)
        _chk(rel % 4 == 0, 'unaligned branch target 0x%x from 0x%x' % (f['tgt'], pos))
        _rng(rel // 4, -0x8000, 0x7fff, 'rel16')
        return (op << 26) | (f['rs'] << 21) | ((f['sh'] & 0x1f) << 16) | ((rel // 4) & 0xffff)
    return enc


def _mask32_enc(f, pos):
    return (0x32 << 26) | (f['rs'] << 21) | (f['rd'] << 16) | ((f['m'] & 0x3f) << 5) | (f['n'] & 0x1f)


def _alu_gen_enc(f, pos):
    return (0x3f << 26) | (f['rs'] << 21) | (f['rd'] << 16) | (f['rt'] << 11) | (f['funct'] & 0x1ff)


def _raw_op_enc(f, pos):
    return ((f['op'] << 26) | (f['rs'] << 21) | (f['rd'] << 16)
            | (f['rt'] << 11) | (f['imm'] & 0xffff))


def _raw_funct_enc(f, pos):
    return ((f['op'] << 26) | (f['rs'] << 21) | (f['rd'] << 16)
            | (f['rt'] << 11) | (f['funct'] & 0x7ff))


def _raw_dword_enc(f, pos):
    return _rng(f['value'], 0, 0xffffffff, 'dword')


def _raw_unki_enc(f, pos):
    return (f['op'] << 26) | (f['rs'] << 21) | (f['rd'] << 16) | (f['imm'] & 0xffff)


def _align8(f):
    f['off'] &= ~7
    return f


_S16 = (-0x8000, 0xffff)
_U16 = (0, 0xffff)
_S16FULL = (-0x8000, 0x7fff)
_OFF14 = (-0x8000, 0x7ffc)
_OFF15 = (-0x8000, 0x7ffe)

_FORMS = {}


def _form(name, params, status='static', enc=None, fix=None):
    _FORMS[name] = {'params': params, 'status': status, 'enc': enc,
                    'fix': fix}


for _m, _op, _sgn in [('addi', 0x00, 1), ('addi.hi', 0x02, 1), ('subi', 0x04, 1),
                      ('subsi', 0x05, 1), ('set0', 0x06, 0), ('set1', 0x07, 0),
                       ('set2', 0x09, 0), ('set3', 0x08, 0), ('and', 0x0a, 1),
                      ('ands', 0x0b, 1), ('andmsk.hi', 0x0c, 0), ('xor', 0x0e, 1),
                      ('and.hi', 0x0d, 0)]:
    _form(_m, [('rd', 'reg'), ('rs', 'reg'),
               ('imm', 'snum' if _sgn else 'num', _S16 if _sgn else _U16)],
          'live' if _m in ('addi', 'set0', 'set1', 'set2', 'set3') else 'static',
          _imm_enc(_op))

for _f, _m in {0: 'add', 1: 'adds', 4: 'sub', 5: 'subs', 0x19: 'lw.r',
               0x25: 'ret.r', 0x2d: 'ret.d', 0x80: 'shl64.r'}.items():
    _form(_m, [('rd', 'reg'), ('rs', 'reg'), ('rt', 'reg')],
          'live' if _m == 'ret.r' else 'static', _alu_enc(_f))
for _m, _f in [('or', 8), ('and', 0xa), ('ands', 0xb), ('xor', 0xe)]:
    _form(_m + '#alu', [('rd', 'reg'), ('rs', 'reg'), ('rt', 'reg')],
          'live' if _m == 'or' else 'static', _alu_enc(_f))
for _f, _m in [(0x81, 'shl64.i'), (0x83, 'shr'), (0x8b, 'shrh')]:
    _form(_m, [('rd', 'reg'), ('rs', 'reg'), ('shamt', 'num', (0, 0x1f))],
          'live' if _m == 'shl64.i' else 'static', _alu_sh_enc(_f))
_form('alu', [('funct', 'num', (0, 0x1ff)), ('rd', 'reg'), ('rs', 'reg'),
              ('rt', 'reg')], 'static', _alu_gen_enc)

_form('ld.i', [('rd', 'reg'), ('imm', 'num', _U16)], 'static', _ldi_enc)
_form('csr.r', [('rd', 'reg'), ('csr', 'csr')], 'static', _csrr_enc)
_form('st.i', [('rs', 'reg'), ('imm', 'num', (0, 0x7ff))], 'static', _sti_enc)
_form('csr.w', [('rs', 'reg'), ('rt', 'reg'), ('imm', 'num', (0, 0x7ff))],
      'live', _csrw_enc)
_form('ld.d.17', [('rd', 'reg'), ('rs', 'reg'), ('off', 'num', _OFF14)],
      'static', _ld17_enc(2))
_form('ld.q.17', [('rd', 'reg'), ('rs', 'reg'), ('off', 'num', _OFF14)],
      'static', _ld17_enc(0), fix=_align8)
_form('ld.b', [('rd', 'reg'), ('rs', 'reg'), ('off', 'num', _S16FULL)],
      'static', _load_enc(0x18, 'b'))
_form('ld.w', [('rd', 'reg'), ('rs', 'reg'), ('off', 'num', _OFF15)],
      'live', _load_enc(0x19, 'w'))
_form('ld.d', [('rd', 'reg'), ('rs', 'reg'), ('off', 'num', _OFF14)],
      'live', _load_enc(0x19, 'd'))
_form('ld.q', [('rd', 'reg'), ('rs', 'reg'), ('off', 'num', _OFF14)],
      'assumed', _load_enc(0x19, 'q'))
_form('st.b', [('rt', 'reg'), ('rs', 'reg'), ('off', 'num', _S16FULL)],
      'static', _store_enc(0x1a, 'b'))
_form('st.w', [('rt', 'reg'), ('rs', 'reg'), ('off', 'num', _OFF15)],
      'live', _store_enc(0x1b, 'w'))
_form('st.d', [('rt', 'reg'), ('rs', 'reg'), ('off', 'num', _OFF14)],
      'live', _store_enc(0x1b, 'd'))
_form('st.q', [('rt', 'reg'), ('rs', 'reg'), ('off', 'num', _OFF14)],
      'static', _store_enc(0x1b, 'q'))
_form('st.w!', [('rt', 'reg'), ('rs', 'reg'), ('off', 'num', _OFF15)],
      'static', _store_enc(0x1c, 'w'))
_form('st.d!', [('rt', 'reg'), ('rs', 'reg'), ('off', 'num', _OFF14)],
      'live', _store_enc(0x1c, 'd'))
_form('st.q!', [('rt', 'reg'), ('rs', 'reg'), ('off', 'num', _OFF14)],
      'static', _store_enc(0x1c, 'q'))
_form('st.d.1e', [('rt', 'reg'), ('rs', 'reg'), ('off', 'num', _OFF14)],
      'static', _store_enc(0x1e, 'd'))
_form('st.q.1e', [('rt', 'reg'), ('rs', 'reg'), ('off', 'num', _OFF14)],
      'static', _store_enc(0x1e, 'q'), fix=_align8)
_form('jump', [('tgt', 'target')], 'live', _jmp_enc(True))
_form('call', [('tgt', 'target')], 'live', _jmp_enc(False))
_form('b.t', [('cc', 'num', (0, 0x1f)), ('rs', 'reg'), ('tgt', 'target')],
      'live', _br_enc(0x28))
_form('b.f', [('cc', 'num', (0, 0x1f)), ('rs', 'reg'), ('tgt', 'target')],
      'live', _br_enc(0x29))
_form('b.bset', [('sh', 'num', (0, 31)), ('rs', 'reg'), ('tgt', 'target')],
      'static', _bbit_enc(0x2a))
_form('b.bclr', [('sh', 'num', (0, 31)), ('rs', 'reg'), ('tgt', 'target')],
      'static', _bbit_enc(0x2b))
_form('mask32', [('rd', 'reg'), ('rs', 'reg'), ('m', 'num', (0, 0x3f)),
                  ('n', 'num', (0, 31))], 'static', _mask32_enc)
_form('op0xNN', [('op', 'num', (0, 0x3f)), ('rd', 'reg'), ('rs', 'reg'),
                 ('rt', 'reg'), ('imm', 'num', _U16)], 'raw', _raw_op_enc)


def _split_args(rest):
    if not rest:
        return []
    if isinstance(rest, list):
        args = [a.strip() for a in rest]
    else:
        args = [a.strip() for a in rest.split(',')]
    if any(not a for a in args):
        raise AsmError('empty argument in %r' % rest)
    return args


def _param_value(name, kind, rng, tok, labels):
    if kind == 'reg':
        return _reg(tok)
    if kind == 'csr':
        _chk(tok.startswith('csr0x'), 'bad csr token %r' % tok)
        return _rng(int(tok[5:], 16), 0, 0x7ff, name)
    if kind == 'target':
        if _is_num(tok):
            return _num(tok)
        _chk(labels is not None and tok in labels, 'unknown label %r' % tok)
        return labels[tok]
    v = _num(tok)
    if rng is not None:
        _rng(v, rng[0], rng[1], name)
    if kind == 'snum' and v > 0x7fff:
        v -= 0x10000
    return v


def _bind(name, args, labels, extra=None):
    spec = _FORMS[name]
    params = spec['params']
    fields = dict(extra) if extra else {}
    use = [p for p in params if p[0] not in fields] if extra else params
    if len(args) != len(use):
        raise AsmError('%s expects %d args, got %d' % (name, len(use), len(args)))
    for param, tok in zip(use, args):
        pname, kind = param[0], param[1]
        rng = param[2] if len(param) > 2 else None
        fields[pname] = _param_value(pname, kind, rng, tok, labels)
    if spec['fix']:
        spec['fix'](fields)
    return fields


def _canon_req(name, rest, labels, extra=None):
    return ('canon', name, _bind(name, _split_args(rest), labels, extra))


def _raw_req(name, rest, labels, extra=None):
    return ('raw', name, _bind(name, _split_args(rest), labels, extra))


def _expand_set32(fields):
    rd = fields['rd']
    v = _rng(fields['imm'], 0, 0xffffffff, 'set32 imm')
    return [('canon', 'set2', {'rd': rd, 'rs': 0, 'imm': (v >> 16) & 0xffff}),
            ('canon', 'set3', {'rd': rd, 'rs': rd, 'imm': v & 0xffff})]


def _expand_set64(fields):
    rd = fields['rd']
    v = _rng(fields['imm'], 0, 0xffffffffffffffff, 'set64 imm')
    return [('canon', 'set0', {'rd': rd, 'rs': 0, 'imm': (v >> 48) & 0xffff}),
            ('canon', 'set1', {'rd': rd, 'rs': rd, 'imm': (v >> 32) & 0xffff}),
            ('canon', 'set2', {'rd': rd, 'rs': rd, 'imm': (v >> 16) & 0xffff}),
            ('canon', 'set3', {'rd': rd, 'rs': rd, 'imm': v & 0xffff})]


def _cmp_eq32(op):
    def expand(fields):
        return [('raw', 'op0xNN', {'op': op, 'rd': 0, 'rs': fields['rs'],
                                   'rt': fields['rt'], 'imm': 2})]
    return expand


def _alu_r(fields):
    return [('raw', 'unk.r', {'op': 0x3f, 'rd': fields['rd'], 'rs': fields['rs'],
                              'rt': fields['rt'], 'funct': fields['funct']})]


def _vendor_mem(op, twobits):
    def expand(fields):
        return [('raw', 'unk.r',
                 {'op': op, 'rd': fields['rd'], 'rs': fields['rs'],
                  'rt': fields['rt'], 'funct': (fields['off11'] | twobits) & 0x7ff})]
    return expand


_form('set32', [('rd', 'reg'), ('imm', 'num', None)], 'assumed')
_form('set64', [('rd', 'reg'), ('imm', 'num', None)], 'assumed')
_form('cmp36_eq32', [('rs', 'reg'), ('rt', 'reg')], 'assumed')
_form('cmp38_eq32', [('rs', 'reg'), ('rt', 'reg')], 'live')
_form('unk.r', [('op', 'num', (0, 0x3f)), ('rd', 'reg'), ('rs', 'reg'),
                ('rt', 'reg'), ('funct', 'num', (0, 0x7ff))], 'raw', _raw_funct_enc)
_form('alu.r', [('funct', 'num', (0, 0x7ff)), ('rd', 'reg'), ('rs', 'reg'),
                ('rt', 'reg')], 'assumed')
_form('unk.i', [('op', 'num', (0, 0x3f)), ('rd', 'reg'), ('rs', 'reg'),
                ('imm', 'num', _U16)], 'raw', _raw_unki_enc)
_form('dword', [('value', 'num', None)], 'raw', _raw_dword_enc)
_form('alur.0xb', [('rd', 'reg'), ('rs', 'reg'), ('rt', 'reg')], 'assumed')
_form('b.set', [('rs', 'reg'), ('bitsel', 'num', (0, 31)), ('tgt', 'target')],
      'assumed')
_form('b.clr', [('rs', 'reg'), ('bitsel', 'num', (0, 31)), ('tgt', 'target')],
      'assumed')
for _name in ('set32', 'set64'):
    _FORMS[_name]['expand'] = _expand_set32 if _name == 'set32' else _expand_set64
_FORMS['cmp36_eq32']['expand'] = _cmp_eq32(0x36)
_FORMS['cmp38_eq32']['expand'] = _cmp_eq32(0x38)
_FORMS['unk.r']['expand'] = lambda f: [('raw', 'unk.r', f)]
_FORMS['unk.i']['expand'] = lambda f: [('raw', 'unk.i', f)]
_FORMS['dword']['expand'] = lambda f: [('raw', 'dword', f)]
_FORMS['alu.r']['expand'] = _alu_r
_FORMS['alur.0xb']['expand'] = (
    lambda f: [('canon', 'ands#alu', {'rd': f['rd'], 'rs': f['rs'],
                                      'rt': f['rt']})])
_FORMS['b.set']['expand'] = (
    lambda f: [('canon', 'b.bset', {'sh': f['bitsel'], 'rs': f['rs'],
                                    'tgt': f['tgt']})])
_FORMS['b.clr']['expand'] = (
    lambda f: [('canon', 'b.bclr', {'sh': f['bitsel'], 'rs': f['rs'],
                                    'tgt': f['tgt']})])

_ALU_ALIAS = ('or', 'and', 'ands', 'xor')
_MEM_ALIAS = {'ld.d': (4, 0x19), 'st.d': (4, 0x1b), 'st.q': (5, 0x1e)}
_B_BARE = ('b.t', 'b.f', 'b.set', 'b.clr')


def _gate_name(mnem):
    if mnem in _FORMS and _FORMS[mnem]['status'] == 'raw':
        return None
    m = re.fullmatch(r'op0x[0-9a-fA-F]{2}', mnem)
    if m:
        return None
    m = re.fullmatch(r'b\.(t|f)\.0x[0-9a-fA-F]+', mnem)
    if m:
        return 'b.t' if m.group(1) == 't' else 'b.f'
    if re.fullmatch(r'alu\.0x[0-9a-fA-F]{1,3}', mnem):
        return 'alu'
    return mnem.split('#', 1)[0] if '#' in mnem else mnem


def _make_gate(profile, allow_assumed):
    def gate(mnem):
        name = _gate_name(mnem)
        if name is None:
            return
        status = profile.form_status(name)
        if status in ('assumed', 'unknown') and not allow_assumed:
            raise AsmError('form %r is %s on %s (strict gate; '
                           'allow_assumed=True to override)'
                           % (name, status, profile.name))
    return gate


def _parse_line(line, pos, labels, gate=None):
    parts = line.split(None, 1)
    mnem = parts[0]
    rest = parts[1].strip() if len(parts) > 1 else ''
    if mnem == 'lbl':
        return []
    if gate is not None:
        gate(mnem)
    m = re.fullmatch(r'b\.(t|f)\.0x([0-9a-fA-F]+)', mnem)
    if m:
        return [_canon_req('b.t' if m.group(1) == 't' else 'b.f', rest, labels,
                           extra={'cc': _rng(int(m.group(2), 16), 0, 0x1f, 'cc')})]
    m = re.fullmatch(r'alu\.0x([0-9a-fA-F]{1,3})', mnem)
    if m:
        return [_canon_req('alu', rest, labels,
                           extra={'funct': _rng(int(m.group(1), 16), 0, 0x1ff, 'funct')})]
    m = re.fullmatch(r'op0x([0-9a-fA-F]{2})', mnem)
    if m:
        args = [t[4:] if t.startswith('imm=') else t
                for t in _split_args(rest.replace(' imm=', ',imm='))]
        return [_raw_req('op0xNN', args, labels,
                         extra={'op': _rng(int(m.group(1), 16), 0, 0x3f, 'op')})]
    if mnem in _ALU_ALIAS:
        args = _split_args(rest)
        if len(args) == 3 and _is_reg(args[2]):
            return [_canon_req(mnem + '#alu', rest, labels)]
    if mnem in _MEM_ALIAS:
        arity, op = _MEM_ALIAS[mnem]
        args = _split_args(rest)
        if len(args) == arity:
            twobits = 2
            off11tok = args[3]
            if mnem == 'st.q':
                twobits = _rng(_num(args[4]), 0, 3, 'twobits')
                off11tok = args[3]
            fields = {'op': op, 'rd': _reg(args[0]), 'rs': _reg(args[1]),
                      'rt': _reg(args[2]),
                      'funct': (_rng(_num(off11tok), 0, 0x7ff, 'off11') | twobits) & 0x7ff}
            return [('raw', 'unk.r', fields)]
    if mnem in _B_BARE:
        args = _split_args(rest)
        _chk(len(args) == 3, '%s expects 3 args, got %d' % (mnem, len(args)))
        if mnem in ('b.t', 'b.f'):
            fields = _bind(mnem, [args[1], args[2]], labels,
                           extra={'cc': _rng(_num(args[0]), 0, 0x1f, 'cc')})
            return [('canon', mnem, fields)]
        base = 'b.bset' if mnem == 'b.set' else 'b.bclr'
        fields = _bind(base, [args[0], args[2]], labels,
                       extra={'sh': _rng(_num(args[1]), 0, 31, 'sh')})
        return [('canon', base, fields)]
    if mnem in _FORMS:
        spec = _FORMS[mnem]
        if 'expand' in spec:
            return spec['expand'](_bind(mnem, _split_args(rest), labels))
        return [_canon_req(mnem, rest, labels)]
    raise AsmError('unknown mnemonic %r' % mnem)


def _encode_request(req, pos):
    return _FORMS[req[1]]['enc'](req[2], pos)


def _verify_word(req, w, pos):
    kind, name, fields = req
    if name == 'dword':
        return
    text = dis(w, pos)
    try:
        reqs = _parse_line(text, pos, None)
    except AsmError as e:
        raise AsmError('decode-verify: cannot reparse %r: %s' % (text, e))
    _chk(len(reqs) == 1, 'decode-verify: %r is not a single word' % text)
    if kind == 'raw':
        w2 = _encode_request(reqs[0], pos)
        _chk(w2 == w, 'decode-verify: word 0x%08x renders as %r and does not '
                      'reassemble bit-exact (non-representable form)' % (w, text))
        return
    _chk(reqs[0][0] == 'canon' and reqs[0][1] == name and reqs[0][2] == fields,
         'decode-verify mismatch: requested %s %r, decoded %r'
         % (name, fields, text))


def _word_count(mnem):
    if mnem == 'set32':
        return 2
    if mnem == 'set64':
        return 4
    return 1


def assemble(text, base=0, profile=None, strict=True, allow_assumed=False):
    gate = None
    if profile is not None and strict:
        prof = load_profile(profile) if isinstance(profile, str) else profile
        if not isinstance(prof, Profile):
            raise AsmError('profile must be a name or Profile, got %r' % prof)
        gate = _make_gate(prof, allow_assumed)
    lines = text.split('\n')
    labels = {}
    pos = base
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(None, 1)
        if parts[0] == 'lbl':
            name = parts[1].strip() if len(parts) > 1 else ''
            _chk(bool(name) and not _is_num(name), 'bad label %r' % line)
            if name in labels:
                _chk(labels[name] == pos, 'label %r redefined at 0x%x' % (name, pos))
            else:
                labels[name] = pos
        else:
            pos += 4 * _word_count(parts[0])
    out = []
    pos = base
    for lineno, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            reqs = _parse_line(line, pos, labels, gate=gate)
        except AsmError as e:
            raise AsmError('line %d: %s' % (lineno, e))
        for req in reqs:
            try:
                w = _encode_request(req, pos)
                _verify_word(req, w, pos)
            except AsmError as e:
                raise AsmError('line %d: %s' % (lineno, e))
            out.append(struct.pack('>L', w))
            pos += 4
    return b''.join(out)


def _format_args(name, fields, skip=()):
    toks = []
    for param in _FORMS[name]['params']:
        pname = param[0]
        if pname in skip:
            continue
        if pname not in fields:
            raise AsmError('encode_form %s: missing field %r' % (name, pname))
        v = fields[pname]
        if param[1] == 'reg':
            toks.append(_regname(v))
        elif param[1] == 'csr':
            toks.append('csr0x%x' % v)
        elif v < 0:
            toks.append('-0x%x' % -v)
        else:
            toks.append('0x%x' % v)
    return toks


def encode_form(mnemonic, pos=0, **fields):
    m = re.fullmatch(r'op0x([0-9a-fA-F]{2})', mnemonic)
    if m:
        req = _raw_req('op0xNN', ','.join(_format_args('op0xNN', fields,
                                                       skip=('op',))),
                       None, extra={'op': _rng(int(m.group(1), 16), 0, 0x3f, 'op')})
        return _encode_request(req, pos)
    m = re.fullmatch(r'alu\.0x([0-9a-fA-F]{1,3})', mnemonic)
    if m:
        funct = _rng(int(m.group(1), 16), 0, 0x1ff, 'funct')
        req = _canon_req('alu', ','.join(_format_args('alu', fields,
                                                      skip=('funct',))),
                         None, extra={'funct': funct})
        return _encode_request(req, pos)
    m = re.fullmatch(r'b\.(t|f)\.0x([0-9a-fA-F]+)', mnemonic)
    if m:
        base = 'b.t' if m.group(1) == 't' else 'b.f'
        cc = _rng(int(m.group(2), 16), 0, 0x1f, 'cc')
        req = _canon_req(base, ','.join(_format_args(base, fields, skip=('cc',))),
                         None, extra={'cc': cc})
        return _encode_request(req, pos)
    if mnemonic not in _FORMS:
        raise AsmError('unknown form %r' % mnemonic)
    if 'expand' in _FORMS[mnemonic]:
        fields2 = _bind(mnemonic, _format_args(mnemonic, fields), None)
        reqs = _FORMS[mnemonic]['expand'](fields2)
        if len(reqs) != 1:
            raise AsmError('form %r is not single-word' % mnemonic)
        return _encode_request(reqs[0], pos)
    return _encode_request(('canon', mnemonic, _bind(
        mnemonic, _format_args(mnemonic, fields), None)), pos)


FORMS = {name: {'fields': [p[0] for p in spec['params']],
                'status': spec['status']}
         for name, spec in _FORMS.items() if '#' not in name}


def _render_template(path, variables):
    text = Path(path).read_text()
    if '{{' not in text and '{%' not in text:
        return text
    try:
        import jinja2
    except ImportError as e:
        raise AsmError('jinja2 is required for template source %s: %s' % (path, e))
    loader = jinja2.FileSystemLoader(['.', str(Path(path).resolve().parent)])
    env = jinja2.Environment(loader=loader)
    return env.get_template(Path(path).name).render(**variables)


def assemble_templated(path, args, base=0, **kw):
    return assemble(_render_template(path, args), base=base, **kw)


def _hexint(v):
    return int(v, 16)


_SUBCOMMANDS = ('roundtrip', 'disasm', 'profile')


def parse_args(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in _SUBCOMMANDS:
        p = argparse.ArgumentParser(prog='irisc_asm')
        sub = p.add_subparsers(dest='cmd', required=True)
        for name in ('roundtrip', 'disasm'):
            s = sub.add_parser(name)
            s.add_argument('source', type=Path)
            s.add_argument('--base', type=_hexint, default=0)
        sub.add_parser('profile')
        return p.parse_args(argv)
    p = argparse.ArgumentParser()
    p.add_argument("--int-arg", nargs=2, default=[], metavar=("key", "val"),
                   action='append')
    p.add_argument("--str-arg", nargs=2, default=[], metavar=("key", "val"),
                   action='append')
    p.add_argument("--base", type=_hexint, default=0x00000000)
    p.add_argument("source", type=Path)
    p.add_argument("output", type=Path)
    return p.parse_args(argv)


def _iter_words(data, base):
    for off in range(0, len(data) - 3, 4):
        yield base + off, struct.unpack_from('>I', data, off)[0]


def _cmd_disasm(args):
    for addr, w in _iter_words(args.source.read_bytes(), args.base):
        print('%08x  %s' % (addr, dis(w, addr)))
    return 0


def _cmd_roundtrip(args):
    bad = 0
    for addr, w in _iter_words(args.source.read_bytes(), args.base):
        text = dis(w, addr)
        try:
            w1 = struct.unpack('>I', assemble(text, base=addr))[0]
            w2 = struct.unpack('>I', assemble(dis(w1, addr), base=addr))[0]
        except AsmError as e:
            print('%08x  ERROR    %s (%s)' % (addr, text, e))
            bad += 1
            continue
        if w1 == w:
            mark = 'exact'
        elif w1 == w2:
            mark = 'fixpoint'
        else:
            mark = 'DRIFT'
            bad += 1
        print('%08x  %-8s %s' % (addr, mark, text))
    return 1 if bad else 0


def _cmd_profile(args):
    for name in sorted(FORMS):
        print('%-10s %-8s %s' % (name, FORMS[name]['status'],
                                 ','.join(FORMS[name]['fields'])))
    return 0


def main(argv=None):
    args = parse_args(argv)
    cmd = getattr(args, 'cmd', None)
    if cmd == 'disasm':
        return _cmd_disasm(args)
    if cmd == 'roundtrip':
        return _cmd_roundtrip(args)
    if cmd == 'profile':
        return _cmd_profile(args)
    variables = dict(args.str_arg + [(k, int(v)) for k, v in args.int_arg])
    args.output.write_bytes(assemble_templated(str(args.source), variables,
                                               base=args.base))
    return 0


if __name__ == '__main__':
    sys.exit(main())
