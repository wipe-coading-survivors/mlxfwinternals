import json
import re
from pathlib import Path

_STATUSES = ('live', 'static', 'assumed', 'unknown')
_DIR = Path(__file__).resolve().parent / 'profiles'
_OP_RE = re.compile(r'\bop0x([0-9a-fA-F]{2})\b')


class ProfileError(Exception):
    pass


class Profile:
    def __init__(self, data):
        self._data = data
        self.name = data['name']
        self.chip = data['chip']
        self.verified_on = list(data['verified_on'])
        self.load_base = dict(data['load_base'])
        self.anchors = dict(data['anchors'])
        self.census = {op: dict(entry) for op, entry in
                       data.get('unknown_ops', {}).items()}

    def form_status(self, mnemonic):
        return self._data['forms'].get(mnemonic, 'assumed')


def _validate(data, name):
    for key in ('name', 'chip', 'verified_on', 'load_base', 'anchors',
                'forms'):
        if key not in data:
            raise ProfileError('profile %r: missing key %r' % (name, key))
    for form, status in data['forms'].items():
        if status not in _STATUSES:
            raise ProfileError('profile %r: bad status %r for form %r'
                               % (name, status, form))
    return Profile(data)


def load_profile(name):
    path = _DIR / ('%s.json' % name)
    if not path.is_file():
        raise ProfileError('unknown profile %r (expected %s)' % (name, path))
    return _validate(json.loads(path.read_text()), name)


def annotate(text, profile):
    if profile is None:
        return text

    def ann_line(line):
        m = _OP_RE.search(line)
        if not m:
            return line
        entry = profile.census.get('0x' + m.group(1).lower())
        if not entry or not entry.get('note'):
            return line
        return '%s ; [%s] %s' % (line, profile.name, entry['note'])

    return '\n'.join(ann_line(line) for line in text.split('\n'))
