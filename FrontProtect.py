#!/usr/bin/env python3
from __future__ import annotations

__version__ = '1.2.0'
__all__ = [
    'Options', 'protect', 'protect_file', 'deobfuscate',
    'gui', 'cli', 'main',
    'position_encode', 'position_decode',
    'matryoshka_pack', 'unpack_matryoshka',
    'ast_mangle', 'ast_partition_numbers', 'ast_xor_strings',
    'ast_dynamic_imports', 'apply_ast',
    'anti_debug_wrap', 'anti_decompile_wrap', 'integrity_wrap',
    'bytecode_wrap', 'aes_gcm_wrap', 'aes_gcm_strip',
]

import ast
import base64
import builtins
import gzip
import hashlib
import json
import lzma
import marshal
import os
import random
import re
import string
import sys
import zlib
from collections import defaultdict
from dataclasses import dataclass, replace

_BUILTINS = frozenset(dir(builtins))
_PBKDF2_ITERS = 600_000
_POS_MAGIC = b'FP2\x00'
_POS_MAGIC_Z = b'FP3\x00'

_GZIP_LEVEL = 9
_ZLIB_LEVEL = 9
_LZMA_PRESET = 9 | lzma.PRESET_EXTREME


@dataclass
class Options:
    mangle: bool = False
    numbers: bool = False
    xor_strings: bool = False
    dynamic_imports: bool = False
    position: bool = True
    anti_debug: bool = False
    anti_decompile: bool = False
    integrity: bool = False
    bytecode: bool = False
    password: str | None = None
    template: str | None = None
    seed: int | str | None = None


def _rnd(k=8):
    return '_' + ''.join(random.choices(string.ascii_lowercase, k=k))


def _ve(n):
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _vd(buf, pos):
    n = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        n |= (b & 0x7F) << shift
        if not b & 0x80:
            return n, pos
        shift += 7


def _build_varint(src):
    cm = defaultdict(list)
    off = 0
    lines = src.split('\n')
    for i, line in enumerate(lines):
        for ch in line:
            cm[ch].append(off)
            off += 1
        if i < len(lines) - 1:
            cm['\n'].append(off)
            off += 1

    buf = bytearray(_POS_MAGIC)
    buf.extend(_ve(off))
    buf.extend(_ve(len(cm)))
    for ch in sorted(cm, key=ord):
        buf.extend(_ve(ord(ch)))
        ps = sorted(cm[ch])
        buf.extend(_ve(len(ps)))
        prev = 0
        for p in ps:
            buf.extend(_ve(p - prev))
            prev = p
    return bytes(buf)


def position_encode(src):
    varint = _build_varint(src)
    compressed = _POS_MAGIC_Z + lzma.compress(varint, preset=_LZMA_PRESET)
    return base64.b85encode(compressed).decode('ascii')


def _decode_bin_pos(raw):
    pos = 4
    total, pos = _vd(raw, pos)
    n_chars, pos = _vd(raw, pos)
    out = ['\x00'] * total
    for _ in range(n_chars):
        cp, pos = _vd(raw, pos)
        n, pos = _vd(raw, pos)
        prev = 0
        for _ in range(n):
            d, pos = _vd(raw, pos)
            prev += d
            out[prev] = chr(cp)
    if '\x00' in out:
        raise ValueError('corrupted binary position map')
    return ''.join(out)


def position_decode(payload):
    try:
        raw = base64.b85decode(payload.encode('ascii'))
        if raw[:4] == _POS_MAGIC_Z:
            return _decode_bin_pos(lzma.decompress(raw[4:]))
        if raw[:4] == _POS_MAGIC:
            return _decode_bin_pos(raw)
    except Exception:
        pass
    try:
        raw = base64.b64decode(payload.encode('ascii'))
        if raw[:4] == _POS_MAGIC_Z:
            return _decode_bin_pos(lzma.decompress(raw[4:]))
        if raw[:4] == _POS_MAGIC:
            return _decode_bin_pos(raw)
    except Exception:
        pass
    raw = base64.b64decode(payload.encode('ascii')).decode()
    data = json.loads(raw)
    grid = [['\x00'] * n for n in data['line_lengths']]
    for ch, ps in data['char_map'].items():
        for i, j in ps:
            grid[i][j] = ch
    if any('\x00' in r for r in grid):
        raise ValueError('corrupted position map')
    return '\n'.join(''.join(r) for r in grid)


def _make_stub(payload):
    A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P = (_rnd(6) for _ in range(16))
    return (
        f'import base64 as {A}, lzma as {B}\n'
        f'def {C}():\n'
        f'    {D} = {B}.decompress({A}.b85decode({payload!r})[4:])\n'
        f'    {E} = [4]\n'
        f'    def {F}():\n'
        f'        {G} = 0\n'
        f'        {H} = 0\n'
        f'        while True:\n'
        f'            {I} = {D}[{E}[0]]\n'
        f'            {E}[0] += 1\n'
        f'            {G} |= ({I} & 0x7F) << {H}\n'
        f'            if not {I} & 0x80:\n'
        f'                return {G}\n'
        f'            {H} += 7\n'
        f'    {J} = {F}()\n'
        f'    {K} = {F}()\n'
        f'    {L} = ["\\x00"] * {J}\n'
        f'    for {M} in range({K}):\n'
        f'        {N} = chr({F}())\n'
        f'        {O} = {F}()\n'
        f'        {P} = 0\n'
        f'        for _ in range({O}):\n'
        f'            {P} += {F}()\n'
        f'            {L}[{P}] = {N}\n'
        f'    return "".join({L})\n'
        f'exec({C}(), globals())\n'
    )


def _extract_pos_payload(stub_src):
    tree = ast.parse(stub_src)
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == 'b85decode'
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            return node.args[0].value
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            v = node.value
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                return v.value
    raise ValueError('no payload found in stub')


def _chunk(s, lo=60, hi=200):
    out = []
    i = 0
    while i < len(s):
        n = random.randint(lo, hi)
        out.append(s[i:i + n])
        i += n
    return out


def _dec_src():
    return {
        'gzip': "__import__('gzip').decompress",
        'lzma': "__import__('lzma').decompress",
        'zlib': "__import__('zlib').decompress",
    }


def matryoshka_pack(src_code):
    order = random.sample(['gzip', 'lzma', 'zlib'], 3)
    data = src_code.encode()
    for name in order:
        if name == 'gzip':
            data = gzip.compress(data, compresslevel=_GZIP_LEVEL)
        elif name == 'lzma':
            data = lzma.compress(data, preset=_LZMA_PRESET)
        else:
            data = zlib.compress(data, level=_ZLIB_LEVEL)
    data = base64.b64encode(data)
    reverse = random.choice([True, False])
    if reverse:
        data = data[::-1]
    packed = data.decode()
    chunks = _chunk(packed)
    inner = "''.join(__)"
    if reverse:
        inner = f"({inner})[::-1]"
    expr = f"__import__('base64').b64decode({inner})"
    ds = _dec_src()
    for name in reversed(order):
        expr = f"{ds[name]}({expr})"
    expr += ".decode()"
    v = _rnd()
    return f"{v}=lambda __:exec({expr},globals());{v}({chunks!r})"


def _extract_chunks(stub_src):
    tree = ast.parse(stub_src)
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and node.args
                and isinstance(node.args[0], ast.List)):
            try:
                return [ast.literal_eval(x) for x in node.args[0].elts]
            except Exception:
                pass
    raise ValueError('no chunks found')


def unpack_matryoshka(stub_src):
    import itertools
    packed = ''.join(_extract_chunks(stub_src))
    decomp = {'gzip': gzip.decompress, 'lzma': lzma.decompress,
              'zlib': zlib.decompress}
    for rev in (True, False):
        try:
            data = base64.b64decode(packed[::-1] if rev else packed)
        except Exception:
            continue
        for perm in itertools.permutations(['gzip', 'lzma', 'zlib']):
            try:
                d = data
                for n in perm:
                    d = decomp[n](d)
                try:
                    return d.decode()
                except UnicodeDecodeError:
                    continue
            except Exception:
                continue
    raise ValueError('cannot unpack matryoshka')


class _Mangler(ast.NodeTransformer):
    def __init__(self):
        self.map = {}
        self.protected = set()

    def _protect(self, name):
        if name and isinstance(name, str):
            self.protected.add(name)

    def _is_prot(self, name):
        return (name in _BUILTINS
                or name in self.protected
                or (name.startswith('__') and name.endswith('__'))
                or name in {'self', 'cls', 'super'})

    def _m(self, name):
        if self._is_prot(name):
            return name
        if name not in self.map:
            self.map[name] = '_' + ''.join(
                random.choices(string.ascii_lowercase, k=8))
        return self.map[name]

    def _prepass(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                a = node.args
                for arg in (list(a.args) + list(a.kwonlyargs)
                            + list(getattr(a, 'posonlyargs', []))):
                    self._protect(arg.arg)
                if a.vararg:
                    self._protect(a.vararg.arg)
                if a.kwarg:
                    self._protect(a.kwarg.arg)
            elif isinstance(node, ast.ExceptHandler):
                if node.name:
                    self._protect(node.name)
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                for n in node.names:
                    self._protect(n)
            elif isinstance(node, ast.Attribute):
                self._protect(node.attr)
            elif isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg:
                        self._protect(kw.arg)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for a in node.names:
                    if a.name != '*':
                        self._protect(a.asname or a.name.split('.')[0])
            elif isinstance(node, (ast.MatchAs, ast.MatchStar)):
                if node.name:
                    self._protect(node.name)
            elif isinstance(node, ast.MatchMapping) and node.rest:
                self._protect(node.rest)

        def collect(node):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return
            if isinstance(node, ast.ClassDef):
                self._protect(node.name)
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._protect(item.name)
                    else:
                        collect(item)
                return
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                self._protect(node.id)
            for child in ast.iter_child_nodes(node):
                collect(child)

        collect(tree)

    def visit_Module(self, node):
        self._prepass(node)
        return self.generic_visit(node)

    def visit_Name(self, node):
        node.id = self._m(node.id)
        return node

    def visit_FunctionDef(self, node):
        node.name = self._m(node.name)
        self.generic_visit(node)
        return node

    def visit_AsyncFunctionDef(self, node):
        node.name = self._m(node.name)
        self.generic_visit(node)
        return node

    def visit_ClassDef(self, node):
        node.name = self._m(node.name)
        self.generic_visit(node)
        return node


class _NumberPart(ast.NodeTransformer):
    def visit_Constant(self, node):
        if (isinstance(node.value, int)
                and not isinstance(node.value, bool)
                and abs(node.value) > 100):
            v = node.value
            if v >= 0:
                a = random.randint(1, v - 1)
                return ast.parse(f"({a} + {v - a})", mode='eval').body
            av = -v
            a = random.randint(1, av - 1)
            return ast.parse(f"-({a} + {av - a})", mode='eval').body
        return node


class _XorStr(ast.NodeTransformer):
    def visit_JoinedStr(self, node):
        return node

    def visit_Constant(self, node):
        if isinstance(node.value, str) and node.value:
            key = random.randint(1, 255)
            enc = bytes(b ^ key for b in node.value.encode())
            return ast.parse(
                f"bytes(b ^ {key} for b in {enc!r}).decode()",
                mode='eval').body
        return node


class _DynImports(ast.NodeTransformer):
    def _expr(self, name):
        h = name.encode().hex()
        return ast.parse(
            f"__import__('importlib').import_module(bytes.fromhex({h!r}).decode())",
            mode='eval').body

    def visit_Import(self, node):
        new = []
        for a in node.names:
            tgt = a.asname or a.name.split('.')[0]
            mod = a.name if a.asname else a.name.split('.')[0]
            new.append(ast.Assign(
                targets=[ast.Name(id=tgt, ctx=ast.Store())],
                value=self._expr(mod)))
        for n in new:
            ast.fix_missing_locations(n)
        if len(new) > 1:
            return new
        if new:
            return new[0]
        return ast.Pass()

    def visit_ImportFrom(self, node):
        if node.level and node.level > 0:
            return node
        if any(a.name == '*' for a in node.names):
            return node
        new = []
        for a in node.names:
            tgt = a.asname or a.name
            new.append(ast.Assign(
                targets=[ast.Name(id=tgt, ctx=ast.Store())],
                value=ast.Attribute(
                    value=self._expr(node.module),
                    attr=a.name, ctx=ast.Load())))
        for n in new:
            ast.fix_missing_locations(n)
        if len(new) > 1:
            return new
        if new:
            return new[0]
        return ast.Pass()


def apply_ast(src, opts):
    tree = ast.parse(src)
    if opts.numbers:
        tree = _NumberPart().visit(tree)
    if opts.xor_strings:
        tree = _XorStr().visit(tree)
    if opts.dynamic_imports:
        tree = _DynImports().visit(tree)
    if opts.mangle:
        tree = _Mangler().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def ast_mangle(src):
    return apply_ast(src, Options(mangle=True, position=False))


def ast_partition_numbers(src):
    return apply_ast(src, Options(numbers=True, position=False))


def ast_xor_strings(src):
    return apply_ast(src, Options(xor_strings=True, position=False))


def ast_dynamic_imports(src):
    return apply_ast(src, Options(dynamic_imports=True, position=False))


def _wrap_b64(code, prologue, imports="import base64 as _b"):
    b64 = base64.b64encode(code.encode()).decode()
    return f"{imports}\n{prologue}\nexec(_b.b64decode('{b64}').decode())\n"


def anti_debug_wrap(code):
    return _wrap_b64(
        code,
        "import sys as _s\nif _s.gettrace() is not None:\n    _s.exit(0)",
        "import base64 as _b, sys as _s")


def anti_decompile_wrap(code):
    return _wrap_b64(
        code,
        "import sys as _s\n"
        "_bad = ('uncompyle6','decompyle3','xdis','pycdc','pycdas')\n"
        "if any(_x in _s.modules for _x in _bad):\n    _s.exit(0)",
        "import base64 as _b, sys as _s")


def integrity_wrap(code):
    h = hashlib.sha256(code.encode()).hexdigest()
    b64 = base64.b64encode(code.encode()).decode()
    return (
        "import base64 as _b, hashlib as _h\n"
        f"_e = '{h}'\n"
        f"_x = _b.b64decode('{b64}')\n"
        "if _h.sha256(_x).hexdigest() != _e:\n"
        "    raise SystemExit(1)\n"
        "exec(_x.decode())\n"
    )


def _combined_guard_wrap(code, integrity=True, anti_debug=True,
                         anti_decompile=True):
    parts = ["import base64 as _b, sys as _s"]
    if anti_debug:
        parts.append("if _s.gettrace() is not None: _s.exit(0)")
    if anti_decompile:
        parts.append(
            "_bad=('uncompyle6','decompyle3','xdis','pycdc','pycdas')")
        parts.append(
            "if any(_x in _s.modules for _x in _bad): _s.exit(0)")
    b64 = base64.b64encode(code.encode()).decode()
    if integrity:
        h = hashlib.sha256(code.encode()).hexdigest()
        parts.append("import hashlib as _h")
        parts.append(f"_e='{h}'")
        parts.append(f"_x=_b.b64decode('{b64}')")
        parts.append("if _h.sha256(_x).hexdigest()!=_e: raise SystemExit(1)")
        parts.append("exec(_x.decode())")
    else:
        parts.append(f"exec(_b.b64decode('{b64}').decode())")
    return "\n".join(parts) + "\n"


def bytecode_wrap(src):
    code = compile(src, '<obfuscated>', 'exec')
    blob = base64.b64encode(marshal.dumps(code)).decode()[::-1]
    chunks = _chunk(blob, lo=80, hi=200)
    m, b, c = _rnd(), _rnd(), _rnd()
    return (
        f"import marshal as {m},base64 as {b}\n"
        f"{c}={chunks!r}\n"
        f"exec({m}.loads({b}.b64decode(''.join({c})[::-1])))\n"
    )


def aes_gcm_wrap(code, password, iterations=_PBKDF2_ITERS):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        raise RuntimeError('pip install cryptography')

    salt = os.urandom(16)
    nonce = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=iterations)
    key = kdf.derive(password.encode())
    ct = AESGCM(key).encrypt(nonce, code.encode(), salt)
    blob = base64.b64encode(salt + nonce + ct).decode()

    return (
        "import os, sys, base64 as _b, getpass\n"
        f"_blob = _b.b64decode('{blob}')\n"
        "_salt, _nonce, _ct = _blob[:16], _blob[16:28], _blob[28:]\n"
        "_pw = os.environ.get('OBF_PASS','').encode() or "
        "getpass.getpass('Password: ').encode()\n"
        "def _dec():\n"
        "    try:\n"
        "        from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC\n"
        "        from cryptography.hazmat.primitives import hashes\n"
        f"        _k = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=_salt,"
        f"iterations={iterations}).derive(_pw)\n"
        "        return AESGCM(_k).decrypt(_nonce, _ct, _salt)\n"
        "    except ImportError:\n"
        "        from Crypto.Cipher import AES\n"
        "        from Crypto.Protocol.KDF import PBKDF2\n"
        f"        _k = PBKDF2(_pw, _salt, dkLen=32, count={iterations})\n"
        "        _c = AES.new(_k, AES.MODE_GCM, nonce=_nonce)\n"
        "        return _c.decrypt_and_verify(_ct[:-16], _ct[-16:])\n"
        "try:\n"
        "    _pt = _dec()\n"
        "except Exception:\n"
        "    sys.exit('Bad password or corrupted payload')\n"
        "exec(_pt.decode(), globals())\n"
    )


def aes_gcm_strip(inner, password):
    m = re.search(r"_blob = _b\.b64decode\('([^']+)'\)", inner)
    if not m:
        raise ValueError('cannot parse AES blob')
    blob = base64.b64decode(m.group(1))
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
    mi = re.search(r'iterations=(\d+)', inner)
    iters = int(mi.group(1)) if mi else _PBKDF2_ITERS

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=iters)
    key = kdf.derive(password.encode())
    return AESGCM(key).decrypt(nonce, ct, salt).decode()


def _make_import_stub(template_src):
    stub = []
    for line in template_src.splitlines():
        s = line.strip()
        if s.startswith(("import ", "from ")) and "__future__" not in s:
            stub.append(s)
    stub.append("import gzip,lzma,zlib")
    return "\n".join(stub) + "\n"


def _build(src, opts):
    code = src
    if any((opts.mangle, opts.numbers, opts.xor_strings, opts.dynamic_imports)):
        code = apply_ast(code, Options(
            mangle=opts.mangle, numbers=opts.numbers,
            xor_strings=opts.xor_strings,
            dynamic_imports=opts.dynamic_imports,
            position=False))

    inner = _make_stub(position_encode(code)) if opts.position \
            else f"exec({code!r})"

    if opts.anti_debug or opts.anti_decompile or opts.integrity:
        inner = _combined_guard_wrap(
            inner,
            integrity=opts.integrity,
            anti_debug=opts.anti_debug,
            anti_decompile=opts.anti_decompile,
        )

    if opts.bytecode:
        inner = bytecode_wrap(inner)
    if opts.password:
        inner = aes_gcm_wrap(inner, opts.password)

    result = matryoshka_pack(inner)

    if opts.template:
        result = _make_import_stub(opts.template) + result
    return result


def protect(source, opts=None, **kwargs):
    base = opts or Options()
    try:
        opts = replace(base, **kwargs)
    except TypeError as e:
        raise TypeError(f'unknown option: {e}') from None

    if opts.seed is not None:
        try:
            random.seed(int(opts.seed))
        except (ValueError, TypeError):
            random.seed(str(opts.seed))
    else:
        random.seed()

    return _build(source, opts)


def protect_file(in_path, out_path, opts=None, **kwargs):
    with open(in_path, 'r', encoding='utf-8', newline='') as f:
        src = f.read()
    result = protect(src, opts, **kwargs)
    with open(out_path, 'w', encoding='utf-8', newline='') as f:
        f.write(result)


def _is_pos_map(s):
    if 'b85decode' in s:
        return True
    return 'char_map' in s and 'line_lengths' in s


def _is_aes(s):
    return '_blob = _b.b64decode' in s and '_salt' in s and 'getpass' in s


def _is_bytecode(s):
    return ('_m.loads' in s or 'marshal.loads' in s) and 'b64decode' in s


def _is_integrity(s):
    return 'sha256' in s and "_e='" in s and '_x=_b.b64decode' in s


def _is_antidecomp(s):
    return 'uncompyle' in s and '_bad=' in s and '_b.b64decode' in s


def _is_antidebug(s):
    return 'gettrace' in s and '_s.exit(0)' in s and '_b.b64decode' in s


def _strip_b64exec(s):
    m = re.search(r"_b\.b64decode\('([^']+)'\)\.decode\(\)", s)
    if not m:
        m = re.search(r"_b\.b64decode\('([^']+)'\)", s)
    if not m:
        raise ValueError('cannot strip b64-exec')
    return base64.b64decode(m.group(1)).decode()


def _strip_guard(s):
    m = re.search(r"_x=_b\.b64decode\('([^']+)'\)", s)
    if m:
        return base64.b64decode(m.group(1)).decode()
    m = re.search(r"exec\(_b\.b64decode\('([^']+)'\)\.decode\(\)\)", s)
    if m:
        return base64.b64decode(m.group(1)).decode()
    raise ValueError('cannot strip guard')


def deobfuscate(payload, password=None):
    inner = unpack_matryoshka(payload)
    for _ in range(12):
        if _is_pos_map(inner):
            try:
                return position_decode(_extract_pos_payload(inner))
            except Exception:
                pass
        if _is_aes(inner):
            if not password:
                raise ValueError('password required')
            inner = aes_gcm_strip(inner, password)
        elif _is_bytecode(inner):
            raise ValueError('bytecode layer is irreversible')
        elif _is_integrity(inner) or _is_antidecomp(inner) or _is_antidebug(inner):
            try:
                inner = _strip_guard(inner)
            except Exception:
                inner = _strip_b64exec(inner)
        else:
            m = re.search(r'exec\((.+)\)\s*$', inner.strip(), re.DOTALL)
            if m:
                try:
                    return ast.literal_eval(m.group(1))
                except Exception:
                    pass
            raise ValueError(f'unknown layer: {inner[:80]!r}')
    raise ValueError('too many layers')


def cli(argv=None):
    import argparse
    p = argparse.ArgumentParser(prog='FrontProtect',
                                description='Multi-layer Python obfuscator')
    p.add_argument('input', nargs='?', help='input .py (omit to launch GUI)')
    p.add_argument('-o', '--output')
    p.add_argument('--mangle', action='store_true')
    p.add_argument('--numbers', action='store_true')
    p.add_argument('--xor-strings', action='store_true')
    p.add_argument('--dynamic-imports', action='store_true')
    p.add_argument('--no-position', action='store_true')
    p.add_argument('--anti-debug', action='store_true')
    p.add_argument('--anti-decompile', action='store_true')
    p.add_argument('--integrity', action='store_true')
    p.add_argument('--bytecode', action='store_true')
    p.add_argument('--password')
    p.add_argument('--pyi', help='PyInstaller template')
    p.add_argument('--seed')
    p.add_argument('-d', '--decode', action='store_true')
    a = p.parse_args(argv)

    if not a.input:
        return gui()

    if not a.output:
        p.error('-o/--output required')

    if a.decode:
        src = open(a.input, 'r', encoding='utf-8', newline='').read()
        restored = deobfuscate(src, password=a.password)
        open(a.output, 'w', encoding='utf-8', newline='').write(restored)
        return 0

    tpl = None
    if a.pyi:
        with open(a.pyi, 'r', encoding='utf-8') as f:
            tpl = f.read()

    seed = a.seed
    if seed is not None:
        try:
            seed = int(seed)
        except ValueError:
            pass

    protect_file(a.input, a.output,
                 mangle=a.mangle,
                 numbers=a.numbers,
                 xor_strings=a.xor_strings,
                 dynamic_imports=a.dynamic_imports,
                 position=not a.no_position,
                 anti_debug=a.anti_debug,
                 anti_decompile=a.anti_decompile,
                 integrity=a.integrity,
                 bytecode=a.bytecode,
                 password=a.password,
                 template=tpl,
                 seed=seed)
    return 0


def gui():
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk
    except ImportError:
        print('tkinter is not available', file=sys.stderr)
        return 1

    class _App:
        def __init__(self, root):
            self.root = root
            root.title('FrontProtect - multi-layer obfuscator')
            root.geometry('920x820')
            self._ui()

        def _ui(self):
            f = ttk.LabelFrame(self.root, text='Files')
            f.pack(fill='x', padx=8, pady=4)
            ttk.Label(f, text='Input:').grid(row=0, column=0, sticky='w', padx=4)
            self.in_var = tk.StringVar()
            ttk.Entry(f, textvariable=self.in_var).grid(row=0, column=1, sticky='ew')
            ttk.Button(f, text='...', width=3, command=self._pin).grid(row=0, column=2)
            ttk.Label(f, text='Output:').grid(row=1, column=0, sticky='w', padx=4)
            self.out_var = tk.StringVar()
            ttk.Entry(f, textvariable=self.out_var).grid(row=1, column=1, sticky='ew')
            ttk.Button(f, text='...', width=3, command=self._pout).grid(row=1, column=2)
            f.columnconfigure(1, weight=1)

            L = ttk.LabelFrame(self.root, text='Layers (bottom to top; Randy always last)')
            L.pack(fill='x', padx=8, pady=4)
            self.vars = {}
            items = [
                ('mangle', 'Name mangling'),
                ('numbers', 'Number partitioning'),
                ('xor_strings', 'XOR strings (inline key)'),
                ('dynamic_imports', 'Dynamic imports (importlib)'),
                ('position', 'Position map'),
                ('anti_debug', 'Anti-debug (gettrace)'),
                ('anti_decompile', 'Anti-decompile (uncompyle/xdis)'),
                ('integrity', 'Integrity check (SHA-256)'),
                ('bytecode', 'Bytecode (marshal) - irreversible'),
            ]
            for i, (k, label) in enumerate(items):
                v = tk.BooleanVar(value=(k == 'position'))
                self.vars[k] = v
                ttk.Checkbutton(L, text=label, variable=v).grid(
                    row=i, column=0, sticky='w', padx=4)

            randy = tk.BooleanVar(value=True)
            cb = ttk.Checkbutton(L, text='Randy (gzip->lzma->zlib->b64) - ALWAYS',
                                 variable=randy)
            cb.state(['disabled', 'selected'])
            cb.grid(row=len(items), column=0, sticky='w', padx=4)

            self.pyi_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(L, text='PyInstaller import stub',
                            variable=self.pyi_var,
                            command=self._pyi_toggle).grid(
                row=len(items) + 1, column=0, sticky='w', padx=4)
            self.tpl_var = tk.StringVar()
            self.tpl_entry = ttk.Entry(L, textvariable=self.tpl_var, state='disabled')
            self.tpl_entry.grid(row=len(items) + 1, column=1, sticky='ew', padx=4)
            self.tpl_btn = ttk.Button(L, text='...', width=3,
                                      command=self._ptpl, state='disabled')
            self.tpl_btn.grid(row=len(items) + 1, column=2)
            L.columnconfigure(1, weight=1)

            P = ttk.LabelFrame(self.root, text='Password (AES-256-GCM, over all layers)')
            P.pack(fill='x', padx=8, pady=4)
            self.pw_var = tk.StringVar()
            ttk.Label(P, text='Password:').pack(side='left', padx=4)
            ttk.Entry(P, textvariable=self.pw_var, show='*').pack(
                side='left', fill='x', expand=True, padx=4)
            ttk.Label(P, text='(empty = no password)').pack(side='left', padx=4)

            S = ttk.Frame(self.root)
            S.pack(fill='x', padx=8)
            ttk.Label(S, text='Seed:').pack(side='left')
            self.seed_var = tk.StringVar()
            ttk.Entry(S, textvariable=self.seed_var, width=20).pack(side='left', padx=4)
            ttk.Label(S, text='(empty = random)').pack(side='left')

            B = ttk.Frame(self.root)
            B.pack(fill='x', padx=8, pady=4)
            ttk.Button(B, text='Obfuscate', command=self._obf).pack(side='left', padx=4)
            self.deobf_btn = ttk.Button(B, text='Deobfuscate', command=self._deobf)
            self.deobf_btn.pack(side='left', padx=4)
            ttk.Button(B, text='Clear log', command=self._clear).pack(side='right', padx=4)

            LF = ttk.LabelFrame(self.root, text='Log')
            LF.pack(fill='both', expand=True, padx=8, pady=4)
            self.log = scrolledtext.ScrolledText(LF, wrap='word', height=15,
                                                 font=('Consolas', 10))
            self.log.pack(fill='both', expand=True)

            self.status = tk.StringVar(value='Ready')
            ttk.Label(self.root, textvariable=self.status,
                      relief='sunken', anchor='w').pack(fill='x', side='bottom')

            self.vars['bytecode'].trace_add('write', self._bytecode_changed)

        def _bytecode_changed(self, *_):
            self.deobf_btn.config(
                state='disabled' if self.vars['bytecode'].get() else 'normal')

        def _pyi_toggle(self):
            s = 'normal' if self.pyi_var.get() else 'disabled'
            self.tpl_entry.config(state=s)
            self.tpl_btn.config(state=s)

        def _pin(self):
            p = filedialog.askopenfilename(filetypes=[('Python', '*.py'), ('All', '*')])
            if p:
                self.in_var.set(p)
                if not self.out_var.get():
                    b, e = os.path.splitext(p)
                    self.out_var.set(b + '_obf' + e)

        def _pout(self):
            p = filedialog.asksaveasfilename(defaultextension='.py')
            if p:
                self.out_var.set(p)

        def _ptpl(self):
            p = filedialog.askopenfilename(filetypes=[('Python', '*.py'), ('All', '*')])
            if p:
                self.tpl_var.set(p)

        def _log(self, msg):
            self.log.insert('end', msg + '\n')
            self.log.see('end')

        def _clear(self):
            self.log.delete('1.0', 'end')

        def _read(self, p):
            with open(p, 'r', encoding='utf-8', newline='') as f:
                return f.read()

        def _write(self, p, d):
            with open(p, 'w', encoding='utf-8', newline='') as f:
                f.write(d)

        def _obf(self):
            try:
                src = self._read(self.in_var.get())
                tpl = None
                if self.pyi_var.get():
                    if not self.tpl_var.get():
                        raise ValueError('PyInstaller requires template')
                    tpl = self._read(self.tpl_var.get())
                pw = self.pw_var.get() or None
                seed = self.seed_var.get().strip() or None
                if seed is not None:
                    try:
                        seed = int(seed)
                    except ValueError:
                        pass
                opts = {k: v.get() for k, v in self.vars.items()}
                self.status.set('Obfuscating...')
                self.root.update_idletasks()
                out = protect(src, template=tpl, password=pw, seed=seed, **opts)
                self._write(self.out_var.get(), out)
                layers = [k for k in ('mangle', 'numbers', 'xor_strings',
                                      'dynamic_imports', 'position', 'anti_debug',
                                      'anti_decompile', 'integrity', 'bytecode')
                          if opts[k]]
                if pw:
                    layers.append('AES-GCM')
                layers.append('Randy')
                self._log(f'[OK] {len(src)} -> {len(out)} bytes')
                self._log(f'     layers: {" -> ".join(layers)}')
                self.status.set(f'Done ({len(out)} bytes)')
            except Exception as e:
                self._log(f'[ERR] {e}')
                messagebox.showerror('Error', str(e))
                self.status.set('Error')

        def _deobf(self):
            try:
                src = self._read(self.in_var.get())
                pw = simpledialog.askstring(
                    'Password', 'Enter password (empty if none):',
                    show='*', parent=self.root) or None
                self.status.set('Deobfuscating...')
                self.root.update_idletasks()
                restored = deobfuscate(src, password=pw)
                self._write(self.out_var.get(), restored)
                self._log(f'[OK] restored {len(restored)} bytes (AST-form)')
                self.status.set('Done')
            except Exception as e:
                self._log(f'[ERR] {e}')
                messagebox.showerror('Deobfuscation error', str(e))
                self.status.set('Error')

    root = tk.Tk()
    try:
        s = ttk.Style()
        for theme in ('vista', 'clam', 'default'):
            if theme in s.theme_names():
                s.theme_use(theme)
                break
    except Exception:
        pass
    _App(root)
    root.mainloop()
    return 0


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        return gui()
    return cli(argv)


if __name__ == '__main__':
    sys.exit(main())