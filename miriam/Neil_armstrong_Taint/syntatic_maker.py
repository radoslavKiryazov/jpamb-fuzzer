#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Conservative Syntactic Analyzer for JPAMB
- Keeps the working patterns from original
- Adds targeted improvements for parameter tracking
- Fixes the trivial method bug
- Deterministic outputs (hash nudging removed)
- Improved brace balancing (ignores strings & comments)
- Broader assert patterns (handles `assert cond : detail;`)

Test locally:
  uv run jpamb test --filter "Simple" -W ./syntatic_maker_v2.py
"""
import os, re, sys
from typing import Tuple, Set, List

# ---------- Small util ----------
_BASE = set("BCDFIJSZ")

def count_params(desc: str) -> int:
    """Count params in a JVM method descriptor"""
    i, n = 1, 0
    while i < len(desc):
        c = desc[i]
        if c == ")":
            break
        while c == "[":
            i += 1
            c = desc[i]
        if c in _BASE:
            n += 1; i += 1
        elif c == "L":
            j = desc.find(";", i)
            if j == -1:
                n += 1; break
            n += 1; i = j + 1
        else:
            n += 1; i += 1
    return n

# ---------- JPAMB helpers (optional) ----------
_has_jpamb = False
try:
    import jpamb
    _has_jpamb = True
except Exception:
    _has_jpamb = False

def source_path(java_class: str) -> str:
    """Locate source file"""
    if _has_jpamb:
        try:
            dummy = type("M", (), {"class_name": java_class, "method_name": None, "descriptor": None})
            p = jpamb.sourcefile(dummy)
            if p and os.path.exists(p):
                return p
        except Exception:
            pass
    p = os.path.join("src", "main", "java", *java_class.split(".")) + ".java"
    if os.path.exists(p):
        return p
    q = os.path.join("decompiled", *java_class.split(".")) + ".java"
    return q if os.path.exists(q) else p

# ---------- Method text extraction (header + body) ----------
_HEADER_RE_TMPL = r"""
(?P<prefix>^|
)
(?:\s*@\w+(?:\([^)]*\))?\s*
\s*)*                # annotations (on separate lines)
(?:public|private|protected|static|final|abstract|synchronized|native|strictfp|\s)*
(?:<[^>]*>\s*)?                                   # method type params
[\w\.$\[\]<>?]+\s+                                # return type (rough, syntactic)
{meth}\s*\(\s*(?P<params>[^)]*)\)\s*              # method name + params capture
(?:throws\s+[\w\.$,\s]+)?\s*                      # throws clause (optional)
\{{                                               # opening brace of body
"""

_HEADER_RE_FLAGS = re.M | re.VERBOSE

_PARAM_SPLIT = re.compile(r",(?![^<]*>)")   # split on commas, but not inside <...>

def _param_count_from_text(params_text: str) -> int:
    params_text = params_text.strip()
    if params_text == "":
        return 0
    parts = [p for p in _PARAM_SPLIT.split(params_text) if p.strip()]
    return len(parts)

def _skip_table(src: str) -> List[bool]:
    """True where char is inside //comment, /*comment*/, or '...' / "..." literal."""
    L = len(src); skip = [False]*L
    i = 0
    while i < L:
        ch = src[i]
        # line comment
        if ch == '/' and i+1 < L and src[i+1] == '/':
            j = i+2
            while j < L and src[j] != '\n':
                j += 1
            for k in range(i, j):
                skip[k] = True
            i = j; continue
        # block comment
        if ch == '/' and i+1 < L and src[i+1] == '*':
            j = i+2
            while j+1 < L and not (src[j] == '*' and src[j+1] == '/'):
                j += 1
            j = min(j+2, L)
            for k in range(i, j):
                skip[k] = True
            i = j; continue
        # string / char literal
        if ch in ('"', "'"):
            q = ch; j = i+1; esc = False
            while j < L:
                if src[j] == '\n' and q == '"':
                    # end string on newline if not closed (be forgiving)
                    break
                if not esc and src[j] == q:
                    j += 1
                    break
                esc = (not esc and src[j] == '\\')
                j += 1
            for k in range(i, j):
                skip[k] = True
            i = j; continue
        i += 1
    return skip

def extract_method_text(java_src: str, method: str, arity: int) -> str:
    """Find full method text (header + balanced body)."""
    header_re = re.compile(_HEADER_RE_TMPL.format(meth=re.escape(method)), _HEADER_RE_FLAGS)
    for m in header_re.finditer(java_src):
        params_text = m.group("params") or ""
        if _param_count_from_text(params_text) != arity:
            continue
        header_start = m.start()
        start = java_src.find("{", m.start())
        if start == -1:
            continue
        depth, i, L = 0, start, len(java_src)
        skip = _skip_table(java_src)
        while i < L:
            if skip[i]:
                i += 1
                continue
            ch = java_src[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return java_src[header_start:i + 1]
            i += 1
    # Fallback: return entire file if not found (keeps original behavior)
    return java_src

# ---------- Parameter extraction ----------
def extract_parameters(method_text: str) -> Set[str]:
    """Extract parameter names from a Java method signature (syntactic, robust to annotations/varargs)."""
    # Find the first "( ... )" after what looks like return type + method name
    sig_match = re.search(r'\b[\w$<>.\[\]]+\s+[\w$<>]+\s*\((.*?)\)', method_text, re.S)
    if not sig_match:
        return set()
    params_text = sig_match.group(1).strip()
    if not params_text:
        return set()

    names: Set[str] = set()
    for raw in _PARAM_SPLIT.split(params_text):
        p = raw.strip()
        if not p:
            continue
        # strip annotations and simple modifiers
        p = re.sub(r'@\w+(?:\([^()]*\))?\s*', '', p)
        p = re.sub(r'\b(final|volatile)\b', '', p)
        # turn varargs into array syntax to keep the last identifier as name
        p = p.replace('...', '[]')
        # variable name is the last simple identifier
        mname = re.search(r'([A-Za-z_]\w*)\s*(?:\[\s*\])*\s*$', p)
        if mname:
            names.add(mname.group(1))
    return names

# ---------- Heuristic analyzer (syntactic only) ----------

# Literal division by zero
RE_DIV_LIT_ZERO = re.compile(r"/\s*=?\s*\(?\s*0\s*\)?(?!\d|\.)")
# Definite assertion failures, including detail:  assert false;  or  assert false : "msg";
RE_ASSERT_FALSE_ANY = re.compile(r"\bassert\s+(?:false|0\s*==\s*1|1\s*==\s*0)\s*(?::[^;]*)?;")
# Infinite loops (basic)
RE_INF_WHILE = re.compile(r"while\s*\(\s*true\s*\)")
RE_INF_FOR = re.compile(r"for\s*\(\s*;\s*;\s*\)")
RE_INF_DO = re.compile(r"do\s*\{[\s\S]*?\}\s*while\s*\(\s*true\s*\)\s*;")
# Out-of-bounds hints
RE_OOB_LENGTH_INDEX = re.compile(r"\[[^\]]*?\.length\s*\]")
RE_OOB_NEG_INDEX = re.compile(r"\[\s*-(?:\s*\d+)\s*\]")
# NPE hints
RE_NULL_LITERAL = re.compile(r"\bnull\b")
RE_MEMBER_ACCESS = re.compile(r"\w+\s*\.\s*\w+")

# Guard patterns
RE_IF_TRUE_RETURN = re.compile(r"if\s*\(\s*true\s*\)\s*\{[^}]*?return[\s\S]*?\}")
RE_ASSERT_VAR_NE0 = re.compile(r"assert\s+(?P<var>[a-zA-Z_]\w*)\s*!=\s*0\s*;")
RE_ASSERT_VAR_GT0 = re.compile(r"assert\s+(?P<var>[a-zA-Z_]\w*)\s*>\s*0\s*;")
RE_IF_VAR_NE0_RET_DIV = re.compile(
    r"if\s*\(\s*(?P<var>[a-zA-Z_]\w*)\s*!=\s*0\s*\)\s*\{[\s\S]*?1\s*/\s*(?P=var)[\s\S]*?\}"
)
RE_IF_VAR_EQ0_RETURN = re.compile(
    r"if\s*\(\s*(?P<var>[a-zA-Z_]\w*)\s*==\s*0\s*\)\s*\{?\s*return\b"
)

def analyze(method_text: str) -> Tuple[int, int, int, int, int, int]:
    """Analyze method and return (ok, divide, assert, oob, npe, inf) percentages."""
    params = extract_parameters(method_text)
    divide, asserr, oob, npe, inf = 5, 5, 5, 5, 5
    t = method_text

    # === DEFINITE PATTERNS ===
    if RE_DIV_LIT_ZERO.search(t):
        divide = 100
    if RE_ASSERT_FALSE_ANY.search(t):
        asserr = 100
    if RE_INF_WHILE.search(t) or RE_INF_FOR.search(t) or RE_INF_DO.search(t):
        inf = 100
    if RE_OOB_LENGTH_INDEX.search(t) or RE_OOB_NEG_INDEX.search(t):
        oob = max(oob, 95)
    if RE_NULL_LITERAL.search(t) and RE_MEMBER_ACCESS.search(t):
        npe = max(npe, 40)

    # === GUARD ANALYSIS ===
    if asserr == 100 and RE_IF_TRUE_RETURN.search(t):
        asserr = 0

    for m in RE_ASSERT_VAR_NE0.finditer(t):
        var = m.group('var')
        if re.search(rf"1\s*/\s*{re.escape(var)}", t[m.end():]):
            divide = min(divide, 5)   # Division is safe
            asserr = max(asserr, 55)  # But assertion can fail

    for m in RE_ASSERT_VAR_GT0.finditer(t):
        var = m.group('var')
        if re.search(rf"1\s*/\s*{re.escape(var)}", t[m.end():]):
            divide = min(divide, 5)
            asserr = max(asserr, 55)

    for _ in RE_IF_VAR_NE0_RET_DIV.finditer(t):
        divide = min(divide, 5)
        asserr = min(asserr, 5)

    for m in RE_IF_VAR_EQ0_RETURN.finditer(t):
        var = m.group('var')
        if re.search(rf"assert[\s\S]*?1\s*/\s*{re.escape(var)}", t[m.end():]):
            divide = min(divide, 5)

    # === PARAMETER-AWARE DIVISION DETECTION ===
    if divide < 100:
        for param in params:
            # Pattern: something / param (not already guarded)
            m = re.search(rf'/\s*{re.escape(param)}\b', t)
            if m:
                # local, textual guard heuristic (small backward window)
                div_pos = m.start()
                window_start = max(0, div_pos - 200)
                window = t[window_start:div_pos]
                guarded = (
                    re.search(rf'\bassert\s+{re.escape(param)}\s*(!=|>)\s*0\s*;', window) or
                    re.search(rf'if\s*\(\s*{re.escape(param)}\s*!=\s*0\s*\)\s*\{{', window)
                )
                if not guarded:
                    divide = max(divide, 75)  # High risk for unguarded param division

            # Pattern: something / (param - constant)
            if re.search(rf'/\s*\(\s*{re.escape(param)}\s*-\s*\d+\s*\)', t):
                divide = max(divide, 75)

    # === BETTER ASSERTION RISK ===
    if asserr < 100 and "assert" in t:
        for param in params:
            if re.search(rf'\bassert\s+{re.escape(param)}\s*;', t):
                asserr = max(asserr, 55)
            if re.search(rf'\bassert\s+{re.escape(param)}\s*[!>]=?\s*\d+', t):
                asserr = max(asserr, 55)
            if re.search(rf'\bassert\s+.*{re.escape(param)}', t):
                asserr = max(asserr, 50)

    # === HINTS ===
    if divide < 100 and "/" in t:
        divide = max(divide, 12)
    if asserr < 100 and "assert" in t:
        asserr = max(asserr, 10)
    if oob < 95 and ("[" in t and "]" in t):
        oob = max(oob, 10)

    # === CALCULATE OK ===
    worst = max(divide, asserr, oob, npe, inf)
    ok = max(0, 100 - worst)

    # === HANDLE TRIVIAL METHODS (only mark truly safe methods) ===
    if worst <= 10:
        # { return 123; }
        if re.match(r'\{\s*return\s+\d+\s*;\s*\}\s*$', t, re.S):
            ok = 95
            divide, asserr, oob, npe, inf = 1, 1, 1, 1, 1
        # { return; }
        elif re.match(r'\{\s*return\s*;\s*\}\s*$', t, re.S):
            ok = 98
            divide, asserr, oob, npe, inf = 1, 1, 1, 1, 1
        # simple addition/multiplication
        elif re.match(r'\{\s*return\s+\w+\s*[+*]\s*\w+\s*;\s*\}\s*$', t, re.S):
            ok = 95
            divide, asserr, oob, npe, inf = 1, 1, 1, 1, 1

    return ok, divide, asserr, oob, npe, inf

# ---------- CLI ----------
INFO_LINES = (
    "Syntatic Maker v2",
    "0.5.0",
    "DTU JPAMB Group",
    "static,syntax,regex",
    "no",
)

def _print_info():
    for line in INFO_LINES:
        print(line)

def _print_defaults():
    print("ok;75%")
    print("divide by zero;5%")
    print("assertion error;5%")
    print("out of bounds;5%")
    print("null pointer;5%")
    print("*;5%")

def _parse_method_id(arg: str):
    """Return (cls, meth, desc, arity, raw)"""
    raw = arg
    if _has_jpamb:
        try:
            methodid = jpamb.getmethodid(
                INFO_LINES[0], INFO_LINES[1], INFO_LINES[2], INFO_LINES[3].split(","), for_science=False
            ) if arg == "info" else jpamb.jvm.AbsMethodID.fromstring(arg)
            cls = methodid.class_name
            meth = methodid.method_name
            desc = methodid.descriptor
            return cls, meth, desc, count_params(desc), raw
        except Exception:
            pass
    m = re.match(r"^(?P<class>[\w.$]+)\.(?P<meth>[\w$<>]+):(?P<desc>\(.*\).*)$", arg)
    if not m:
        raise ValueError("bad method id format")
    cls, meth, desc = m.group("class"), m.group("meth"), m.group("desc")
    return cls, meth, desc, count_params(desc), raw


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "info":
        _print_info()
        return

    if len(sys.argv) != 2:
        print("usage: syntatic_maker_v2.py info | syntatic_maker_v2.py <Class.method:(desc)>", file=sys.stderr)
        sys.exit(2)

    method_arg = sys.argv[1]
    try:
        cls, meth, desc, arity, raw = _parse_method_id(method_arg)
    except Exception:
        _print_defaults()
        return

    path = source_path(cls)
    try:
        with open(path, "rb") as f:
            src = f.read().decode("utf-8", "ignore")
    except Exception:
        src = ""

    method_text = extract_method_text(src, meth, arity) if src else ""
    if not method_text:
        _print_defaults()
        return

    ok, div0, asrt, oob, npe, inf = analyze(method_text)

    print(f"ok;{ok}%")
    print(f"divide by zero;{div0}%")
    print(f"assertion error;{asrt}%")
    print(f"out of bounds;{oob}%")
    print(f"null pointer;{npe}%")
    print(f"*;{inf}%")


if __name__ == "__main__":
    main()
