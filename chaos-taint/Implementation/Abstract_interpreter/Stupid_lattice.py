#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bounded Abstract Interpreter (JPAMB CLI-compatible)
- Standalone, no heavy deps
- Uses a tiny IR built from Java method source (header+body)
- Runs bounded may-analysis over a taint lattice
- Emits the same 6-line KPI format JPAMB expects

Usage examples:
  # JPAMB:
  uv run jpamb test --filter "Simple" -W ./bounded_ai.py
  # Standalone (no jpamb):
  python3 bounded_ai.py com.example.Simple.foo:(I)I
"""

import os, re, sys
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Iterable, Optional, Set, Literal

# --------- JPAMB integration (optional) ---------
_has_jpamb = False
try:
    import jpamb  # type: ignore
    _has_jpamb = True
except Exception:
    _has_jpamb = False

def _resolve_source(java_class: str) -> str:
    """Best-effort source path resolution (works in JPAMB tree or local /mnt/data)."""
    # 1) JPAMB-provided lookup
    if _has_jpamb:
        try:
            dummy = type("M", (), {"class_name": java_class, "method_name": None, "descriptor": None})
            p = jpamb.sourcefile(dummy)  # type: ignore[attr-defined]
            if p and os.path.exists(p):
                return p
        except Exception:
            pass
    # 2) Local project layouts
    candidates = []
    candidates.append(os.path.join("src", "main", "java", *java_class.split(".")) + ".java")
    candidates.append(os.path.join("decompiled", *java_class.split(".")) + ".java")
    # 3) Uploaded test files (ChatGPT sandbox path)
    base = os.environ.get("BOUND_AI_SEARCH_BASE", "/mnt/data")
    candidates.append(os.path.join(base, *(java_class.split("."))) + ".java")
    for p in candidates:
        if os.path.exists(p):
            return p
    # Fallback to first candidate
    return candidates[0]

# --------- Utility: JVM descriptor param count ---------
_BASE = set("BCDFIJSZ")
def count_params(desc: str) -> int:
    i, n = 1, 0
    while i < len(desc):
        c = desc[i]
        if c == ")": break
        while c == "[":
            i += 1; c = desc[i]
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

# --------- Extract method text (header+body), robust to comments/strings ---------
_HEADER_RE_TMPL = r"""
(?P<prefix>^|\n)
(?:\s*@\w+(?:\([^)]*\))?\s*\n\s*)*                # annotations lines
(?:public|private|protected|static|final|abstract|synchronized|native|strictfp|\s)*
(?:<[^>]*>\s*)?                                   # method type params
[\w\.$\[\]<>?]+\s+                                # return type (syntactic)
{meth}\s*\(\s*(?P<params>[^)]*)\)\s*
(?:throws\s+[\w\.$,\s]+)?\s*
\{{
"""
_HEADER_RE_FLAGS = re.M | re.VERBOSE
_PARAM_SPLIT = re.compile(r",(?![^<]*>)")

def _param_count_from_text(params_text: str) -> int:
    params_text = params_text.strip()
    if not params_text: return 0
    return len([p for p in _PARAM_SPLIT.split(params_text) if p.strip()])

def _skip_table(src: str) -> List[bool]:
    L = len(src); skip = [False]*L; i=0
    while i < L:
        ch = src[i]
        if ch == '/' and i+1<L and src[i+1]=='/':
            j=i+2
            while j<L and src[j]!='\n': j+=1
            for k in range(i,j): skip[k]=True
            i=j; continue
        if ch == '/' and i+1<L and src[i+1]=='*':
            j=i+2
            while j+1<L and not (src[j]=='*' and src[j+1]=='/'): j+=1
            j=min(j+2,L)
            for k in range(i,j): skip[k]=True
            i=j; continue
        if ch in ('"', "'"):
            q=ch; j=i+1; esc=False
            while j<L:
                if src[j]=='\n' and q=='"': break
                if not esc and src[j]==q: j+=1; break
                esc = (not esc and src[j]=='\\')
                j+=1
            for k in range(i,j): skip[k]=True
            i=j; continue
        i+=1
    return skip

def extract_method_text(java_src: str, method: str, arity: int) -> str:
    header_re = re.compile(_HEADER_RE_TMPL.format(meth=re.escape(method)), _HEADER_RE_FLAGS)
    for m in header_re.finditer(java_src):
        params_text = m.group("params") or ""
        if _param_count_from_text(params_text) != arity: continue
        header_start = m.start()
        start = java_src.find("{", m.start())
        if start == -1: continue
        depth, i, L = 0, start, len(java_src)
        skip = _skip_table(java_src)
        while i < L:
            if skip[i]: i+=1; continue
            ch = java_src[i]
            if ch == "{": depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return java_src[header_start:i+1]
            i += 1
    return ""

def read_source(java_class: str) -> str:
    path = _resolve_source(java_class)
    try:
        with open(path, "rb") as f:
            return f.read().decode("utf-8", "ignore")
    except Exception:
        return ""

def extract_parameters(method_text: str) -> List[str]:
    m = re.search(r'\b[\w$<>.\[\]]+\s+[\w$<>]+\s*\((.*?)\)', method_text, re.S)
    if not m: return []
    params_text = m.group(1).strip()
    if not params_text: return []
    names = []
    for raw in _PARAM_SPLIT.split(params_text):
        p = raw.strip()
        if not p: continue
        p = re.sub(r'@\w+(?:\([^()]*\))?\s*', '', p)
        p = re.sub(r'\b(final|volatile)\b', '', p)
        p = p.replace('...', '[]')
        m2 = re.search(r'([A-Za-z_]\w*)\s*(?:\[\s*\])*\s*$', p)
        if m2: names.append(m2.group(1))
    return names

# --------- Tiny IR ---------
@dataclass(frozen=True)
class Instr:
    op: str
    args: Tuple

Program = Dict[int, Instr]  # pc -> instruction

# IR builder (very small; handles a subset sufficient for JPAMB Simple tests)
def build_ir(method_text: str, params: List[str]) -> Program:
    body_m = re.search(r'\{(.*)\}\s*$', method_text, re.S)
    body = body_m.group(1) if body_m else method_text
    # Normalize whitespace
    t = re.sub(r'\s+', ' ', body).strip()

    prog: Program = {}
    pc = 0

    # 0) Simple assignments: x = expr;
    for m in re.finditer(r'\b([A-Za-z_]\w*)\s*=\s*(.*?);', t):
        var, expr = m.group(1), m.group(2)
        if not any(k in expr for k in ['{', '}', 'if ', 'for ', 'while ', 'class ', 'return ']):
            prog[pc] = Instr("ASSIGN", (var, expr)); pc += 1

    # 0b) Very simple call shape: x = foo(bar, baz);
    for m in re.finditer(r'\b([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\((.*?)\)\s*;', t):
        var, callee, args_text = m.group(1), m.group(2), m.group(3).strip()
        args = tuple(a.strip() for a in args_text.split(",")) if args_text else tuple()
        prog[pc] = Instr("CALL", (var, callee, args)); pc += 1

    # 1) Assert statements
    for m in re.finditer(r'\bassert\s*\((.*?)\)\s*;', t):
        cond = m.group(1)
        prog[pc] = Instr("ASSERT", (cond,)); pc += 1

    # 2) If statements (very coarse)
    for m in re.finditer(r'if\s*\((.*?)\)\s*\{', t):
        cond = m.group(1)
        # branch to +2 (then) and +1 (fallthrough) as a sketch
        prog[pc] = Instr("IF", (cond, pc+2)); pc += 1
        prog[pc] = Instr("NOP", ()); pc += 1

    # 3) Divisions
    for m in re.finditer(r'([A-Za-z_]\w*|\d+)\s*/\s*([A-Za-z_]\w*|\d+)', t):
        a, b = m.group(1), m.group(2)
        prog[pc] = Instr("DIV", (a, b)); pc += 1

    # 4) Array access (oob risk)
    for m in re.finditer(r'([A-Za-z_]\w*)\s*\[([^\]]+)\]', t):
        arr, idx = m.group(1), m.group(2)
        prog[pc] = Instr("INDEX", (arr, idx)); pc += 1

    # 5) Null deref patterns (very coarse)
    for m in re.finditer(r'([A-Za-z_]\w*)\s*\.\s*[A-Za-z_]\w*', t):
        obj = m.group(1)
        prog[pc] = Instr("MEMBER", (obj,)); pc += 1

    # Terminal
    prog[pc] = Instr("RET", ()); pc += 1
    return prog

# --------- Taint lattice ---------
@dataclass(frozen=True)
class Taint:
    kinds: Optional[frozenset]  # None=⊥, empty=untainted, set=tainted, top=True
    top: bool = False
    @staticmethod
    def bot(): return Taint(None)
    @staticmethod
    def u():   return Taint(frozenset())
    @staticmethod
    def t(*k): return Taint(frozenset(k))
    @staticmethod
    def topv(): return Taint(frozenset(), True)
    def is_bot(self): return self.kinds is None and not self.top
    def is_top(self): return self.top
    def join(self, other:"Taint")->"Taint":
        if self.is_top() or other.is_top(): return Taint.topv()
        if self.is_bot(): return other
        if other.is_bot(): return self
        return Taint(self.kinds | other.kinds)
    def leq(self, other:"Taint")->bool:
        if self.is_bot(): return True
        if other.is_top(): return True
        if self.is_top(): return other.is_top()
        if other.is_bot(): return self.is_bot()
        return self.kinds.issubset(other.kinds)

# --------- Abstract State ---------
FrameTag = Literal["ok","err"]
@dataclass
class AState:
    pc: int
    env: Dict[str, Taint] = field(default_factory=dict)  # var -> taint
    facts: Dict[str, str] = field(default_factory=dict)  # simple facts like "n!=0"
    tag: Optional[FrameTag] = "ok"

    def join(self, other:"AState")->"AState":
        assert self.pc == other.pc
        keys = set(self.env) | set(other.env)
        env = {k: self.env.get(k, Taint.bot()).join(other.env.get(k, Taint.bot())) for k in keys}
        tag = "err" if (self.tag=="err" or other.tag=="err") else "ok"
        # facts are dropped on join (may-analysis)
        return AState(self.pc, env, {}, tag)

# --------- Taint seeding ---------
def initial_env_from_params(params: List[str]) -> Dict[str, Taint]:
    # Treat all method parameters as untrusted user-tainted
    return {p: Taint.t("param") for p in params}

# --------- Expression taint ---------
_ID = re.compile(r'\b[A-Za-z_]\w*\b')
def eval_expr_taint(expr: str, s: AState) -> Taint:
    # Constants are untainted; any identifier contributes its taint.
    ids = _ID.findall(expr)
    if not ids: return Taint.u()
    out = Taint.u()
    for name in ids:
        out = out.join(s.env.get(name, Taint.u()))
    return out

# --------- Transfer ---------
SOURCE_FUNCS = (
    "readLine", "next", "nextInt", "nextLong", "nextLine", "getParameter",
    "getInput", "read", "recv", "receive"
)
SANITIZERS = ("parseInt", "parseLong")  # placeholder; currently no de-taint

def step_one(prog: Program, s: AState) -> Iterable[AState]:
    ins = prog.get(s.pc)
    if ins is None: return []
    op, args = ins.op, ins.args

    def nxt(pc, env=None, facts=None, tag=None):
        return AState(pc, env or dict(s.env), facts or dict(s.facts), tag or s.tag)

    if op == "ASSERT":
        cond, = args
        cond_taint = eval_expr_taint(cond, s)
        if not cond_taint.leq(Taint.u()):
            # condition depends on input → may fail
            yield nxt(s.pc+1, tag="err")
        # also keep ok path (may-analysis)
        yield nxt(s.pc+1, tag="ok")

    elif op == "IF":
        cond, tgt = args
        m_ne = re.search(r'\b([A-Za-z_]\w*)\s*!=\s*0\b', cond)
        m_eq = re.search(r'\b([A-Za-z_]\w*)\s*==\s*0\b', cond)
        if m_ne:
            var = m_ne.group(1)
            s_then = nxt(tgt, facts={var:"!=0"})
            s_else = nxt(s.pc+1)
            yield s_then; yield s_else
        elif m_eq:
            var = m_eq.group(1)
            s_then = nxt(tgt, facts={var:"==0"})
            s_else = nxt(s.pc+1)
            yield s_then; yield s_else
        else:
            yield nxt(tgt); yield nxt(s.pc+1)

    elif op == "ASSIGN":
        var, expr = args
        ta = eval_expr_taint(expr, s)
        env2 = dict(s.env); env2[var] = ta
        yield nxt(s.pc+1, env=env2)

    elif op == "CALL":
        var, callee, call_args = args
        # Source heuristic
        if any(callee.endswith(sf) or callee == sf for sf in SOURCE_FUNCS):
            ta = Taint.t("source")
        else:
            ta = Taint.u()
            for a in call_args:
                ta = ta.join(eval_expr_taint(a, s))
        env2 = dict(s.env); env2[var] = ta
        yield nxt(s.pc+1, env=env2)

    elif op == "DIV":
        a, b = args
        denom_taint = eval_expr_taint(str(b), s)
        if not s.facts.get(str(b)) == "!=0" and not denom_taint.leq(Taint.u()):
            yield nxt(s.pc+1, tag="err")
        yield nxt(s.pc+1, tag="ok")

    elif op == "INDEX":
        arr, idx = args
        idx_taint = eval_expr_taint(idx, s)
        if not idx_taint.leq(Taint.u()):
            yield nxt(s.pc+1, tag="err")
        yield nxt(s.pc+1, tag="ok")

    elif op == "MEMBER":
        obj, = args
        obj_taint = eval_expr_taint(obj, s)
        if not obj_taint.leq(Taint.u()):
            yield nxt(s.pc+1, tag="err")
        yield nxt(s.pc+1, tag="ok")

    elif op == "NOP":
        yield nxt(s.pc+1)

    elif op == "RET":
        yield nxt(s.pc)  # terminal; keep pc

    else:
        yield nxt(s.pc+1)

# Bounded run
def bounded_run(prog: Program, depth: int, init_env: Optional[Dict[str, Taint]] = None) -> Dict[int, AState]:
    per_pc: Dict[int, AState] = {0: AState(0, env=(init_env or {}))}
    for _ in range(depth):
        next_map: Dict[int, AState] = {}
        for pc, st in per_pc.items():
            for s2 in step_one(prog, st):
                if s2.pc in next_map:
                    next_map[s2.pc] = next_map[s2.pc].join(s2)
                else:
                    next_map[s2.pc] = s2
        per_pc = next_map
        if not per_pc: break
    return per_pc

# --------- Scoring to JPAMB 6-line format ---------
def compute_scores(method_text: str, per_pc: Dict[int, AState], prog: Program)->Tuple[int,int,int,int,int,int]:
    """Heuristic KPIs. We bias scores upward if an 'err' tag occurs anywhere."""
    src = method_text
    divide = 5
    asserr = 5
    oob = 5
    npe = 5
    inf = 5

    # Baseline regex hints
    if re.search(r'\bassert\b', src):
        asserr = max(asserr, 40)
    if re.search(r"/\s*0\b", src):
        divide = 100
    elif re.search(r"/\s*[A-Za-z_]\w*", src):
        divide = max(divide, 40)
    if re.search(r"\[[^\]]+\]", src):
        oob = max(oob, 40)
    if re.search(r"\.\s*[A-Za-z_]\w*", src):
        npe = max(npe, 30)
    if re.search(r"while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)", src):
        inf = 100

    # Lift based on err tags
    if any(st.tag == "err" for st in per_pc.values()):
        # Push the worst category up to reflect taint-induced reachability
        worst = max(divide, asserr, oob, npe, inf)
        bump = max(55, worst)
        # Try to reflect common sinks
        divide = max(divide, 55)
        oob = max(oob, 55)
        npe = max(npe, 40)
        asserr = max(asserr, 55)

    worst = max(divide, asserr, oob, npe, inf)
    ok = max(0, 100 - worst)
    return ok, divide, asserr, oob, npe, inf

# --------- CLI contract with JPAMB ---------
INFO_LINES = (
    "Bounded AI",
    "0.2.0",
    "DTU JPAMB Group",
    "static,ai,bounded,taint",
    "no",
)

def _print_info():
    for line in INFO_LINES: print(line)

def _print_defaults():
    print("ok;75%")
    print("divide by zero;5%")
    print("assertion error;5%")
    print("out of bounds;5%")
    print("null pointer;5%")
    print("*;5%")

def _parse_method_id(arg: str):
    if _has_jpamb and arg != "info":
        try:
            methodid = jpamb.jvm.AbsMethodID.fromstring(arg)  # type: ignore[attr-defined]
            cls = methodid.class_name
            meth = methodid.method_name
            desc = methodid.descriptor
            return cls, meth, desc, count_params(desc)
        except Exception:
            pass
    m = re.match(r"^(?P<class>[\w.$]+)\.(?P<meth>[\w$<>]+):(?P<desc>\(.*\).*)$", arg)
    if not m: raise ValueError("bad method id format")
    cls, meth, desc = m.group("class"), m.group("meth"), m.group("desc")
    return cls, meth, desc, count_params(desc)

def main():
    if len(sys.argv)==2 and sys.argv[1]=="info":
        _print_info(); return
    if len(sys.argv) != 2:
        print("usage: bounded_ai.py info | bounded_ai.py <Class.method:(desc)>", file=sys.stderr)
        sys.exit(2)

    try:
        cls, meth, desc, arity = _parse_method_id(sys.argv[1])
    except Exception:
        _print_defaults(); return

    src = read_source(cls)
    if not src:
        _print_defaults(); return
    method_text = extract_method_text(src, meth, arity)
    if not method_text:
        _print_defaults(); return

    params = extract_parameters(method_text)
    prog = build_ir(method_text, params)
    states = bounded_run(prog, depth=5, init_env=initial_env_from_params(params))  # small bound

    ok, div0, asrt, oob, npe, inf = compute_scores(method_text, states, prog)
    print(f"ok;{ok}%")
    print(f"divide by zero;{div0}%")
    print(f"assertion error;{asrt}%")
    print(f"out of bounds;{oob}%")
    print(f"null pointer;{npe}%")
    print(f"*;{inf}%")

if __name__ == "__main__":
    main()
