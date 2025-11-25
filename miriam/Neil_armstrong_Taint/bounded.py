#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bounded Abstract Interpreter (JPAMB CLI-compatible)
(With explicit novel_abstractions import + stderr diagnostics)
Integrated with syntactic analyzer for better parsing and analysis
"""

import os, re, sys, importlib
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Iterable, Optional, Set, Literal


# ---------- Import AST/CST parser (tree-sitter) ----------
try:
    HERE = os.path.dirname(os.path.abspath(__file__))
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    from ast_parser import (
        parse_java_source,
        extract_ast_features,
        build_ir_from_ast,
        MethodAST,
        _has_tree_sitter,
    )
    _has_ast_parser = _has_tree_sitter
except ImportError as e:
    sys.stderr.write(f"[bounded] Warning: Could not import ast_parser: {e}\n")
    _has_ast_parser = False


# ---------- Import syntactic analyzer functions (fallback) ----------
try:
    HERE = os.path.dirname(os.path.abspath(__file__))
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    from syntatic_maker import (
        extract_method_text as syntatic_extract_method_text,
        extract_parameters as syntatic_extract_parameters,
        analyze as syntatic_analyze,
        source_path as syntatic_source_path,
        count_params as syntatic_count_params,
    )
    _has_syntatic = True
except ImportError as e:
    sys.stderr.write(f"[bounded] Warning: Could not import syntatic_maker: {e}\n")
    _has_syntatic = False


# --------- JPAMB integration (optional) ---------
_has_jpamb = False
try:
    import jpamb  # type: ignore
    _has_jpamb = True
except Exception:
    _has_jpamb = False


def _resolve_source(java_class: str) -> str:
    if _has_jpamb:
        try:
            dummy = type("M", (), {"class_name": java_class, "method_name": None, "descriptor": None})
            p = jpamb.sourcefile(dummy)  # type: ignore[attr-defined]
            if p and os.path.exists(p):
                return p
        except Exception:
            pass
    candidates = []
    candidates.append(os.path.join("src", "main", "java", *java_class.split(".")) + ".java")
    candidates.append(os.path.join("decompiled", *java_class.split(".")) + ".java")
    base = os.environ.get("BOUND_AI_SEARCH_BASE", "/mnt/data")
    candidates.append(os.path.join(base, *(java_class.split("."))) + ".java")
    for p in candidates:
        if os.path.exists(p):
            return p
    return candidates[0]


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

_HEADER_RE_TMPL = r"""
(?P<prefix>^|\n)
(?:\s*@\w+(?:\([^)]*\))?\s*\n\s*)*
(?:public|private|protected|static|final|abstract|synchronized|native|strictfp|\s)*
(?:<[^>]*>\s*)?
[\w\.$\[\]<>?]+\s+
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
        # Find the opening brace of the method body (skip annotation braces)
        # Look for the brace after the method signature
        method_end = m.end() - 1  # The regex ends with '{'
        # But we need to find the actual method body brace, not annotation braces
        # Search forward from the match end for the method body brace
        start = java_src.find("{", m.end() - 10)  # Look near the end of the match
        # Make sure we're past any annotation content
        while start < len(java_src) and start < m.end() + 50:
            # Check if this brace is part of an annotation
            before_brace = java_src[max(0, start-20):start]
            if "@" in before_brace and "(" in before_brace[before_brace.rfind("@"):]:
                # This might be an annotation brace, skip it
                start = java_src.find("{", start + 1)
                continue
            break
        if start == -1 or start >= len(java_src): continue
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
    # Try using syntactic analyzer's source_path first
    if _has_syntatic:
        try:
            path = syntatic_source_path(java_class)
            if os.path.exists(path):
                with open(path, "rb") as f:
                    return f.read().decode("utf-8", "ignore")
        except Exception:
            pass
    # Fallback to original method
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


@dataclass(frozen=True)
class Instr:
    op: str
    args: Tuple

Program = Dict[int, Instr]


def build_ir(method_text: str, params: List[str], syntax_hints: Optional[Dict[str, int]] = None) -> Program:
    """
    Build IR from method text.
    If syntax_hints is provided (from syntactic analyzer), use it to guide IR construction.
    syntax_hints: dict with keys 'divide', 'assert', 'oob', 'npe' with risk scores
    """
    body_m = re.search(r'\{(.*)\}\s*$', method_text, re.S)
    body = body_m.group(1) if body_m else method_text
    t = re.sub(r'\s+', ' ', body).strip()

    prog: Program = {}
    pc = 0

    # Use syntax hints to prioritize IR construction
    # If syntactic analyzer found high risk areas, be more thorough
    check_assert = syntax_hints is None or syntax_hints.get('assert', 0) > 10
    check_divide = syntax_hints is None or syntax_hints.get('divide', 0) > 10
    check_oob = syntax_hints is None or syntax_hints.get('oob', 0) > 10
    check_npe = syntax_hints is None or syntax_hints.get('npe', 0) > 10

    # Always extract assignments and calls
    for m in re.finditer(r'\b([A-Za-z_]\w*)\s*=\s*(.*?);', t):
        var, expr = m.group(1), m.group(2)
        if not any(k in expr for k in ['{', '}', 'if ', 'for ', 'while ', 'class ', 'return ']):
            prog[pc] = Instr("ASSIGN", (var, expr)); pc += 1

    for m in re.finditer(r'\b([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\((.*?)\)\s*;', t):
        var, callee, args_text = m.group(1), m.group(2), m.group(3).strip()
        args = tuple(a.strip() for a in args_text.split(",")) if args_text else tuple()
        prog[pc] = Instr("CALL", (var, callee, args)); pc += 1

    # Extract control flow and error-prone operations based on syntax hints
    if check_assert:
        for m in re.finditer(r'\bassert\s*(?:\((.*?)\)|([^;]+))', t):
            cond = m.group(1) or m.group(2) or "true"
            prog[pc] = Instr("ASSERT", (cond,)); pc += 1

    for m in re.finditer(r'if\s*\((.*?)\)\s*\{', t):
        cond = m.group(1)
        prog[pc] = Instr("IF", (cond, pc+2)); pc += 1
        prog[pc] = Instr("NOP", ()); pc += 1

    if check_divide:
        for m in re.finditer(r'([A-Za-z_]\w*|\d+)\s*/\s*([A-Za-z_]\w*|\d+)', t):
            a, b = m.group(1), m.group(2)
            prog[pc] = Instr("DIV", (a, b)); pc += 1

    if check_oob:
        for m in re.finditer(r'([A-Za-z_]\w*)\s*\[([^\]]+)\]', t):
            arr, idx = m.group(1), m.group(2)
            prog[pc] = Instr("INDEX", (arr, idx)); pc += 1

    if check_npe:
        for m in re.finditer(r'([A-Za-z_]\w*)\s*\.\s*[A-Za-z_]\w*', t):
            obj = m.group(1)
            prog[pc] = Instr("MEMBER", (obj,)); pc += 1

    prog[pc] = Instr("RET", ()); pc += 1
    return prog


@dataclass(frozen=True)
class Taint:
    kinds: Optional[frozenset]
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

FrameTag = Literal["ok","err"]


@dataclass
class AState:
    pc: int
    env: Dict[str, Taint] = field(default_factory=dict)
    facts: Dict[str, str] = field(default_factory=dict)
    tag: Optional[FrameTag] = "ok"
    def join(self, other:"AState")->"AState":
        assert self.pc == other.pc
        keys = set(self.env) | set(other.env)
        env = {k: self.env.get(k, Taint.bot()).join(other.env.get(k, Taint.bot())) for k in keys}
        tag = "err" if (self.tag=="err" or other.tag=="err") else "ok"
        return AState(self.pc, env, {}, tag)


def initial_env_from_params(params: List[str]) -> Dict[str, Taint]:
    return {p: Taint.t("param") for p in params}


_ID = re.compile(r'\b[A-Za-z_]\w*\b')
def eval_expr_taint(expr: str, s: AState) -> Taint:
    ids = _ID.findall(expr)
    if not ids: return Taint.u()
    out = Taint.u()
    for name in ids:
        out = out.join(s.env.get(name, Taint.u()))
    return out


SOURCE_FUNCS = (
    "readLine", "next", "nextInt", "nextLong", "nextLine", "getParameter",
    "getInput", "read", "recv", "receive"
)
SANITIZERS = ("parseInt", "parseLong")


def step_one(prog: 'Program', s: AState) -> Iterable[AState]:
    ins = prog.get(s.pc)
    if ins is None: return []
    op, args = ins.op, ins.args
    def nxt(pc, env=None, facts=None, tag=None):
        return AState(pc, env or dict(s.env), facts or dict(s.facts), tag or s.tag)
    if op == "ASSERT":
        cond, = args
        cond_taint = eval_expr_taint(cond, s)
        if not cond_taint.leq(Taint.u()):
            yield nxt(s.pc+1, tag="err")
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
        yield nxt(s.pc)  # terminal
    else:
        yield nxt(s.pc+1)


def bounded_run(prog: 'Program', depth: int, init_env: Optional[Dict[str, Taint]] = None) -> Dict[int, AState]:
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


def relational_bounded_run(prog: 'Program', depth: int, init_env: Optional[Dict[str, Any]] = None) -> Dict[int, Any]:
    """
    Run bounded analysis with relational abstract domain.
    Returns states enhanced with relational constraints.
    """
    if not _has_relational_domain:
        # Fallback to regular bounded run
        return bounded_run(prog, depth, init_env)
    
    try:
        # Convert regular states to EnhancedAState format
        enhanced_states = integrate_relational_domain(
            prog, depth, init_env, Taint, AState, step_one
        )
        
        # Convert back to regular AState format for compatibility
        regular_states = {}
        for pc, enhanced_state in enhanced_states.items():
            regular_state = AState(
                pc=enhanced_state.pc,
                env=enhanced_state.env,
                facts=enhanced_state.facts,
                tag=enhanced_state.tag
            )
            regular_states[pc] = regular_state
        
        return regular_states
    except Exception as e:
        sys.stderr.write(f"[bounded] relational analysis failed, falling back: {e}\n")
        return bounded_run(prog, depth, init_env)


def compute_scores(method_text: str, per_pc: Dict[int, AState], prog: 'Program')->Tuple[int,int,int,int,int,int]:
    src = method_text
    divide = 5; asserr = 5; oob = 5; npe = 5; inf = 5
    if re.search(r'\bassert\b', src): asserr = max(asserr, 40)
    if re.search(r"/\s*0\b", src): divide = 100
    elif re.search(r"/\s*[A-Za-z_]\w*", src): divide = max(divide, 40)
    if re.search(r"\[[^\]]+\]", src): oob = max(oob, 40)
    if re.search(r"\.\s*[A-Za-z_]\w*", src): npe = max(npe, 30)
    if re.search(r"while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)", src): inf = 100
    if any(st.tag == "err" for st in per_pc.values()):
        divide = max(divide, 55); oob = max(oob, 55); npe = max(npe, 40); asserr = max(asserr, 55)
    worst = max(divide, asserr, oob, npe, inf)
    ok = max(0, 100 - worst)
    return ok, divide, asserr, oob, npe, inf

INFO_LINES = (
    "Bounded AI",
    "0.3.0",
    "Group 20",
    "static,ai,bounded,taint,relational",
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
        print("usage: bounded.py info | bounded.py <Class.method:(desc)>", file=sys.stderr)
        sys.exit(2)

    try:
        cls, meth, desc, arity = _parse_method_id(sys.argv[1])
    except Exception:
        _print_defaults(); return

    src = read_source(cls)
    if not src:
        _print_defaults(); return
    
    # Try AST parsing first (tree-sitter) - this is the proper way
    method_ast = None
    ast_features = None
    params = []
    method_text = None
    prog = None
    syntax_hints = None  # Initialize for later use
    
    if _has_ast_parser:
        try:
            src_bytes = src.encode('utf-8')
            method_ast = parse_java_source(src_bytes, cls.split('.')[-1], meth, arity)
            if method_ast:
                params = method_ast.parameters
                method_text = method_ast.source_text
                ast_features = extract_ast_features(method_ast)
                prog = build_ir_from_ast(method_ast, ast_features)
                sys.stderr.write(f"[bounded] using AST parser (tree-sitter) for parsing\n")
                sys.stderr.write(f"[bounded] AST features: loops={ast_features['has_loops']}, asserts={ast_features['has_assertions']}, divs={ast_features['has_divisions']}\n")
                # Create syntax hints from AST features for scoring combination
                syntax_hints = {
                    'divide': 50 if ast_features['has_divisions'] else 5,
                    'assert': 50 if ast_features['has_assertions'] else 5,
                    'oob': 50 if ast_features['has_array_access'] else 5,
                    'npe': 50 if ast_features['has_member_access'] else 5,
                    'inf': 50 if ast_features['has_loops'] else 5,
                }
        except Exception as e:
            sys.stderr.write(f"[bounded] AST parsing failed: {e}\n")
            import traceback
            sys.stderr.write(traceback.format_exc() + "\n")
    
    # Fallback to regex-based extraction if AST parsing failed
    if not method_ast or not prog:
        sys.stderr.write(f"[bounded] falling back to regex-based extraction\n")
        method_text = extract_method_text(src, meth, arity)
        if not method_text:
            _print_defaults(); return
        
        # Use syntactic analyzer for parameter extraction if available (more robust)
        if _has_syntatic:
            try:
                params = list(syntatic_extract_parameters(method_text))
                sys.stderr.write(f"[bounded] using syntactic analyzer for parameter extraction\n")
            except Exception as e:
                sys.stderr.write(f"[bounded] syntactic parameter extraction failed, using fallback: {e}\n")
                params = extract_parameters(method_text)
        else:
            params = extract_parameters(method_text)
        
        if not method_text:
            _print_defaults(); return

        # Run syntactic analysis to get hints for IR building
        syntax_hints = None
        if _has_syntatic:
            try:
                syn_ok, syn_div, syn_asrt, syn_oob, syn_npe, syn_inf = syntatic_analyze(method_text)
                syntax_hints = {
                    'divide': syn_div,
                    'assert': syn_asrt,
                    'oob': syn_oob,
                    'npe': syn_npe,
                    'inf': syn_inf,
                }
                sys.stderr.write(f"[bounded] syntactic analysis: div={syn_div}, asrt={syn_asrt}, oob={syn_oob}, npe={syn_npe}, inf={syn_inf}\n")
            except Exception as e:
                sys.stderr.write(f"[bounded] syntactic analysis failed: {e}\n")
        
        prog = build_ir(method_text, params, syntax_hints)

    # Force-local import of novel_abstractions from same dir, log to STDERR
    enhanced_used = False
    try:
        HERE = os.path.dirname(os.path.abspath(__file__))
        if HERE not in sys.path:
            sys.path.insert(0, HERE)
        na = importlib.import_module("novel_abstractions")
        na = importlib.reload(na)
        sys.stderr.write(f"[bounded] using novel_abstractions from: {getattr(na, '__file__', '?')}\n")
        
        
        # Try to use relational domain WITH novel abstractions if both available
        if _has_relational_domain:
            sys.stderr.write("[bounded] using relational domain + novel abstractions\n")
            # Use novel_abstractions but with our enhanced step function
            states, loop_tracker = na.enhanced_bounded_run(
                prog,
                depth=8,
                init_env=initial_env_from_params(params),
                Taint=Taint,
                AState=EnhancedAState,  # Use enhanced state
                step_one_func=lambda prog, s: enhanced_step_one(prog, s, step_one)  # Use enhanced stepping
            )
        else:
            sys.stderr.write("[bounded] using novel_abstractions only\n")
            states, loop_tracker = na.enhanced_bounded_run(
                prog,
                depth=8,
                init_env=initial_env_from_params(params),
                Taint=Taint,
                AState=AState,
                step_one_func=step_one
            )
        
        scores_dict = na.compute_enhanced_scores(method_text, states, prog, loop_tracker)
        ai_ok, ai_div0, ai_asrt, ai_oob, ai_npe, ai_inf = (
            int(scores_dict.get("ok", 0)),
            int(scores_dict.get("div0", 0)),
            int(scores_dict.get("asrt", 0)),
            int(scores_dict.get("oob", 0)),
            int(scores_dict.get("npe", 0)),
            int(scores_dict.get("inf", 0)),
        )
        
        # Abstract interpreter is the primary scorer (the "brain")
        # Syntactic analysis is only used for guidance, not to override AI results
        # Start with AI results as the base
        div0, asrt, oob, npe, inf = ai_div0, ai_asrt, ai_oob, ai_npe, ai_inf
        ok = ai_ok
        
        if syntax_hints:
            syn_div = syntax_hints.get('divide', 5)
            syn_asrt = syntax_hints.get('assert', 5)
            syn_oob = syntax_hints.get('oob', 5)
            syn_npe = syntax_hints.get('npe', 5)
            syn_inf = syntax_hints.get('inf', 5)
            
            # Only override AI if syntactic found a definite pattern (100%) AND AI missed it (low score)
            # BUT: Don't override if AI detected an infinite loop (inf > 50) - code after loop is unreachable
            # This handles cases like literal "/ 0" or "assert false" that syntactic catches but AI might miss
            if syn_div == 100 and ai_div0 < 50 and ai_inf < 50:
                div0 = 100
                sys.stderr.write(f"[bounded] syntactic override: div=100 (AI had {ai_div0})\n")
            if syn_asrt == 100 and ai_asrt < 50 and ai_inf < 50:
                asrt = 100
                sys.stderr.write(f"[bounded] syntactic override: asrt=100 (AI had {ai_asrt})\n")
            if syn_inf == 100 and ai_inf < 50:
                inf = 100
                sys.stderr.write(f"[bounded] syntactic override: inf=100 (AI had {ai_inf})\n")
            
            # For other cases, trust AI results (they have better loop/taint analysis)
            # Only boost if syntactic is much higher and AI is very low
            # BUT: Don't boost errors after infinite loops (they're unreachable)
            if ai_inf < 50:  # Only boost if not an infinite loop
                if ai_div0 < 20 and syn_div > ai_div0 + 30:
                    div0 = min(syn_div, ai_div0 + 20)  # Small boost, don't override completely
                if ai_asrt < 20 and syn_asrt > ai_asrt + 30:
                    asrt = min(syn_asrt, ai_asrt + 20)
                if ai_oob < 20 and syn_oob > ai_oob + 30:
                    oob = min(syn_oob, ai_oob + 20)
                if ai_npe < 20 and syn_npe > ai_npe + 30:
                    npe = min(syn_npe, ai_npe + 20)
            if ai_inf < 20 and syn_inf > ai_inf + 30:
                inf = min(syn_inf, ai_inf + 20)
            
            # Recompute ok
            worst = max(div0, asrt, oob, npe, inf)
            ok = max(0, 100 - worst)
            sys.stderr.write(f"[bounded] final scores: ok={ok}, div={div0}, asrt={asrt}, oob={oob}, npe={npe}, inf={inf}\n")
        
        enhanced_used = True
        sys.stderr.write("[bounded] enhanced path OK\n")
    except Exception as e:
        sys.stderr.write(f"[bounded] enhanced path failed: {e}\n")
        import traceback
        sys.stderr.write(traceback.format_exc() + "\n")
        states = bounded_run(prog, depth=5, init_env=initial_env_from_params(params))
        # If we have syntactic analysis, combine it with basic AI
        if syntax_hints:
            syn_ok, syn_div, syn_asrt, syn_oob, syn_npe, syn_inf = (
                100 - max(syntax_hints.get('divide', 5), syntax_hints.get('assert', 5), 
                         syntax_hints.get('oob', 5), syntax_hints.get('npe', 5), syntax_hints.get('inf', 5)),
                syntax_hints.get('divide', 5),
                syntax_hints.get('assert', 5),
                syntax_hints.get('oob', 5),
                syntax_hints.get('npe', 5),
                syntax_hints.get('inf', 5),
            )
            ai_ok, ai_div0, ai_asrt, ai_oob, ai_npe, ai_inf = compute_scores(method_text, states, prog)
            div0 = max(syn_div, ai_div0)
            asrt = max(syn_asrt, ai_asrt)
            oob = max(syn_oob, ai_oob)
            npe = max(syn_npe, ai_npe)
            inf = max(syn_inf, ai_inf)
            worst = max(div0, asrt, oob, npe, inf)
            ok = max(0, 100 - worst)
        else:
            ok, div0, asrt, oob, npe, inf = compute_scores(method_text, states, prog)

    except Exception as e:
        sys.stderr.write(f"[bounded] enhanced path failed: {e}\n")
        import traceback
        sys.stderr.write(traceback.format_exc() + "\n")
        states = bounded_run(prog, depth=5, init_env=initial_env_from_params(params))
        # If we have syntactic analysis, combine it with basic AI
        if syntax_hints:
            syn_ok, syn_div, syn_asrt, syn_oob, syn_npe, syn_inf = (
                100 - max(syntax_hints.get('divide', 5), syntax_hints.get('assert', 5), 
                         syntax_hints.get('oob', 5), syntax_hints.get('npe', 5), syntax_hints.get('inf', 5)),
                syntax_hints.get('divide', 5),
                syntax_hints.get('assert', 5),
                syntax_hints.get('oob', 5),
                syntax_hints.get('npe', 5),
                syntax_hints.get('inf', 5),
            )
            ai_ok, ai_div0, ai_asrt, ai_oob, ai_npe, ai_inf = compute_scores(method_text, states, prog)
            div0 = max(syn_div, ai_div0)
            asrt = max(syn_asrt, ai_asrt)
            oob = max(syn_oob, ai_oob)
            npe = max(syn_npe, ai_npe)
            inf = max(syn_inf, ai_inf)
            worst = max(div0, asrt, oob, npe, inf)
            ok = max(0, 100 - worst)
        else:
            ok, div0, asrt, oob, npe, inf = compute_scores(method_text, states, prog)

    print(f"ok;{ok}%")
    print(f"divide by zero;{div0}%")
    print(f"assertion error;{asrt}%")
    print(f"out of bounds;{oob}%")
    print(f"null pointer;{npe}%")
    print(f"*;{inf}%")


if __name__ == "__main__":
    main()
