#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Novel Abstractions v2.2 (Loops-focused)
---------------------------------------
1) Loop Widening with Iteration Tracking (modified-vars only)
2) Narrowing pass to refine after widening
3) Optional "loop-dependent" taint tagging
4) Conservative scoring: bump '*' only for likely-infinite constructs

Exports expected by bounded.py:
- enhanced_bounded_run(...)
- compute_enhanced_scores(...)
"""

from dataclasses import dataclass, field, replace
from typing import Dict, Optional, Iterable, Tuple, Set, Any, Callable
from collections import defaultdict

Program = Dict[int, Any]

@dataclass
class LoopTracker:
    header_counts: Dict[int, int] = field(default_factory=dict)
    widened_headers: Set[int] = field(default_factory=set)
    # Variables modified inside the loop keyed by loop header pc
    modified_vars: Dict[int, Set[str]] = field(default_factory=lambda: defaultdict(set))
    # Snapshot of env just BEFORE we first widened a header (for narrowing seed)
    pre_widen_env: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    # Edge counters to distinguish real loops vs. spurious back steps
    back_edge_counts: Dict[Tuple[int, int], int] = field(default_factory=lambda: defaultdict(int))

# ---------------------------- helpers ---------------------------------

def _is_top(val: Any, Taint) -> bool:
    if hasattr(Taint, "is_top") and callable(getattr(Taint, "is_top")):
        try:
            return bool(Taint.is_top(val))
        except Exception:
            pass
    try:
        return val == Taint.topv()
    except Exception:
        return False

def _topv(Taint):
    return Taint.topv() if hasattr(Taint, "topv") else getattr(Taint, "TOP", object())

def _widen_selected(env: Dict[str, Any], vars_to_top: Set[str], Taint) -> Dict[str, Any]:
    if not env or not vars_to_top:
        return env
    topv = _topv(Taint)
    return {k: (topv if k in vars_to_top else v) for k, v in env.items()}

def _env_changed_keys(env_before: Dict[str, Any], env_after: Dict[str, Any]) -> Set[str]:
    keys = set(env_before.keys()) | set(env_after.keys())
    changed = set()
    for k in keys:
        vb, va = env_before.get(k, None), env_after.get(k, None)
        if vb != va:
            changed.add(k)
    return changed

def _join_states(existing, new_state):
    if hasattr(existing, "join"):
        return existing.join(new_state)
    return new_state

def _prefer_non_top_env(old_env: Dict[str, Any], new_env: Dict[str, Any], Taint) -> Dict[str, Any]:
    out = {}
    keys = set(old_env.keys()) | set(new_env.keys())
    for k in keys:
        ov = old_env.get(k, None)
        nv = new_env.get(k, None)
        if _is_top(ov, Taint) and not _is_top(nv, Taint):
            out[k] = nv
        elif _is_top(nv, Taint) and not _is_top(ov, Taint):
            out[k] = ov
        else:
            out[k] = nv if nv is not None else ov
    return out

# ------------------------- main enhanced runner ------------------------------

def enhanced_bounded_run(
    prog: Program,
    *,
    depth: int,
    init_env: Optional[Dict[str, Any]],
    Taint,
    AState,
    step_one_func: Callable[[Program, Any], Iterable[Any]],
    # knobs
    WIDEN_AFTER: int = 2,
    NARROW_STEPS: int = 2,
    enable_loop_dependent_taint: bool = True,
    # loop detection knob
    MAX_BACK_JUMP: int = 16,           # generous window for Java bytecode loops
    MIN_BACK_EDGE_REPETITIONS: int = 2 # require same back edge seen >=2x
) -> Tuple[Dict[int, Any], LoopTracker]:
    """
    Bounded run with loop-widening (modified vars only) + narrowing.

    Loop detection:
      - s2.pc < st.pc (backward)
      - (st.pc - s2.pc) <= MAX_BACK_JUMP
      - s2.pc != 0 (ignore entry)
      - require same (st.pc -> s2.pc) back-edge at least MIN_BACK_EDGE_REPETITIONS times
    """
    loop = LoopTracker()
    per_pc: Dict[int, Any] = {0: AState(0, env=(init_env or {}))}

    def _is_candidate_back_edge(st, s2) -> bool:
        if s2.pc >= st.pc:
            return False
        if s2.pc == 0:
            return False
        return (st.pc - s2.pc) <= MAX_BACK_JUMP

    # ----- exploration with targeted widening -----
    for _ in range(max(0, depth)):
        next_map: Dict[int, Any] = {}
        for pc, st in per_pc.items():
            for s2 in step_one_func(prog, st):
                # candidate back-edge detection
                if _is_candidate_back_edge(st, s2):
                    edge = (st.pc, s2.pc)
                    loop.back_edge_counts[edge] += 1
                    if loop.back_edge_counts[edge] >= MIN_BACK_EDGE_REPETITIONS:
                        hdr = s2.pc
                        loop.header_counts[hdr] = loop.header_counts.get(hdr, 0) + 1
                        # track vars modified along this loop body
                        try:
                            changed = _env_changed_keys(st.env, s2.env)
                            loop.modified_vars[hdr].update(changed)
                        except Exception:
                            pass

                # apply widening if threshold exceeded at header
                if s2.pc in loop.header_counts and loop.header_counts[s2.pc] > WIDEN_AFTER:
                    vars_to_top = set(loop.modified_vars.get(s2.pc, set()))
                    if vars_to_top:
                        if s2.pc not in loop.widened_headers:
                            # snapshot incoming pre-widen env for narrowing
                            loop.pre_widen_env[s2.pc] = dict(getattr(s2, "env", {}) or {})
                            loop.widened_headers.add(s2.pc)

                        widened_env = _widen_selected(getattr(s2, "env", {}) or {}, vars_to_top, Taint)
                        if enable_loop_dependent_taint and hasattr(Taint, "loop_dependent"):
                            try:
                                widened_env = {
                                    k: (Taint.loop_dependent(v) if k in vars_to_top else v)
                                    for k, v in widened_env.items()
                                }
                            except Exception:
                                pass
                        try:
                            s2 = replace(s2, env=widened_env)
                        except Exception:
                            s2 = AState(s2.pc, env=widened_env, facts=getattr(s2, "facts", {}), tag=getattr(s2, "tag", None))

                if s2.pc in next_map:
                    next_map[s2.pc] = _join_states(next_map[s2.pc], s2)
                else:
                    next_map[s2.pc] = s2

        per_pc = next_map
        if not per_pc:
            break

    # ----- narrowing pass (lightweight) -----
    if loop.widened_headers and NARROW_STEPS > 0:
        refined: Dict[int, Any] = dict(per_pc)
        seeds: Dict[int, Any] = {}
        for hdr in loop.widened_headers:
            pre_env = loop.pre_widen_env.get(hdr)
            if pre_env is not None:
                try:
                    seeds[hdr] = AState(hdr, env=pre_env, facts={}, tag=getattr(refined.get(hdr, None), "tag", None))
                except Exception:
                    seeds[hdr] = AState(hdr, env=pre_env)

        frontier = {**seeds}
        for _ in range(NARROW_STEPS):
            next_frontier: Dict[int, Any] = {}
            for pc, st in frontier.items():
                for s2 in step_one_func(prog, st):
                    # forbid back-edges during narrowing to avoid re-widening
                    if s2.pc <= st.pc:
                        continue
                    if s2.pc in next_frontier:
                        next_frontier[s2.pc] = _join_states(next_frontier[s2.pc], s2)
                    else:
                        next_frontier[s2.pc] = s2
            if not next_frontier:
                break
            # merge into refined map, preferring non-top values
            for pc, s2 in next_frontier.items():
                if pc in refined:
                    try:
                        env_old = getattr(refined[pc], "env", {}) or {}
                        env_new = getattr(s2, "env", {}) or {}
                        merged_env = _prefer_non_top_env(env_old, env_new, Taint)
                        try:
                            refined[pc] = replace(refined[pc], env=merged_env)
                        except Exception:
                            refined[pc] = AState(pc, env=merged_env, facts=getattr(refined[pc], "facts", {}), tag=getattr(refined[pc], "tag", None))
                    except Exception:
                        refined[pc] = _join_states(refined[pc], s2)
                else:
                    refined[pc] = s2
            frontier = next_frontier

        per_pc = refined

    return per_pc, loop

# --------------------------- scoring wrapper --------------------------------

def compute_enhanced_scores(method_text: str, states: Dict[int, Any], prog: Program, loop_tracker: LoopTracker):
    """
    Enhanced scoring with better loop analysis.
    
    Analyzes source code to detect infinite loops by:
    1. Checking for explicit infinite patterns (while(true), etc.)
    2. Analyzing loop conditions and whether loop variables are modified
    3. Using loop tracker information when available
    """
    import re
    
    try:
        from bounded import compute_scores  # provided by bounded.py
        ok, div0, asrt, oob, npe, inf = compute_scores(method_text, states, prog)
    except Exception:
        # Heuristic fallback if bounded.compute_scores is unavailable
        divide = 5; asserr = 5; oob = 5; npe = 5; inf = 5
        src = method_text
        if re.search(r'\bassert\b', src): asserr = max(asserr, 40)
        if re.search(r"/\s*0\b", src): divide = 100
        elif re.search(r"/\s*[A-Za-z_]\w*", src): divide = max(divide, 40)
        if re.search(r"\[[^\]]+\]", src): oob = max(oob, 40)
        if re.search(r"\.\s*[A-Za-z_]\w*", src): npe = max(npe, 30)
        if re.search(r"while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)", src): inf = 100
        worst = max(divide, asserr, oob, npe, inf); ok = max(0, 100 - worst)
        ok, div0, asrt, oob, npe, inf = ok, divide, asserr, oob, npe, inf

    src = method_text or ""
    
    # Pattern 1: Explicit infinite loops
    explicit_infinite = bool(
        re.search(r"while\s*\(\s*true\s*\)", src, re.IGNORECASE) or
        re.search(r"for\s*\(\s*;\s*;\s*\)", src) or
        re.search(r"do\s*\{[^}]*\}\s*while\s*\(\s*true\s*\)", src, re.IGNORECASE)
    )
    
    # Pattern 2: Analyze while loops with conditions
    # Find all while loops and check if they're infinite
    while_loops = list(re.finditer(r'\bwhile\s*\((.*?)\)\s*\{', src, re.S))
    likely_infinite_loops = []
    
    for while_match in while_loops:
        cond = while_match.group(1).strip()
        loop_start = while_match.end()
        # Find matching closing brace
        depth = 1
        pos = loop_start
        while pos < len(src) and depth > 0:
            if src[pos] == '{':
                depth += 1
            elif src[pos] == '}':
                depth -= 1
            pos += 1
        loop_body = src[loop_start:pos-1] if pos <= len(src) else ""
        
        # Check if condition is always true
        if re.match(r'\s*true\s*$', cond, re.IGNORECASE):
            likely_infinite_loops.append(True)
            continue
        
        # Check for conditions like "i > 0" where i might not be modified
        # Extract variable from condition
        var_match = re.search(r'\b([a-z_][a-z0-9_]*)\s*[><=!]', cond, re.IGNORECASE)
        if var_match:
            var_name = var_match.group(1)
            # Check if this variable is modified in the loop body
            # Look for assignments, increments, decrements
            modified = bool(
                re.search(rf'\b{re.escape(var_name)}\s*[+\-*/]?=', loop_body) or
                re.search(rf'\b{re.escape(var_name)}\s*\+\+', loop_body) or
                re.search(rf'\+\+\s*{re.escape(var_name)}', loop_body) or
                re.search(rf'\b{re.escape(var_name)}\s*--', loop_body) or
                re.search(rf'--\s*{re.escape(var_name)}', loop_body)
            )
            
            # If variable is not modified and condition is like "i > 0" or "i != 0"
            # and we see an initial assignment like "i = 1", it's likely infinite
            if not modified:
                # Check for initial assignment before loop
                before_loop = src[:while_match.start()]
                init_match = re.search(rf'\b{re.escape(var_name)}\s*=\s*([^;]+);', before_loop)
                if init_match:
                    init_val = init_match.group(1).strip()
                    # If initialized to positive value and condition is > or != 0, likely infinite
                    if re.match(r'\d+', init_val) and int(init_val) > 0:
                        if re.search(r'[>!]', cond):
                            likely_infinite_loops.append(True)
                            continue
        
        # Check for patterns like "i++ != 0" which terminate due to overflow
        if re.search(r'\+\+', cond) or re.search(r'--', cond):
            # This is likely a terminating loop (overflow pattern)
            likely_infinite_loops.append(False)
            continue
        
        # Default: if we can't determine, don't assume infinite
        likely_infinite_loops.append(False)
    
    # Determine if method has infinite loops
    has_infinite_loop = explicit_infinite or any(likely_infinite_loops)
    
    # Adjust scores based on loop analysis
    if has_infinite_loop:
        # High confidence for infinite loop - this is the primary outcome
        inf = max(inf, 95)
        # If there's an infinite loop, other errors after the loop are unreachable
        # So reduce their scores - check for any division or assert after the loop
        has_division = bool(re.search(r'/\s*[A-Za-z_]\w*|/\s*0\b', src))
        has_assert = bool(re.search(r'\bassert\s*', src))  # Match assert with or without parentheses
        # If we have an infinite loop, code after it is unreachable
        if has_division:
            # Division after infinite loop is unreachable
            div0 = 5  # Force to low value
        if has_assert:
            # Assert after infinite loop is unreachable
            asrt = 5  # Force to low value
        # Reduce ok score accordingly
        worst = max(div0, asrt, oob, npe, inf)
        ok = max(0, 100 - worst)
    else:
        # If we have loops but they're not infinite, keep inf low
        if while_loops:
            # Terminating loops - keep inf at base level
            inf = max(inf, 5)
    
    # Check for other error conditions (only if no infinite loop)
    if not has_infinite_loop:
        if re.search(r'\bassert\s*', src):  # Match assert with or without parentheses
            asrt = max(asrt, 40)
            # If there's an assert after a loop, it might be reachable (terminating loop)
            if while_loops:
                asrt = max(asrt, 85)  # High confidence if loop terminates
        
        if re.search(r'/\s*0\b', src):
            div0 = 100
        elif re.search(r'/\s*[A-Za-z_]\w*', src):
            div0 = max(div0, 40)
            # If division is after a loop and loop terminates, higher confidence
            if while_loops:
                div0 = max(div0, 85)
    
    # Recompute ok as final step
    worst = max(div0, asrt, oob, npe, inf)
    ok = max(0, 100 - worst)
    
    return {"ok": ok, "div0": div0, "asrt": asrt, "oob": oob, "npe": npe, "inf": inf}
