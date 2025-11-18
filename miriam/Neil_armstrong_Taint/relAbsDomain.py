#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Relational Abstract Domain (Simplified Octagons/Zones)
-----------------------------------------------------
Tracks relational constraints between variables to prove safety properties:
- x != 0 for division safety
- x < y for bounds checking  
- x == y + c for value relationships
- Proper joining of constraints across paths

Integrated with the existing bounded abstract interpreter.
"""

from dataclasses import dataclass, field
from typing import Dict, Set, List, Tuple, Optional, Any, FrozenSet
import re
from collections import defaultdict

@dataclass(frozen=True)
class LinearExpr:
    """Represents a linear expression: c0 + c1*x1 + c2*x2 + ..."""
    coefficients: Dict[str, int] = field(default_factory=dict)  # variable -> coefficient
    constant: int = 0
    
    def __post_init__(self):
        # Remove zero coefficients
        zero_vars = [var for var, coef in self.coefficients.items() if coef == 0]
        for var in zero_vars:
            object.__setattr__(self, 'coefficients', {k: v for k, v in self.coefficients.items() if v != 0})
    
    @classmethod
    def from_var(cls, var: str, coef: int = 1) -> 'LinearExpr':
        return cls(coefficients={var: coef})
    
    @classmethod
    def from_constant(cls, constant: int) -> 'LinearExpr':
        return cls(constant=constant)
    
    def __add__(self, other: 'LinearExpr') -> 'LinearExpr':
        coefs = defaultdict(int)
        for var, coef in self.coefficients.items():
            coefs[var] += coef
        for var, coef in other.coefficients.items():
            coefs[var] += coef
        return LinearExpr(
            coefficients=dict(coefs),
            constant=self.constant + other.constant
        )
    
    def __sub__(self, other: 'LinearExpr') -> 'LinearExpr':
        return self + (other * -1)
    
    def __mul__(self, scalar: int) -> 'LinearExpr':
        return LinearExpr(
            coefficients={var: coef * scalar for var, coef in self.coefficients.items()},
            constant=self.constant * scalar
        )
    
    def __rmul__(self, scalar: int) -> 'LinearExpr':
        return self * scalar
    
    def vars(self) -> Set[str]:
        return set(self.coefficients.keys())
    
    def evaluate(self, env: Dict[str, int]) -> int:
        """Evaluate with given variable values (for testing)"""
        result = self.constant
        for var, coef in self.coefficients.items():
            result += env.get(var, 0) * coef
        return result

@dataclass(frozen=True)
class Constraint:
    """Represents a constraint: expr1 <= expr2 or expr1 == expr2"""
    left: LinearExpr
    right: LinearExpr
    is_equality: bool = False
    
    def normalize(self) -> 'Constraint':
        """Convert to canonical form: expr <= 0 or expr == 0"""
        diff = self.left - self.right
        return Constraint(
            left=diff,
            right=LinearExpr.from_constant(0),
            is_equality=self.is_equality
        )
    
    def vars(self) -> Set[str]:
        return self.left.vars() | self.right.vars()
    
    def __str__(self) -> str:
        normalized = self.normalize()
        if normalized.is_equality:
            return f"{normalized.left} == 0"
        else:
            return f"{normalized.left} <= 0"

class RelationalState:
    """
    Tracks relational constraints using a simplified octagon domain.
    Maintains constraints of form: ±x ± y ≤ c and x == y + c
    """
    
    def __init__(self, constraints: Optional[Set[Constraint]] = None):
        self.constraints: Set[Constraint] = constraints or set()
        self._normalize_constraints()
    
    def _normalize_constraints(self):
        """Normalize all constraints and remove redundancies"""
        normalized = set()
        for constraint in self.constraints:
            normalized.add(constraint.normalize())
        self.constraints = self._remove_redundant(normalized)
    
    def _remove_redundant(self, constraints: Set[Constraint]) -> Set[Constraint]:
        """Remove obviously redundant constraints"""
        # Simple redundancy removal - in practice would use more sophisticated methods
        result = set()
        constraint_dict = {}
        
        for c in constraints:
            key = (frozenset(c.left.coefficients.items()), c.left.constant, c.is_equality)
            # Keep the tightest bound for inequalities
            if key not in constraint_dict:
                constraint_dict[key] = c
            elif not c.is_equality:
                # For inequalities, we might want to keep the tighter bound
                # This is simplified - real implementation would compare bounds
                pass
        
        return set(constraint_dict.values())
    
    def add_constraint(self, constraint: Constraint) -> 'RelationalState':
        """Add a new constraint and return updated state"""
        new_constraints = self.constraints | {constraint.normalize()}
        return RelationalState(new_constraints)
    
    def implies(self, constraint: Constraint) -> bool:
        """
        Check if the current state implies the given constraint.
        This is a simplified implementation - real octagon would use Floyd-Warshall.
        """
        test_constraint = constraint.normalize()
        
        # Quick checks for common patterns
        if test_constraint.is_equality:
            return self._implies_equality(test_constraint)
        else:
            return self._implies_inequality(test_constraint)
    
    def _implies_equality(self, constraint: Constraint) -> bool:
        """Check if we can prove an equality constraint"""
        # Look for direct equality in our constraints
        for c in self.constraints:
            if c.is_equality and c.left.coefficients == constraint.left.coefficients:
                return c.left.constant == constraint.left.constant
        return False
    
    def _implies_inequality(self, constraint: Constraint) -> bool:
        """Check if we can prove an inequality constraint"""
        # Simplified implication checking
        # In practice, this would use the octagon closure
        expr = constraint.left
        vars_in_expr = expr.vars()
        
        # For single variable constraints like x <= 0
        if len(vars_in_expr) == 1:
            var = next(iter(vars_in_expr))
            coef = expr.coefficients[var]
            
            # Look for bounds on this variable
            for c in self.constraints:
                if len(c.left.vars()) == 1 and var in c.left.vars():
                    if c.is_equality:
                        # If we know x == k, check if k <= 0
                        if coef * (-c.left.constant) <= 0:
                            return True
                    else:
                        # If we know x <= k, check if k <= 0
                        if coef * c.left.constant <= 0:
                            return True
        
        return False
    
    def join(self, other: 'RelationalState') -> 'RelationalState':
        """Join two relational states (find common constraints)"""
        if not self.constraints:
            return other
        if not other.constraints:
            return self
        
        # Keep constraints that appear in both states
        common_constraints = self.constraints & other.constraints
        
        # Also keep constraints that are implied by both states
        # This is simplified - real implementation would be more sophisticated
        for c in self.constraints:
            if other.implies(c):
                common_constraints.add(c)
        for c in other.constraints:
            if self.implies(c):
                common_constraints.add(c)
        
        return RelationalState(common_constraints)
    
    def is_bottom(self) -> bool:
        """Check for contradictions"""
        # Look for x <= c and x <= d where c and d contradict
        # Simplified contradiction detection
        var_bounds = defaultdict(list)
        
        for c in self.constraints:
            if len(c.left.vars()) == 1:
                var = next(iter(c.left.vars()))
                coef = c.left.coefficients[var]
                bound = -c.left.constant  # because we normalized to expr <= 0
                
                if c.is_equality:
                    var_bounds[var].append(('eq', bound * coef))
                else:
                    var_bounds[var].append(('le', bound * coef))
        
        # Check for contradictions
        for var, bounds in var_bounds.items():
            equalities = [b for typ, b in bounds if typ == 'eq']
            inequalities = [b for typ, b in bounds if typ == 'le']
            
            # Multiple different equalities
            if len(set(equalities)) > 1:
                return True
            
            # Equality contradicts inequality
            for eq in equalities:
                for le in inequalities:
                    if eq > le:
                        return True
            
            # Inconsistent inequalities
            if inequalities and min(inequalities) < max(inequalities):
                # This doesn't necessarily mean contradiction, but if we have
                # x <= 5 and x <= 3, that's fine. We need x <= c and x >= d with c < d
                pass
        
        return False

# Pattern matching for common Java expressions
class ConstraintExtractor:
    """Extracts relational constraints from Java expressions"""
    
    @staticmethod
    def from_condition(cond: str, negated: bool = False) -> List[Constraint]:
        """
        Extract constraints from a Java boolean condition.
        Returns list of Constraint objects.
        """
        constraints = []
        cond = cond.strip()
        
        # Handle compound conditions with && and ||
        # For now, we'll handle simple conditions
        if "&&" in cond or "||" in cond:
            # For complex conditions, extract from each simple part
            parts = re.split(r'\s*\|\|\s*', cond)  # Very simplified
            for part in parts:
                constraints.extend(ConstraintExtractor._from_simple_condition(part, negated))
        else:
            constraints.extend(ConstraintExtractor._from_simple_condition(cond, negated))
        
        return constraints
    
    @staticmethod
    def _from_simple_condition(cond: str, negated: bool = False) -> List[Constraint]:
        """Extract from a simple condition without && or ||"""
        patterns = [
            # x != y, x != 0
            (r'(\w+)\s*!=\s*(\w+|\d+)', '!='),
            # x == y, x == 0  
            (r'(\w+)\s*==\s*(\w+|\d+)', '=='),
            # x < y, x < 5
            (r'(\w+)\s*<\s*(\w+|\d+)', '<'),
            # x > y, x > 5
            (r'(\w+)\s*>\s*(\w+|\d+)', '>'),
            # x <= y, x <= 5
            (r'(\w+)\s*<=\s*(\w+|\d+)', '<='),
            # x >= y, x >= 5
            (r'(\w+)\s*>=\s*(\w+|\d+)', '>='),
        ]
        
        constraints = []
        
        for pattern, op in patterns:
            matches = list(re.finditer(pattern, cond))
            for match in matches:
                left, right = match.group(1), match.group(2)
                
                # Apply negation
                if negated:
                    if op == '!=': op = '=='
                    elif op == '==': op = '!='
                    elif op == '<': op = '>='
                    elif op == '>': op = '<='
                    elif op == '<=': op = '>'
                    elif op == '>=': op = '<'
                
                constraints.extend(ConstraintExtractor._create_constraint(left, right, op))
        
        return constraints
    
    @staticmethod
    def _create_constraint(left: str, right: str, op: str) -> List[Constraint]:
        """Create constraint objects from parsed operation"""
        try:
            right_val = int(right)
            right_expr = LinearExpr.from_constant(right_val)
        except ValueError:
            right_expr = LinearExpr.from_var(right)
        
        left_expr = LinearExpr.from_var(left)
        
        if op == '==':
            return [Constraint(left_expr, right_expr, is_equality=True)]
        elif op == '!=':
            # x != y is not directly representable in our simple domain
            # We'll track it as a special fact for now
            return []
        elif op == '<':
            return [Constraint(left_expr, right_expr - LinearExpr.from_constant(1))]
        elif op == '<=':
            return [Constraint(left_expr, right_expr)]
        elif op == '>':
            return [Constraint(right_expr, left_expr - LinearExpr.from_constant(1))]
        elif op == '>=':
            return [Constraint(right_expr, left_expr)]
        
        return []

# Enhanced AState with relational information
@dataclass
class EnhancedAState:
    """Augmented abstract state with relational constraints"""
    pc: int
    env: Dict[str, Any]  # Existing taint information
    facts: Dict[str, str]  # Existing simple facts
    relational: RelationalState  # New relational constraints
    tag: Optional[str] = "ok"
    
    def join(self, other: 'EnhancedAState') -> 'EnhancedAState':
        """Join two enhanced states"""
        assert self.pc == other.pc
        
        # Join existing components
        keys = set(self.env.keys()) | set(other.env.keys())
        env = {k: self.env.get(k, None).join(other.env.get(k, None)) 
               for k in keys if self.env.get(k) and other.env.get(k)}
        
        # For facts, we take intersection (keep only common facts)
        facts = {}
        for k, v in self.facts.items():
            if k in other.facts and other.facts[k] == v:
                facts[k] = v
        
        # Join relational states
        relational = self.relational.join(other.relational)
        
        tag = "err" if (self.tag == "err" or other.tag == "err") else "ok"
        
        return EnhancedAState(self.pc, env, facts, relational, tag)
    
    def add_constraint(self, constraint: Constraint) -> 'EnhancedAState':
        """Add a constraint to the relational state"""
        new_relational = self.relational.add_constraint(constraint)
        return EnhancedAState(self.pc, self.env, self.facts, new_relational, self.tag)
    
    def implies(self, constraint: Constraint) -> bool:
        """Check if this state implies the given constraint"""
        return self.relational.implies(constraint)
    
    def prove_non_zero(self, var: str) -> bool:
        """Check if we can prove var != 0"""
        # Try to prove var <= -1 or var >= 1
        var_expr = LinearExpr.from_var(var)
        neg_one = LinearExpr.from_constant(-1)
        one = LinearExpr.from_constant(1)
        
        return (self.implies(Constraint(var_expr, neg_one)) or 
                self.implies(Constraint(one, var_expr)))
    
    def prove_positive(self, var: str) -> bool:
        """Check if we can prove var > 0"""
        zero = LinearExpr.from_constant(0)
        var_expr = LinearExpr.from_var(var)
        return self.implies(Constraint(zero, var_expr - LinearExpr.from_constant(1)))

# Integration with existing interpreter
def enhanced_step_one(prog, s: EnhancedAState, step_one_func) -> List[EnhancedAState]:
    """
    Enhanced step function that maintains relational constraints.
    """
    base_states = list(step_one_func(prog, s))
    enhanced_states = []
    
    for base_state in base_states:
        # Convert base state to enhanced state
        enhanced_state = EnhancedAState(
            pc=base_state.pc,
            env=base_state.env,
            facts=base_state.facts,
            relational=s.relational,  # Carry forward relational state
            tag=base_state.tag
        )
        
        # Extract constraints from the current instruction
        ins = prog.get(s.pc)
        if ins:
            enhanced_state = _extract_constraints_from_instruction(ins, enhanced_state)
        
        enhanced_states.append(enhanced_state)
    
    return enhanced_states

def _extract_constraints_from_instruction(ins, state: EnhancedAState) -> EnhancedAState:
    """Extract relational constraints from instruction"""
    op, args = ins.op, ins.args
    
    if op == "IF":
        cond, _ = args
        # Extract constraints from the condition (true branch)
        constraints = ConstraintExtractor.from_condition(cond, negated=False)
        for constraint in constraints:
            state = state.add_constraint(constraint)
    
    elif op == "ASSERT":
        cond, = args
        # Extract constraints from assertion condition
        constraints = ConstraintExtractor.from_condition(cond, negated=False)
        for constraint in constraints:
            state = state.add_constraint(constraint)
    
    elif op == "ASSIGN":
        var, expr = args
        # Try to extract linear assignments: x = y + 5, etc.
        match = re.match(r'(\w+)\s*([+\-])\s*(\d+)', expr.strip())
        if match:
            other_var, op, constant = match.groups()
            const_val = int(constant)
            if op == '-':
                const_val = -const_val
            
            # Create equality constraint: var == other_var + const_val
            left = LinearExpr.from_var(var)
            right = LinearExpr.from_var(other_var) + LinearExpr.from_constant(const_val)
            constraint = Constraint(left, right, is_equality=True)
            state = state.add_constraint(constraint)
    
    return state

# Enhanced safety checks using relational domain
def enhanced_safety_checks(state: EnhancedAState, ins) -> Optional[str]:
    """
    Use relational constraints to prove safety of operations.
    Returns "err" if unsafe, None if safe or unknown.
    """
    op, args = ins.op, ins.args
    
    if op == "DIV":
        _, b = args
        # Try to prove denominator is non-zero
        if state.prove_non_zero(b):
            return None  # Safe
        # If we can't prove it's non-zero, be conservative
        return "err"
    
    elif op == "INDEX":
        arr, idx = args
        # For now, simple check - could be enhanced with array bounds
        if state.prove_positive(idx):
            return None  # At least positive
        return "err"
    
    elif op == "MEMBER":
        obj, = args
        # Could track nullness relations here
        return "err"  # Conservative
    
    return None  # Unknown or not applicable

def integrate_relational_domain(prog, depth: int, init_env, Taint, AState, step_one_func):
    """
    Main integration function that runs the interpreter with relational domain.
    """
    # Convert initial state to enhanced state
    init_enhanced = EnhancedAState(
        pc=0,
        env=init_env,
        facts={},
        relational=RelationalState(),
        tag="ok"
    )
    
    per_pc = {0: init_enhanced}
    
    for _ in range(depth):
        next_map = {}
        for pc, st in per_pc.items():
            for s2 in enhanced_step_one(prog, st, step_one_func):
                # Apply enhanced safety checks
                ins = prog.get(st.pc)
                if ins:
                    safety_tag = enhanced_safety_checks(s2, ins)
                    if safety_tag == "err":
                        s2 = EnhancedAState(s2.pc, s2.env, s2.facts, s2.relational, "err")
                
                if s2.pc in next_map:
                    next_map[s2.pc] = next_map[s2.pc].join(s2)
                else:
                    next_map[s2.pc] = s2
        
        per_pc = next_map
        if not per_pc:
            break
    
    return per_pc

# Export the main integration function
__all__ = ['integrate_relational_domain', 'EnhancedAState', 'RelationalState', 'Constraint']