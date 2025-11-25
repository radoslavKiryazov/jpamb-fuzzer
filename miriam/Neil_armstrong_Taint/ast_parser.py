#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AST/CST Parser using tree-sitter for Java
Extracts structured syntax trees and feeds them to the abstract interpreter
"""

import os
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass

try:
    import tree_sitter
    import tree_sitter_java
    _has_tree_sitter = True
    JAVA_LANGUAGE = tree_sitter.Language(tree_sitter_java.language())
    PARSER = tree_sitter.Parser(JAVA_LANGUAGE)
except ImportError:
    _has_tree_sitter = False
    JAVA_LANGUAGE = None
    PARSER = None


@dataclass
class ASTNode:
    """Represents an AST node with its type and children"""
    node_type: str
    text: str
    start_byte: int
    end_byte: int
    children: List['ASTNode']
    parent: Optional['ASTNode'] = None
    
    @classmethod
    def from_tree_sitter(cls, ts_node, parent=None):
        """Convert tree-sitter node to ASTNode"""
        children = []
        for i in range(ts_node.child_count):
            child = ts_node.child(i)
            if child:
                ast_child = cls.from_tree_sitter(child, parent=None)
                ast_child.parent = parent
                children.append(ast_child)
        
        return cls(
            node_type=ts_node.type,
            text=ts_node.text.decode('utf-8') if ts_node.text else '',
            start_byte=ts_node.start_byte,
            end_byte=ts_node.end_byte,
            children=children,
            parent=parent
        )

@dataclass
class MethodAST:
    """Complete AST for a method"""
    name: str
    parameters: List[str]  # Parameter names
    return_type: Optional[str]
    body: ASTNode  # The method body AST
    full_ast: ASTNode  # Complete method declaration AST
    source_text: str  # Original source text

def parse_java_source(java_source: bytes, class_name: str, method_name: str, arity: int) -> Optional[MethodAST]:
    """
    Parse Java source and extract method AST.
    Returns MethodAST if found, None otherwise.
    """
    if not _has_tree_sitter:
        return None
    
    try:
        tree = PARSER.parse(java_source)
        root = tree.root_node
        
        # Find the class
        class_query = JAVA_LANGUAGE.query(f"""
            (class_declaration 
                name: ((identifier) @class-name 
                       (#eq? @class-name "{class_name}"))) @class
        """)
        
        class_node = None
        for node in tree_sitter.QueryCursor(class_query).captures(root)["class"]:
            class_node = node
            break
        
        if not class_node:
            return None
        
        # Find the method within the class body
        class_body = class_node.child_by_field_name("body")
        if not class_body:
            return None
        
        method_query = JAVA_LANGUAGE.query(f"""
            (method_declaration 
                name: ((identifier) @method-name (#eq? @method-name "{method_name}"))) @method
        """)
        
        method_node = None
        for node in tree_sitter.QueryCursor(method_query).captures(class_body)["method"]:
            # Check parameter count
            params_node = node.child_by_field_name("parameters")
            if params_node:
                param_count = sum(1 for c in params_node.children if c.type == "formal_parameter")
                if param_count == arity:
                    method_node = node
                    break
        
        if not method_node:
            return None
        
        # Extract parameters
        params = []
        params_node = method_node.child_by_field_name("parameters")
        if params_node:
            for child in params_node.children:
                if child.type == "formal_parameter":
                    # Extract variable name (last identifier in the parameter)
                    var_node = child.child_by_field_name("name")
                    if var_node:
                        params.append(var_node.text.decode('utf-8'))
        
        # Extract return type
        return_type_node = method_node.child_by_field_name("type")
        return_type = return_type_node.text.decode('utf-8') if return_type_node else None
        
        # Get method body
        body_node = method_node.child_by_field_name("body")
        if not body_node:
            return None
        
        # Convert to ASTNode structure
        full_ast = ASTNode.from_tree_sitter(method_node)
        body_ast = ASTNode.from_tree_sitter(body_node)
        
        # Get source text
        source_text = java_source[method_node.start_byte:method_node.end_byte].decode('utf-8', errors='ignore')
        
        return MethodAST(
            name=method_name,
            parameters=params,
            return_type=return_type,
            body=body_ast,
            full_ast=full_ast,
            source_text=source_text
        )
    except Exception as e:
        return None

def extract_ast_features(method_ast: MethodAST) -> Dict[str, Any]:
    """
    Extract features from AST for IR building and analysis.
    Returns a dictionary with structured information about the method.
    """
    features = {
        'parameters': method_ast.parameters,
        'has_loops': False,
        'has_assertions': False,
        'has_divisions': False,
        'has_array_access': False,
        'has_member_access': False,
        'loop_nodes': [],
        'assert_nodes': [],
        'div_nodes': [],
        'index_nodes': [],
        'member_nodes': [],
        'if_nodes': [],
        'assign_nodes': [],
        'call_nodes': [],
    }
    
    def traverse(node: ASTNode):
        """Recursively traverse AST and collect features"""
        if node.node_type == "while_statement":
            features['has_loops'] = True
            features['loop_nodes'].append(node)
        elif node.node_type == "for_statement":
            features['has_loops'] = True
            features['loop_nodes'].append(node)
        elif node.node_type == "do_statement":
            features['has_loops'] = True
            features['loop_nodes'].append(node)
        elif node.node_type == "assert_statement":
            features['has_assertions'] = True
            features['assert_nodes'].append(node)
        elif node.node_type == "binary_expression":
            # Check if it's a division
            operator = None
            for child in node.children:
                if child.node_type == "/":
                    operator = child
                    break
            if operator:
                features['has_divisions'] = True
                features['div_nodes'].append(node)
        elif node.node_type == "array_access":
            features['has_array_access'] = True
            features['index_nodes'].append(node)
        elif node.node_type == "field_access" or node.node_type == "method_invocation":
            features['has_member_access'] = True
            features['member_nodes'].append(node)
        elif node.node_type == "if_statement":
            features['if_nodes'].append(node)
        elif node.node_type == "assignment_expression":
            features['assign_nodes'].append(node)
        elif node.node_type == "method_invocation":
            features['call_nodes'].append(node)
        
        # Recursively process children
        for child in node.children:
            traverse(child)
    
    traverse(method_ast.body)
    return features

def find_child_by_field(ast_node: ASTNode, field_name: str) -> Optional[ASTNode]:
    """Find child node by field name in ASTNode structure"""
    # We need to traverse and match field names
    # For simplicity, we'll search by node type patterns
    # This is a simplified version - in practice you'd want to preserve field names
    for child in ast_node.children:
        if field_name == "left" and child.node_type in ["identifier", "field_access"]:
            return child
        if field_name == "right" and child.node_type not in ["identifier", "field_access"]:
            # Usually right comes after left
            return child
    return None

def extract_text_from_ast(ast_node: ASTNode) -> str:
    """Extract text from AST node"""
    return ast_node.text.strip()

def build_ir_from_ast(method_ast: MethodAST, features: Dict[str, Any]) -> Dict[int, Any]:
    """
    Build IR from AST structure.
    Returns a Program (dict mapping pc to Instr).
    """
    from bounded import Instr
    
    prog = {}
    pc = 0
    
    # Process assignments - extract left and right sides
    for assign_node in features['assign_nodes']:
        # Find left (variable) and right (expression) children
        # In assignment_expression, typically: left = right
        left_found = False
        var = None
        expr_parts = []
        for child in assign_node.children:
            if child.node_type == "=":
                left_found = True
                continue
            if not left_found:
                var = extract_text_from_ast(child)
            else:
                expr_parts.append(extract_text_from_ast(child))
        
        if var and expr_parts:
            expr = " ".join(expr_parts)
            prog[pc] = Instr("ASSIGN", (var, expr))
            pc += 1
    
    # Process method calls
    for call_node in features['call_nodes']:
        # Extract method name and arguments
        name_parts = []
        args = []
        in_args = False
        for child in call_node.children:
            if child.node_type == "(":
                in_args = True
                continue
            elif child.node_type == ")":
                in_args = False
                continue
            elif child.node_type == ",":
                continue
            elif not in_args:
                name_parts.append(extract_text_from_ast(child))
            else:
                args.append(extract_text_from_ast(child))
        
        if name_parts:
            callee = "".join(name_parts)
            prog[pc] = Instr("CALL", ("_", callee, tuple(args)))
            pc += 1
    
    # Process assertions
    for assert_node in features['assert_nodes']:
        # Extract condition
        cond_parts = []
        for child in assert_node.children:
            if child.node_type not in ["assert", ":", ";"]:
                cond_parts.append(extract_text_from_ast(child))
        if cond_parts:
            cond = " ".join(cond_parts)
            prog[pc] = Instr("ASSERT", (cond,))
            pc += 1
    
    # Process if statements
    for if_node in features['if_nodes']:
        # Extract condition
        cond_parts = []
        in_condition = False
        for child in if_node.children:
            if child.node_type == "if":
                continue
            elif child.node_type == "(":
                in_condition = True
                continue
            elif child.node_type == ")":
                in_condition = False
                break
            elif in_condition:
                cond_parts.append(extract_text_from_ast(child))
        
        if cond_parts:
            cond = " ".join(cond_parts)
            prog[pc] = Instr("IF", (cond, pc + 2))
            pc += 1
            prog[pc] = Instr("NOP", ())
            pc += 1
    
    # Process divisions
    for div_node in features['div_nodes']:
        # Extract left and right operands
        left_parts = []
        right_parts = []
        found_div = False
        for child in div_node.children:
            if child.text == "/":
                found_div = True
                continue
            if not found_div:
                left_parts.append(extract_text_from_ast(child))
            else:
                right_parts.append(extract_text_from_ast(child))
        
        if left_parts and right_parts:
            a = " ".join(left_parts)
            b = " ".join(right_parts)
            prog[pc] = Instr("DIV", (a, b))
            pc += 1
    
    # Process array access
    for index_node in features['index_nodes']:
        # Extract array and index
        array_parts = []
        index_parts = []
        in_index = False
        for child in index_node.children:
            if child.text == "[":
                in_index = True
                continue
            elif child.text == "]":
                in_index = False
                continue
            elif not in_index:
                array_parts.append(extract_text_from_ast(child))
            else:
                index_parts.append(extract_text_from_ast(child))
        
        if array_parts and index_parts:
            arr = "".join(array_parts)
            idx = " ".join(index_parts)
            prog[pc] = Instr("INDEX", (arr, idx))
            pc += 1
    
    # Process member access
    for member_node in features['member_nodes']:
        # Extract object
        obj_parts = []
        for child in member_node.children:
            if child.text != ".":
                obj_parts.append(extract_text_from_ast(child))
                break  # Just get the object part
        if obj_parts:
            obj = "".join(obj_parts)
            prog[pc] = Instr("MEMBER", (obj,))
            pc += 1
    
    # Add return
    prog[pc] = Instr("RET", ())
    return prog

