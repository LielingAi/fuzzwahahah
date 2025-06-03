"""
Symbolic Execution Integration for FUZZ Generator

This module provides symbolic execution capabilities to generate
precise test cases based on path constraints and program analysis.
"""

import ast
import sys
import time
import threading
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum
import operator


class ConstraintType(Enum):
    """Types of symbolic constraints."""
    EQUAL = "=="
    NOT_EQUAL = "!="
    LESS_THAN = "<"
    LESS_EQUAL = "<="
    GREATER_THAN = ">"
    GREATER_EQUAL = ">="
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    LENGTH = "length"
    REGEX_MATCH = "regex_match"


@dataclass
class SymbolicConstraint:
    """Represents a symbolic constraint on input variables."""
    variable: str
    constraint_type: ConstraintType
    value: Any
    negated: bool = False
    
    def __str__(self):
        op = "not " if self.negated else ""
        return f"{op}{self.variable} {self.constraint_type.value} {self.value}"


@dataclass
class PathConstraint:
    """Represents a path through the program with associated constraints."""
    path_id: str
    constraints: List[SymbolicConstraint]
    target_location: str
    complexity_score: float
    reachable: bool = True
    
    def __str__(self):
        return f"Path {self.path_id}: {len(self.constraints)} constraints -> {self.target_location}"


class SymbolicVariable:
    """Represents a symbolic variable in the execution."""
    
    def __init__(self, name: str, var_type: type = str):
        self.name = name
        self.var_type = var_type
        self.constraints: List[SymbolicConstraint] = []
        self.possible_values: Set[Any] = set()
        
    def add_constraint(self, constraint: SymbolicConstraint):
        """Add a constraint to this variable."""
        self.constraints.append(constraint)
        
    def get_concrete_values(self, max_values: int = 10) -> List[Any]:
        """Generate concrete values that satisfy all constraints."""
        values = []
        
        # Start with basic values based on type
        if self.var_type == str:
            candidates = ["", "a", "test", "A" * 100, "special<>&\"'", "admin", "root", "../", "/etc/passwd"]
        elif self.var_type == int:
            candidates = [0, 1, -1, 255, 256, 65535, 65536, -2147483648, 2147483647]
        elif self.var_type == bytes:
            candidates = [b"", b"a", b"test", b"A" * 100, b"\x00\x01\x7f"]
        else:
            candidates = [None, "", 0, []]
        
        # Filter candidates based on constraints
        for candidate in candidates:
            if self._satisfies_constraints(candidate):
                values.append(candidate)
                if len(values) >= max_values:
                    break
        
        # Generate additional values to satisfy specific constraints
        for constraint in self.constraints:
            if constraint.constraint_type == ConstraintType.EQUAL:
                if constraint.value not in values:
                    values.append(constraint.value)
            elif constraint.constraint_type == ConstraintType.LENGTH:
                if self.var_type == str:
                    length_value = "A" * int(constraint.value)
                    if length_value not in values:
                        values.append(length_value)
        
        return values[:max_values]
    
    def _satisfies_constraints(self, value: Any) -> bool:
        """Check if a value satisfies all constraints."""
        for constraint in self.constraints:
            if not self._check_constraint(value, constraint):
                return False
        return True
    
    def _check_constraint(self, value: Any, constraint: SymbolicConstraint) -> bool:
        """Check if a value satisfies a specific constraint."""
        try:
            if constraint.constraint_type == ConstraintType.EQUAL:
                result = value == constraint.value
            elif constraint.constraint_type == ConstraintType.NOT_EQUAL:
                result = value != constraint.value
            elif constraint.constraint_type == ConstraintType.LESS_THAN:
                result = value < constraint.value
            elif constraint.constraint_type == ConstraintType.LESS_EQUAL:
                result = value <= constraint.value
            elif constraint.constraint_type == ConstraintType.GREATER_THAN:
                result = value > constraint.value
            elif constraint.constraint_type == ConstraintType.GREATER_EQUAL:
                result = value >= constraint.value
            elif constraint.constraint_type == ConstraintType.IN:
                result = value in constraint.value
            elif constraint.constraint_type == ConstraintType.NOT_IN:
                result = value not in constraint.value
            elif constraint.constraint_type == ConstraintType.CONTAINS:
                result = constraint.value in str(value)
            elif constraint.constraint_type == ConstraintType.STARTS_WITH:
                result = str(value).startswith(str(constraint.value))
            elif constraint.constraint_type == ConstraintType.ENDS_WITH:
                result = str(value).endswith(str(constraint.value))
            elif constraint.constraint_type == ConstraintType.LENGTH:
                result = len(value) == constraint.value
            else:
                result = True  # Unknown constraint type
            
            return not result if constraint.negated else result
            
        except (TypeError, AttributeError):
            return False


class SimpleSymbolicExecutor:
    """
    Simplified symbolic execution engine for FUZZ generation.
    
    This provides basic symbolic execution capabilities without
    requiring complex external dependencies.
    """
    
    def __init__(self):
        self.variables: Dict[str, SymbolicVariable] = {}
        self.paths: List[PathConstraint] = []
        self.current_path: List[SymbolicConstraint] = []
        self.path_counter = 0
        
        # Statistics
        self.stats = {
            'paths_explored': 0,
            'constraints_generated': 0,
            'concrete_values_generated': 0,
            'execution_time': 0.0
        }
    
    def create_symbolic_variable(self, name: str, var_type: type = str) -> SymbolicVariable:
        """Create a new symbolic variable."""
        var = SymbolicVariable(name, var_type)
        self.variables[name] = var
        return var
    
    def add_constraint(self, variable_name: str, constraint_type: ConstraintType, 
                      value: Any, negated: bool = False):
        """Add a constraint to the current path."""
        constraint = SymbolicConstraint(variable_name, constraint_type, value, negated)
        self.current_path.append(constraint)
        
        if variable_name in self.variables:
            self.variables[variable_name].add_constraint(constraint)
        
        self.stats['constraints_generated'] += 1
    
    def branch_condition(self, condition_func, true_constraints: List[Tuple], 
                        false_constraints: List[Tuple]) -> List[PathConstraint]:
        """
        Handle a branch condition and generate path constraints.
        
        Args:
            condition_func: Function representing the condition
            true_constraints: Constraints for the true branch
            false_constraints: Constraints for the false branch
            
        Returns:
            List of path constraints for both branches
        """
        paths = []
        
        # True branch
        true_path = self.current_path.copy()
        for var_name, constraint_type, value in true_constraints:
            constraint = SymbolicConstraint(var_name, constraint_type, value)
            true_path.append(constraint)
        
        path_id = f"path_{self.path_counter}"
        self.path_counter += 1
        
        paths.append(PathConstraint(
            path_id=path_id + "_true",
            constraints=true_path,
            target_location=f"branch_true_{path_id}",
            complexity_score=len(true_path)
        ))
        
        # False branch
        false_path = self.current_path.copy()
        for var_name, constraint_type, value in false_constraints:
            constraint = SymbolicConstraint(var_name, constraint_type, value, negated=True)
            false_path.append(constraint)
        
        paths.append(PathConstraint(
            path_id=path_id + "_false",
            constraints=false_path,
            target_location=f"branch_false_{path_id}",
            complexity_score=len(false_path)
        ))
        
        self.paths.extend(paths)
        self.stats['paths_explored'] += 2
        
        return paths
    
    def analyze_function(self, func_source: str, input_variables: List[str]) -> List[PathConstraint]:
        """
        Analyze a function and extract path constraints.
        
        Args:
            func_source: Source code of the function to analyze
            input_variables: List of input variable names
            
        Returns:
            List of discovered path constraints
        """
        start_time = time.time()
        
        try:
            # Parse the function source
            tree = ast.parse(func_source)
            
            # Create symbolic variables for inputs
            for var_name in input_variables:
                self.create_symbolic_variable(var_name, str)
            
            # Simple AST analysis to find conditions
            paths = self._analyze_ast_node(tree)
            
            self.stats['execution_time'] += time.time() - start_time
            return paths
            
        except Exception as e:
            print(f"Error analyzing function: {e}")
            return []
    
    def _analyze_ast_node(self, node) -> List[PathConstraint]:
        """Recursively analyze AST nodes to find constraints."""
        paths = []
        
        if isinstance(node, ast.If):
            # Handle if statements
            condition_constraints = self._extract_condition_constraints(node.test)
            
            if condition_constraints:
                var_name, constraint_type, value = condition_constraints[0]
                
                # Create paths for both branches
                branch_paths = self.branch_condition(
                    None,  # condition function not needed for simple analysis
                    [(var_name, constraint_type, value)],
                    [(var_name, constraint_type, value)]  # Negated automatically
                )
                paths.extend(branch_paths)
        
        # Recursively analyze child nodes
        for child in ast.iter_child_nodes(node):
            paths.extend(self._analyze_ast_node(child))
        
        return paths
    
    def _extract_condition_constraints(self, condition_node) -> List[Tuple]:
        """Extract constraints from a condition AST node."""
        constraints = []
        
        if isinstance(condition_node, ast.Compare):
            # Handle comparison operations
            if (isinstance(condition_node.left, ast.Name) and 
                len(condition_node.ops) == 1 and 
                len(condition_node.comparators) == 1):
                
                var_name = condition_node.left.id
                op = condition_node.ops[0]
                comparator = condition_node.comparators[0]
                
                # Extract the comparison value
                if isinstance(comparator, ast.Constant):
                    value = comparator.value
                elif isinstance(comparator, ast.Str):  # Python < 3.8
                    value = comparator.s
                elif isinstance(comparator, ast.Num):  # Python < 3.8
                    value = comparator.n
                else:
                    return constraints
                
                # Map AST operators to constraint types
                if isinstance(op, ast.Eq):
                    constraint_type = ConstraintType.EQUAL
                elif isinstance(op, ast.NotEq):
                    constraint_type = ConstraintType.NOT_EQUAL
                elif isinstance(op, ast.Lt):
                    constraint_type = ConstraintType.LESS_THAN
                elif isinstance(op, ast.LtE):
                    constraint_type = ConstraintType.LESS_EQUAL
                elif isinstance(op, ast.Gt):
                    constraint_type = ConstraintType.GREATER_THAN
                elif isinstance(op, ast.GtE):
                    constraint_type = ConstraintType.GREATER_EQUAL
                elif isinstance(op, ast.In):
                    constraint_type = ConstraintType.IN
                elif isinstance(op, ast.NotIn):
                    constraint_type = ConstraintType.NOT_IN
                else:
                    return constraints
                
                constraints.append((var_name, constraint_type, value))
        
        return constraints
    
    def generate_test_inputs(self, max_inputs_per_path: int = 5) -> Dict[str, List[Dict[str, Any]]]:
        """
        Generate concrete test inputs for all discovered paths.
        
        Args:
            max_inputs_per_path: Maximum number of inputs to generate per path
            
        Returns:
            Dictionary mapping path IDs to lists of input dictionaries
        """
        test_inputs = {}
        
        for path in self.paths:
            path_inputs = []
            
            # Group constraints by variable
            var_constraints = {}
            for constraint in path.constraints:
                if constraint.variable not in var_constraints:
                    var_constraints[constraint.variable] = []
                var_constraints[constraint.variable].append(constraint)
            
            # Generate inputs for each variable
            var_values = {}
            for var_name, constraints in var_constraints.items():
                if var_name in self.variables:
                    # Temporarily add constraints to variable
                    original_constraints = self.variables[var_name].constraints.copy()
                    self.variables[var_name].constraints = constraints
                    
                    # Generate concrete values
                    values = self.variables[var_name].get_concrete_values(max_inputs_per_path)
                    var_values[var_name] = values
                    
                    # Restore original constraints
                    self.variables[var_name].constraints = original_constraints
            
            # Create input combinations
            if var_values:
                max_combinations = min(max_inputs_per_path, 
                                     max(len(values) for values in var_values.values()))
                
                for i in range(max_combinations):
                    input_dict = {}
                    for var_name, values in var_values.items():
                        if i < len(values):
                            input_dict[var_name] = values[i]
                        elif values:
                            input_dict[var_name] = values[0]  # Use first value as fallback
                    
                    if input_dict:
                        path_inputs.append(input_dict)
            
            test_inputs[path.path_id] = path_inputs
            self.stats['concrete_values_generated'] += len(path_inputs)
        
        return test_inputs
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get symbolic execution statistics."""
        return {
            **self.stats,
            'variables_count': len(self.variables),
            'paths_count': len(self.paths),
            'average_constraints_per_path': (
                sum(len(path.constraints) for path in self.paths) / len(self.paths)
                if self.paths else 0
            )
        }
    
    def clear(self):
        """Clear all symbolic execution state."""
        self.variables.clear()
        self.paths.clear()
        self.current_path.clear()
        self.path_counter = 0
        self.stats = {
            'paths_explored': 0,
            'constraints_generated': 0,
            'concrete_values_generated': 0,
            'execution_time': 0.0
        }


class SymbolicFuzzGenerator:
    """
    FUZZ generator enhanced with symbolic execution capabilities.

    This generator uses symbolic execution to create targeted test cases
    that explore specific program paths and satisfy complex constraints.
    """

    def __init__(self, target_function_source: str = None):
        """
        Initialize symbolic FUZZ generator.

        Args:
            target_function_source: Source code of target function to analyze
        """
        self.symbolic_executor = SimpleSymbolicExecutor()
        self.target_function_source = target_function_source
        self.discovered_paths = []
        self.generated_inputs = {}

        # Performance tracking
        self.stats = {
            'total_inputs_generated': 0,
            'unique_paths_covered': 0,
            'constraint_satisfaction_rate': 0.0,
            'generation_time': 0.0
        }

        # Common protocol patterns for symbolic analysis
        self.protocol_patterns = {
            'http': self._get_http_patterns(),
            'sql': self._get_sql_patterns(),
            'json': self._get_json_patterns(),
            'xml': self._get_xml_patterns(),
            'binary': self._get_binary_patterns(),
            'ftp_user': self._get_ftp_user_patterns(),
            'ftp_path': self._get_ftp_path_patterns()
        }

    def _get_http_patterns(self) -> List[Dict]:
        """Get HTTP protocol patterns for symbolic analysis."""
        return [
            {
                'name': 'http_method_check',
                'source': '''
def check_http_method(method):
    if method == "GET":
        return "safe_path"
    elif method == "POST":
        return "modify_path"
    elif method == "DELETE":
        return "danger_path"
    else:
        return "unknown_path"
                ''',
                'input_vars': ['method']
            },
            {
                'name': 'http_header_validation',
                'source': '''
def validate_header(header_value):
    if len(header_value) > 1000:
        return "header_too_long"
    elif "script" in header_value.lower():
        return "potential_xss"
    elif header_value.startswith("Bearer "):
        return "auth_token"
    else:
        return "normal_header"
                ''',
                'input_vars': ['header_value']
            }
        ]

    def _get_sql_patterns(self) -> List[Dict]:
        """Get SQL injection patterns for symbolic analysis."""
        return [
            {
                'name': 'sql_injection_check',
                'source': '''
def check_sql_input(user_input):
    if "'" in user_input:
        return "sql_injection_risk"
    elif "UNION" in user_input.upper():
        return "union_attack"
    elif "--" in user_input:
        return "comment_injection"
    else:
        return "safe_input"
                ''',
                'input_vars': ['user_input']
            }
        ]

    def _get_json_patterns(self) -> List[Dict]:
        """Get JSON parsing patterns for symbolic analysis."""
        return [
            {
                'name': 'json_depth_check',
                'source': '''
def check_json_depth(json_str):
    depth = json_str.count('{') + json_str.count('[')
    if depth > 100:
        return "too_deep"
    elif depth > 10:
        return "moderate_depth"
    else:
        return "shallow"
                ''',
                'input_vars': ['json_str']
            }
        ]

    def _get_xml_patterns(self) -> List[Dict]:
        """Get XML parsing patterns for symbolic analysis."""
        return [
            {
                'name': 'xml_entity_check',
                'source': '''
def check_xml_entities(xml_content):
    if "<!ENTITY" in xml_content:
        return "entity_expansion_risk"
    elif "<!DOCTYPE" in xml_content:
        return "dtd_processing"
    else:
        return "safe_xml"
                ''',
                'input_vars': ['xml_content']
            }
        ]

    def _get_binary_patterns(self) -> List[Dict]:
        """Get binary protocol patterns for symbolic analysis."""
        return [
            {
                'name': 'buffer_overflow_check',
                'source': '''
def check_buffer_size(data_length):
    if data_length > 65535:
        return "overflow_risk"
    elif data_length > 1024:
        return "large_buffer"
    elif data_length == 0:
        return "empty_buffer"
    else:
        return "normal_size"
                ''',
                'input_vars': ['data_length']
            }
        ]

    def _get_ftp_user_patterns(self) -> List[Dict]:
        """Get FTP user validation patterns for symbolic analysis."""
        return [
            {
                'name': 'ftp_user_validation',
                'source': '''
def validate_ftp_user(username):
    if username == "anonymous":
        return "anonymous_login"
    elif len(username) > 32:
        return "username_too_long"
    elif "admin" in username.lower():
        return "admin_access"
    elif username == "root":
        return "root_access"
    else:
        return "normal_user"
                ''',
                'input_vars': ['username']
            }
        ]

    def _get_ftp_path_patterns(self) -> List[Dict]:
        """Get FTP path validation patterns for symbolic analysis."""
        return [
            {
                'name': 'ftp_path_validation',
                'source': '''
def validate_ftp_path(path):
    if "../" in path:
        return "directory_traversal"
    elif len(path) > 255:
        return "path_too_long"
    elif path.startswith("/"):
        return "absolute_path"
    elif path.endswith(".exe"):
        return "executable_file"
    else:
        return "relative_path"
                ''',
                'input_vars': ['path']
            }
        ]

    def analyze_protocol(self, protocol_type: str) -> List[Dict[str, Any]]:
        """
        Analyze a specific protocol and generate symbolic constraints.

        Args:
            protocol_type: Type of protocol ('http', 'sql', 'json', 'xml', 'binary')

        Returns:
            List of generated test inputs based on symbolic analysis
        """
        start_time = time.time()

        if protocol_type not in self.protocol_patterns:
            return []

        all_inputs = []
        patterns = self.protocol_patterns[protocol_type]

        for pattern in patterns:
            # Analyze the pattern function
            paths = self.symbolic_executor.analyze_function(
                pattern['source'],
                pattern['input_vars']
            )

            # Generate test inputs for discovered paths
            test_inputs = self.symbolic_executor.generate_test_inputs(max_inputs_per_path=10)

            # Format inputs for FUZZ generation
            for path_id, inputs in test_inputs.items():
                for input_dict in inputs:
                    formatted_input = {
                        'protocol': protocol_type,
                        'pattern': pattern['name'],
                        'path_id': path_id,
                        'inputs': input_dict,
                        'symbolic_origin': True
                    }
                    all_inputs.append(formatted_input)

        self.stats['generation_time'] += time.time() - start_time
        self.stats['total_inputs_generated'] += len(all_inputs)
        self.stats['unique_paths_covered'] = len(self.symbolic_executor.paths)

        return all_inputs

    def generate_constraint_based_inputs(self, constraints: List[Tuple[str, str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate inputs based on custom constraints.

        Args:
            constraints: List of (variable_name, constraint_type, value) tuples

        Returns:
            List of generated inputs satisfying the constraints
        """
        start_time = time.time()

        # Clear previous state
        self.symbolic_executor.clear()

        # Create variables and add constraints
        variables = set()
        for var_name, constraint_type_str, value in constraints:
            variables.add(var_name)

            # Convert string constraint type to enum
            constraint_type = getattr(ConstraintType, constraint_type_str.upper(), ConstraintType.EQUAL)

            # Create variable if not exists
            if var_name not in self.symbolic_executor.variables:
                var_type = type(value) if value is not None else str
                self.symbolic_executor.create_symbolic_variable(var_name, var_type)

            # Add constraint
            self.symbolic_executor.add_constraint(var_name, constraint_type, value)

        # Generate concrete values
        inputs = []
        for var_name in variables:
            if var_name in self.symbolic_executor.variables:
                values = self.symbolic_executor.variables[var_name].get_concrete_values(20)
                for value in values:
                    inputs.append({
                        'variable': var_name,
                        'value': value,
                        'constraint_based': True,
                        'satisfies_constraints': True
                    })

        self.stats['generation_time'] += time.time() - start_time
        self.stats['total_inputs_generated'] += len(inputs)

        return inputs

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive symbolic execution statistics."""
        symbolic_stats = self.symbolic_executor.get_statistics()

        return {
            'generator_stats': self.stats,
            'symbolic_execution': symbolic_stats,
            'protocol_patterns_available': list(self.protocol_patterns.keys()),
            'efficiency': {
                'inputs_per_second': (
                    self.stats['total_inputs_generated'] / self.stats['generation_time']
                    if self.stats['generation_time'] > 0 else 0
                ),
                'paths_per_input': (
                    self.stats['unique_paths_covered'] / self.stats['total_inputs_generated']
                    if self.stats['total_inputs_generated'] > 0 else 0
                )
            }
        }
