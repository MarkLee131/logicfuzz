"""
Skeleton Generator

Generates driver skeletons using traditional program synthesis techniques.
A skeleton contains:
1. Deterministic parts: API call sequences, variable declarations, control flow structures
2. Holes: Uncertain parts that need to be filled later

Design principles:
- Skeleton covers the overall structure of the driver
- Holes represent parts requiring semantic reasoning
- Supports incremental filling and validation
"""

import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum, auto

from liberator_adapter.common.api import Api, Arg
from liberator_adapter.driver.synthesis.hole import (
    Hole, HoleSet, HolePriority,
    ArrayLengthHole, InitValueHole, LoopBoundHole, ResourceCleanupHole,
    create_buffer_size_hole, create_callback_hole, create_loop_condition_hole,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Skeleton IR Definition
# =============================================================================

class StatementKind(Enum):
    """Statement types"""
    BUFFER_DECL = auto()        # Buffer declaration
    BUFFER_INIT = auto()        # Buffer initialization
    API_CALL = auto()           # API call
    ASSIGNMENT = auto()         # Assignment
    IF_CHECK = auto()           # Condition check
    LOOP_START = auto()         # Loop start
    LOOP_END = auto()           # Loop end
    CLEANUP = auto()            # Resource cleanup
    RETURN = auto()             # Return
    COMMENT = auto()            # Comment
    RAW_CODE = auto()           # Raw code


class AllocationType(Enum):
    """Memory allocation types"""
    STACK = auto()      # Stack allocation
    HEAP = auto()       # Heap allocation
    FUZZ_INPUT = auto() # From fuzzer input


@dataclass
class SkeletonVariable:
    """Skeleton variable"""
    name: str
    c_type: str
    allocation: AllocationType = AllocationType.STACK
    is_pointer: bool = False
    is_array: bool = False
    array_size: Optional[str] = None  # May be a Hole placeholder
    init_value: Optional[str] = None  # May be a Hole placeholder
    source_api: Optional[str] = None  # API that produces this variable (if any)

    def get_declaration(self) -> str:
        """Generate declaration code"""
        if self.is_array and self.array_size:
            return f"{self.c_type} {self.name}[{self.array_size}]"
        elif self.init_value:
            return f"{self.c_type} {self.name} = {self.init_value}"
        else:
            return f"{self.c_type} {self.name}"


@dataclass
class SkeletonStatement:
    """Skeleton statement"""
    kind: StatementKind
    code: str = ""                              # Code string
    holes: List[str] = field(default_factory=list)  # Contained Hole names
    api: Optional[Api] = None                   # Associated API (if API call)
    variables: List[str] = field(default_factory=list)  # Involved variable names
    indent: int = 1                             # Indentation level

    def has_holes(self) -> bool:
        return len(self.holes) > 0


@dataclass
class DriverSkeleton:
    """Driver skeleton"""

    # Basic information
    name: str
    target_apis: List[Api]

    # Structure components
    includes: List[str] = field(default_factory=list)
    variables: Dict[str, SkeletonVariable] = field(default_factory=dict)
    statements: List[SkeletonStatement] = field(default_factory=list)
    cleanup_statements: List[SkeletonStatement] = field(default_factory=list)
    stub_functions: List[str] = field(default_factory=list)

    # Hole management
    holes: HoleSet = field(default_factory=HoleSet)

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_variable(self, var: SkeletonVariable) -> None:
        """Add variable"""
        self.variables[var.name] = var

    def add_statement(self, stmt: SkeletonStatement) -> None:
        """Add statement"""
        self.statements.append(stmt)

    def add_cleanup(self, stmt: SkeletonStatement) -> None:
        """Add cleanup statement"""
        self.cleanup_statements.append(stmt)

    def add_hole(self, hole: Hole) -> None:
        """Add hole"""
        self.holes.add(hole)

    def get_unfilled_holes(self) -> List[Hole]:
        """Get unfilled holes"""
        return self.holes.get_unfilled()

    def is_complete(self) -> bool:
        """Check if skeleton is complete (all holes filled)"""
        return self.holes.all_filled()

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize skeleton to dictionary for storage and JSON serialization.

        Returns:
            Dictionary containing:
            - name: Driver name
            - code: Rendered code with hole placeholders
            - holes: List of hole definitions
            - api_sequence: List of API names in order
            - metadata: Any additional metadata
        """
        # Render code with holes marked
        try:
            renderer = SkeletonRenderer()
            code = renderer.render_with_holes_marked(self)
        except Exception:
            code = ""

        # Serialize holes
        holes_list = []
        for hole in self.holes:
            hole_dict = {
                'name': hole.name,
                'hole_type': hole.kind.name if hasattr(hole.kind, 'name') else str(hole.kind),
                'placeholder': hole.get_placeholder(),
                'is_filled': hole.is_filled,
                'priority': hole.priority.name if hasattr(hole.priority, 'name') else str(hole.priority),
                'is_simple': hole.is_simple,
            }

            # Add type-specific fields
            if hasattr(hole, 'buffer_arg_idx'):
                hole_dict['buffer_arg_idx'] = hole.buffer_arg_idx
                hole_dict['length_arg_idx'] = hole.length_arg_idx
                hole_dict['relationship'] = hole.relationship
            if hasattr(hole, 'callback_signature'):
                hole_dict['callback_signature'] = hole.callback_signature
                hole_dict['callback_type'] = hole.callback_type
            if hasattr(hole, 'loop_type'):
                hole_dict['loop_type'] = hole.loop_type
            if hasattr(hole, 'target_type'):
                hole_dict['target_type'] = hole.target_type

            holes_list.append(hole_dict)

        # API sequence
        api_sequence = [api.function_name for api in self.target_apis] if self.target_apis else []

        return {
            'name': self.name,
            'code': code,
            'holes': holes_list,
            'api_sequence': api_sequence,
            'metadata': dict(self.metadata) if self.metadata else {},
            'includes': list(self.includes) if self.includes else [],
        }


# =============================================================================
# Skeleton Generator
# =============================================================================

class SkeletonGenerator:
    """
    Skeleton generator

    Generates driver skeleton from API sequence, including:
    1. Variable declarations (with Hole placeholders)
    2. API call sequences
    3. Error checks (with Hole placeholders)
    4. Resource cleanup

    Design principles:
    - Deterministic structure: API call order, variable binding
    - Holes: parameter values, callback implementations, loop conditions
    """

    def __init__(self):
        self._var_counter = 0
        self._hole_counter = 0

        # Type to initialization value mapping
        self.type_init_map = {
            "int": "0",
            "unsigned int": "0",
            "size_t": "0",
            "long": "0",
            "unsigned long": "0",
            "float": "0.0f",
            "double": "0.0",
            "char": "'\\0'",
            "bool": "false",
            "_Bool": "0",
        }

    def generate(self, api_sequence: List[Api],
                 varlen_relations: Optional[Dict[str, List[Tuple[int, int, str]]]] = None,
                 loop_patterns: Optional[Dict[str, Dict]] = None,
                 callback_infos: Optional[Dict[str, List[Dict]]] = None,
                 driver_name: str = "fuzz_driver",
                 is_cpp: bool = True) -> DriverSkeleton:
        """
        Generate driver skeleton

        Args:
            api_sequence: API call sequence
            varlen_relations: API var-len relationships {api_name: [(buf_idx, len_idx, rel), ...]}
            loop_patterns: API loop patterns {api_name: {needs_loop, loop_type, ...}}
            callback_infos: API callback information {api_name: [{arg_idx, type, ...}, ...]}
            driver_name: Generated driver name
            is_cpp: If True, generate C++ skeleton with FuzzedDataProvider

        Returns:
            DriverSkeleton: Skeleton with holes
        """
        self._var_counter = 0
        self._hole_counter = 0

        skeleton = DriverSkeleton(
            name=driver_name,
            target_apis=api_sequence
        )

        # 1. Generate includes (with FuzzedDataProvider for C++)
        skeleton.includes = self._generate_includes(api_sequence, is_cpp=is_cpp)

        # 2. Analyze variable requirements
        var_requirements = self._analyze_variable_requirements(
            api_sequence, varlen_relations or {}
        )

        # 3. Generate variable declarations
        self._generate_variable_declarations(skeleton, var_requirements)

        # 4. Generate API call sequence
        self._generate_api_calls(
            skeleton, api_sequence,
            varlen_relations or {},
            loop_patterns or {},
            callback_infos or {}
        )

        # 5. Generate cleanup code
        self._generate_cleanup(skeleton)

        return skeleton

    def _generate_includes(self, apis: List[Api], is_cpp: bool = True) -> List[str]:
        """Generate include list

        Args:
            apis: List of APIs (for future header detection)
            is_cpp: If True, include C++ headers like FuzzedDataProvider
        """
        includes = [
            "#include <stdint.h>",
            "#include <stddef.h>",
            "#include <stdlib.h>",
            "#include <string.h>",
        ]

        # C++ projects use FuzzedDataProvider for structured fuzzing
        if is_cpp:
            includes.append("#include <fuzzer/FuzzedDataProvider.h>")

        return includes

    def _analyze_variable_requirements(
        self,
        apis: List[Api],
        varlen_relations: Dict[str, List[Tuple[int, int, str]]]
    ) -> Dict[str, Dict]:
        """
        Analyze variable requirements

        Returns:
            {api_name: {
                'args': [{name, type, is_input, is_output, varlen_idx}, ...],
                'return': {type, name}
            }}
        """
        requirements = {}

        for api in apis:
            api_req = {
                'args': [],
                'return': None
            }

            # Get var-len relationships for this API
            api_varlen = varlen_relations.get(api.function_name, [])
            varlen_map = {buf_idx: (len_idx, rel) for buf_idx, len_idx, rel in api_varlen}

            # Analyze parameters
            for idx, arg in enumerate(api.arguments_info):
                arg_info = {
                    'name': arg.name or f"arg{idx}",
                    'type': arg.type,
                    'idx': idx,
                    'is_input': self._is_input_param(arg),
                    'is_output': self._is_output_param(arg),
                    'is_callback': self._is_callback_param(arg),
                    'varlen_target': varlen_map.get(idx),  # (len_idx, rel) or None
                }
                api_req['args'].append(arg_info)

            # Analyze return value
            if api.return_info and api.return_info.type not in ['void', '']:
                api_req['return'] = {
                    'type': api.return_info.type,
                    'name': f"ret_{api.function_name}"
                }

            requirements[api.function_name] = api_req

        return requirements

    def _is_input_param(self, arg: Arg) -> bool:
        """Determine if parameter is input"""
        # const pointer or value passing is usually input
        if arg.is_const and any(arg.is_const):
            return True
        if '*' not in arg.type:
            return True
        return False

    def _is_output_param(self, arg: Arg) -> bool:
        """Determine if parameter is output"""
        # Non-const pointer is usually output
        if '*' in arg.type and (not arg.is_const or not any(arg.is_const)):
            return True
        return False

    def _is_callback_param(self, arg: Arg) -> bool:
        """Determine if parameter is callback"""
        type_str = arg.type
        # Function pointer characteristics
        if '(*)' in type_str or '(*' in type_str:
            return True
        # Common callback typedefs
        callback_suffixes = ['_func', '_callback', '_handler', '_t']
        for suffix in callback_suffixes:
            if arg.name and suffix in arg.name.lower():
                return True
            if suffix in type_str.lower():
                return True
        return False

    def _generate_variable_declarations(
        self,
        skeleton: DriverSkeleton,
        var_requirements: Dict[str, Dict]
    ) -> None:
        """Generate variable declarations"""
        declared_vars: Set[str] = set()

        for api_name, req in var_requirements.items():
            # Return value variable
            if req['return']:
                ret_name = req['return']['name']
                if ret_name not in declared_vars:
                    var = self._create_variable_for_type(
                        ret_name, req['return']['type']
                    )
                    skeleton.add_variable(var)
                    declared_vars.add(ret_name)

            # Parameter variables
            for arg_info in req['args']:
                var_name = f"{arg_info['name']}_{api_name}"
                if var_name not in declared_vars:
                    var = self._create_variable_for_param(var_name, arg_info, skeleton)
                    if var:
                        skeleton.add_variable(var)
                        declared_vars.add(var_name)

    def _create_variable_for_type(self, name: str, c_type: str) -> SkeletonVariable:
        """Create variable for type"""
        is_pointer = '*' in c_type

        # Determine initial value
        if is_pointer:
            init_value = "NULL"
        else:
            base_type = c_type.replace('const', '').strip()
            init_value = self.type_init_map.get(base_type, "0")

        return SkeletonVariable(
            name=name,
            c_type=c_type,
            is_pointer=is_pointer,
            init_value=init_value
        )

    def _create_variable_for_param(
        self,
        name: str,
        arg_info: Dict,
        skeleton: DriverSkeleton
    ) -> Optional[SkeletonVariable]:
        """Create variable for parameter"""
        c_type = arg_info['type']
        is_pointer = '*' in c_type

        # Callback parameter - create Hole
        if arg_info['is_callback']:
            hole = create_callback_hole(
                name=f"callback_{self._next_hole_id()}",
                signature=c_type,
                callback_type="unknown"
            )
            skeleton.add_hole(hole)
            return SkeletonVariable(
                name=name,
                c_type=c_type,
                init_value=hole.get_placeholder()
            )

        # Input buffer parameter - may need to get from fuzz input
        if arg_info['is_input'] and is_pointer:
            # Check if there's var-len relationship
            if arg_info.get('varlen_target'):
                len_idx, rel = arg_info['varlen_target']
                hole = create_buffer_size_hole(
                    name=f"bufsize_{self._next_hole_id()}",
                    buffer_idx=arg_info['idx'],
                    length_idx=len_idx,
                    relationship=rel
                )
                skeleton.add_hole(hole)
                return SkeletonVariable(
                    name=name,
                    c_type=c_type,
                    allocation=AllocationType.FUZZ_INPUT,
                    is_pointer=True,
                    init_value="(void*)data"  # Default to use fuzz data
                )

        # Output parameter - need to allocate buffer
        if arg_info['is_output'] and is_pointer:
            # Create array length Hole
            hole = ArrayLengthHole(
                name=f"arrlen_{self._next_hole_id()}",
                priority=HolePriority.HIGH,
                element_type=c_type.replace('*', '').strip()
            )
            skeleton.add_hole(hole)
            return SkeletonVariable(
                name=name,
                c_type=c_type.replace('*', '').strip(),
                is_array=True,
                array_size=hole.get_placeholder(),
                allocation=AllocationType.STACK
            )

        # Regular parameter
        if is_pointer:
            init_value = "NULL"
        else:
            base_type = c_type.replace('const', '').strip()
            init_value = self.type_init_map.get(base_type, "0")

        return SkeletonVariable(
            name=name,
            c_type=c_type,
            is_pointer=is_pointer,
            init_value=init_value
        )

    def _generate_api_calls(
        self,
        skeleton: DriverSkeleton,
        apis: List[Api],
        varlen_relations: Dict[str, List[Tuple[int, int, str]]],
        loop_patterns: Dict[str, Dict],
        callback_infos: Dict[str, List[Dict]]
    ) -> None:
        """Generate API call sequence"""

        for api in apis:
            # Check if loop is needed
            loop_info = loop_patterns.get(api.function_name, {})
            if loop_info.get('needs_loop'):
                self._generate_loop_call(skeleton, api, loop_info)
            else:
                self._generate_single_call(skeleton, api)

    def _generate_single_call(self, skeleton: DriverSkeleton, api: Api) -> None:
        """Generate single API call"""

        # Build argument list
        args = []
        for idx, arg in enumerate(api.arguments_info):
            var_name = f"{arg.name or f'arg{idx}'}_{api.function_name}"
            if var_name in skeleton.variables:
                var = skeleton.variables[var_name]
                if var.is_array:
                    args.append(var.name)  # Array name is address
                elif var.is_pointer:
                    args.append(var.name)
                else:
                    args.append(var.name)
            else:
                # Variable not declared, use placeholder
                hole = InitValueHole(
                    name=f"param_{self._next_hole_id()}",
                    target_type=arg.type,
                    is_pointer='*' in arg.type
                )
                skeleton.add_hole(hole)
                args.append(hole.get_placeholder())

        # Build call code
        args_str = ", ".join(args)
        if api.return_info and api.return_info.type not in ['void', '']:
            ret_name = f"ret_{api.function_name}"
            call_code = f"{ret_name} = {api.function_name}({args_str});"
        else:
            call_code = f"{api.function_name}({args_str});"

        stmt = SkeletonStatement(
            kind=StatementKind.API_CALL,
            code=call_code,
            api=api,
            variables=args
        )
        skeleton.add_statement(stmt)

        # Add error check (if returns pointer)
        if api.return_info and '*' in api.return_info.type:
            ret_name = f"ret_{api.function_name}"
            check_code = f"if ({ret_name} == NULL) return 0;"
            check_stmt = SkeletonStatement(
                kind=StatementKind.IF_CHECK,
                code=check_code,
                variables=[ret_name]
            )
            skeleton.add_statement(check_stmt)

    def _generate_loop_call(
        self,
        skeleton: DriverSkeleton,
        api: Api,
        loop_info: Dict
    ) -> None:
        """Generate loop API call"""

        loop_type = loop_info.get('loop_type', 'iterator')

        # Create loop condition Hole
        cond_hole = create_loop_condition_hole(
            name=f"loopcond_{self._next_hole_id()}",
            loop_type=loop_type,
            api_return_type=api.return_info.type if api.return_info else ""
        )
        skeleton.add_hole(cond_hole)

        # Create loop bound Hole
        bound_hole = LoopBoundHole(
            name=f"loopbound_{self._next_hole_id()}",
            suggested_bound=loop_info.get('max_iterations', 100)
        )
        skeleton.add_hole(bound_hole)

        # Loop start
        loop_start = SkeletonStatement(
            kind=StatementKind.LOOP_START,
            code=f"int __iter_count = 0;\nwhile ({cond_hole.get_placeholder()} && __iter_count++ < {bound_hole.get_placeholder()}) {{",
            holes=[cond_hole.name, bound_hole.name]
        )
        skeleton.add_statement(loop_start)

        # API call in loop body
        self._generate_single_call(skeleton, api)

        # Loop end
        loop_end = SkeletonStatement(
            kind=StatementKind.LOOP_END,
            code="}"
        )
        skeleton.add_statement(loop_end)

    def _generate_cleanup(self, skeleton: DriverSkeleton) -> None:
        """Generate cleanup code"""

        # Create resource cleanup Hole
        cleanup_hole = ResourceCleanupHole(
            name=f"cleanup_{self._next_hole_id()}",
            resources=list(skeleton.variables.keys()),
            priority=HolePriority.MEDIUM
        )
        skeleton.add_hole(cleanup_hole)

        cleanup_stmt = SkeletonStatement(
            kind=StatementKind.CLEANUP,
            code=cleanup_hole.get_placeholder(),
            holes=[cleanup_hole.name]
        )
        skeleton.add_cleanup(cleanup_stmt)

    def _next_var_id(self) -> int:
        """Get next variable ID"""
        self._var_counter += 1
        return self._var_counter

    def _next_hole_id(self) -> int:
        """Get next Hole ID"""
        self._hole_counter += 1
        return self._hole_counter


# =============================================================================
# Skeleton Renderer
# =============================================================================

class SkeletonRenderer:
    """
    Skeleton renderer

    Renders DriverSkeleton to C code string
    """

    def render(self, skeleton: DriverSkeleton, is_cpp_target: bool = True) -> str:
        """Render skeleton to C/C++ code

        Args:
            skeleton: Driver skeleton to render
            is_cpp_target: If True, use 'extern "C"' for C++ fuzz target.
                          If False, emit pure C code (no extern "C").
        """
        lines = []

        # 1. Includes
        for inc in skeleton.includes:
            lines.append(inc)
        lines.append("")

        # 2. Stub functions
        for stub in skeleton.stub_functions:
            lines.append(stub)
            lines.append("")

        # 3. Fuzz function signature
        # OSS-Fuzz ALWAYS uses clang++ ($CXX) even for .c files, so we need extern "C"
        # to prevent C++ name mangling. Use #ifdef __cplusplus guard for compatibility.
        lines.append("#ifdef __cplusplus")
        lines.append("extern \"C\" {")
        lines.append("#endif")
        lines.append("")
        lines.append("int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {")

        # 4. Minimum size check
        lines.append("    if (size < 1) return 0;")
        lines.append("")

        # 5. Variable declarations
        for var_name, var in skeleton.variables.items():
            decl = var.get_declaration()
            lines.append(f"    {decl};")
        lines.append("")

        # 6. Statements
        for stmt in skeleton.statements:
            indent = "    " * stmt.indent
            for code_line in stmt.code.split('\n'):
                lines.append(f"{indent}{code_line}")

        lines.append("")

        # 7. Cleanup
        for stmt in skeleton.cleanup_statements:
            indent = "    " * stmt.indent
            for code_line in stmt.code.split('\n'):
                lines.append(f"{indent}{code_line}")

        # 8. Return
        lines.append("    return 0;")
        lines.append("}")

        # Close extern "C" block
        lines.append("")
        lines.append("#ifdef __cplusplus")
        lines.append("}")
        lines.append("#endif")

        return "\n".join(lines)

    def render_with_holes_marked(self, skeleton: DriverSkeleton, is_cpp_target: bool = True) -> str:
        """Render skeleton, marking all Hole positions"""
        code = self.render(skeleton, is_cpp_target=is_cpp_target)

        # Add comment for each Hole
        for hole in skeleton.holes:
            placeholder = hole.get_placeholder()
            if placeholder in code:
                comment = f"/* HOLE[{hole.kind.name}]: {hole.name} */"
                code = code.replace(placeholder, f"{placeholder} {comment}")

        return code


# =============================================================================
# Utility Functions
# =============================================================================

def generate_skeleton_for_sequence(
    api_sequence: List[Api],
    varlen_relations: Optional[Dict] = None,
    loop_patterns: Optional[Dict] = None,
    callback_infos: Optional[Dict] = None,
    driver_name: str = "fuzz_driver",
    is_cpp: bool = True
) -> DriverSkeleton:
    """Convenience function: generate skeleton for API sequence

    Args:
        api_sequence: API call sequence
        varlen_relations: Variable-length parameter relationships
        loop_patterns: Loop patterns for APIs
        callback_infos: Callback information
        driver_name: Name for the generated driver
        is_cpp: If True, include C++ headers (FuzzedDataProvider)
    """
    generator = SkeletonGenerator()
    return generator.generate(
        api_sequence,
        varlen_relations,
        loop_patterns,
        callback_infos,
        driver_name,
        is_cpp=is_cpp
    )


def render_skeleton(skeleton: DriverSkeleton, mark_holes: bool = False, is_cpp_target: bool = True) -> str:
    """Convenience function: render skeleton

    Args:
        skeleton: Driver skeleton to render
        mark_holes: Whether to mark unfilled holes with comments
        is_cpp_target: Deprecated - no longer used. The generated code now always
                      uses #ifdef __cplusplus guard for extern "C" since OSS-Fuzz
                      always compiles with clang++.
    """
    renderer = SkeletonRenderer()
    if mark_holes:
        return renderer.render_with_holes_marked(skeleton, is_cpp_target=is_cpp_target)
    return renderer.render(skeleton, is_cpp_target=is_cpp_target)
