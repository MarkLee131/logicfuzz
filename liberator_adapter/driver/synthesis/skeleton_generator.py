"""
Skeleton Generator - 骨架生成器

基于传统程序合成技术生成Driver骨架，骨架包含:
1. 确定性部分: API调用序列、变量声明、控制流结构
2. 孔(Holes): 需要后续填充的不确定部分

设计原则:
- 骨架覆盖Driver的整体结构
- 孔表示需要语义推理的部分
- 支持增量式填充和验证
"""

import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum, auto

from liberator_adapter.common.api import Api, Arg
from liberator_adapter.driver.synthesis.hole import (
    Hole, HoleSet, HoleKind, HolePriority,
    BufferSizeHole, ArrayLengthHole, InitValueHole, LoopBoundHole,
    CallbackImplHole, LoopConditionHole, ErrorHandlingHole, ResourceCleanupHole,
    create_buffer_size_hole, create_callback_hole, create_loop_condition_hole,
)

logger = logging.getLogger(__name__)


# =============================================================================
# 骨架IR定义
# =============================================================================

class StatementKind(Enum):
    """语句类型"""
    BUFFER_DECL = auto()        # Buffer声明
    BUFFER_INIT = auto()        # Buffer初始化
    API_CALL = auto()           # API调用
    ASSIGNMENT = auto()         # 赋值
    IF_CHECK = auto()           # 条件检查
    LOOP_START = auto()         # 循环开始
    LOOP_END = auto()           # 循环结束
    CLEANUP = auto()            # 资源清理
    RETURN = auto()             # 返回
    COMMENT = auto()            # 注释
    RAW_CODE = auto()           # 原始代码


class AllocationType(Enum):
    """内存分配类型"""
    STACK = auto()      # 栈上分配
    HEAP = auto()       # 堆上分配
    FUZZ_INPUT = auto() # 来自fuzzer输入


@dataclass
class SkeletonVariable:
    """骨架变量"""
    name: str
    c_type: str
    allocation: AllocationType = AllocationType.STACK
    is_pointer: bool = False
    is_array: bool = False
    array_size: Optional[str] = None  # 可能是Hole占位符
    init_value: Optional[str] = None  # 可能是Hole占位符
    source_api: Optional[str] = None  # 产生该变量的API（如果有）

    def get_declaration(self) -> str:
        """生成声明代码"""
        if self.is_array and self.array_size:
            return f"{self.c_type} {self.name}[{self.array_size}]"
        elif self.init_value:
            return f"{self.c_type} {self.name} = {self.init_value}"
        else:
            return f"{self.c_type} {self.name}"


@dataclass
class SkeletonStatement:
    """骨架语句"""
    kind: StatementKind
    code: str = ""                              # 代码字符串
    holes: List[str] = field(default_factory=list)  # 包含的Hole名称
    api: Optional[Api] = None                   # 关联的API（如果是API调用）
    variables: List[str] = field(default_factory=list)  # 涉及的变量名
    indent: int = 1                             # 缩进级别

    def has_holes(self) -> bool:
        return len(self.holes) > 0


@dataclass
class DriverSkeleton:
    """Driver骨架"""

    # 基本信息
    name: str
    target_apis: List[Api]

    # 结构组件
    includes: List[str] = field(default_factory=list)
    variables: Dict[str, SkeletonVariable] = field(default_factory=dict)
    statements: List[SkeletonStatement] = field(default_factory=list)
    cleanup_statements: List[SkeletonStatement] = field(default_factory=list)
    stub_functions: List[str] = field(default_factory=list)

    # 孔管理
    holes: HoleSet = field(default_factory=HoleSet)

    # 元数据
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_variable(self, var: SkeletonVariable) -> None:
        """添加变量"""
        self.variables[var.name] = var

    def add_statement(self, stmt: SkeletonStatement) -> None:
        """添加语句"""
        self.statements.append(stmt)

    def add_cleanup(self, stmt: SkeletonStatement) -> None:
        """添加清理语句"""
        self.cleanup_statements.append(stmt)

    def add_hole(self, hole: Hole) -> None:
        """添加孔"""
        self.holes.add(hole)

    def get_unfilled_holes(self) -> List[Hole]:
        """获取未填充的孔"""
        return self.holes.get_unfilled()

    def is_complete(self) -> bool:
        """检查骨架是否完整（所有孔已填充）"""
        return self.holes.all_filled()


# =============================================================================
# 骨架生成器
# =============================================================================

class SkeletonGenerator:
    """
    骨架生成器

    从API序列生成Driver骨架，包含:
    1. 变量声明（带Hole占位符）
    2. API调用序列
    3. 错误检查（带Hole占位符）
    4. 资源清理

    设计原则:
    - 确定性结构：API调用顺序、变量绑定
    - Holes：参数值、回调实现、循环条件
    """

    def __init__(self):
        self._var_counter = 0
        self._hole_counter = 0

        # 类型到初始化值的映射
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
                 driver_name: str = "fuzz_driver") -> DriverSkeleton:
        """
        生成Driver骨架

        Args:
            api_sequence: API调用序列
            varlen_relations: API的var-len关系 {api_name: [(buf_idx, len_idx, rel), ...]}
            loop_patterns: API的循环模式 {api_name: {needs_loop, loop_type, ...}}
            callback_infos: API的回调信息 {api_name: [{arg_idx, type, ...}, ...]}
            driver_name: 生成的driver名称

        Returns:
            DriverSkeleton: 带孔的骨架
        """
        self._var_counter = 0
        self._hole_counter = 0

        skeleton = DriverSkeleton(
            name=driver_name,
            target_apis=api_sequence
        )

        # 1. 生成includes
        skeleton.includes = self._generate_includes(api_sequence)

        # 2. 分析变量需求
        var_requirements = self._analyze_variable_requirements(
            api_sequence, varlen_relations or {}
        )

        # 3. 生成变量声明
        self._generate_variable_declarations(skeleton, var_requirements)

        # 4. 生成API调用序列
        self._generate_api_calls(
            skeleton, api_sequence,
            varlen_relations or {},
            loop_patterns or {},
            callback_infos or {}
        )

        # 5. 生成清理代码
        self._generate_cleanup(skeleton)

        return skeleton

    def _generate_includes(self, apis: List[Api]) -> List[str]:
        """生成include列表"""
        includes = [
            "#include <stdint.h>",
            "#include <stddef.h>",
            "#include <stdlib.h>",
            "#include <string.h>",
        ]
        return includes

    def _analyze_variable_requirements(
        self,
        apis: List[Api],
        varlen_relations: Dict[str, List[Tuple[int, int, str]]]
    ) -> Dict[str, Dict]:
        """
        分析变量需求

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

            # 获取该API的var-len关系
            api_varlen = varlen_relations.get(api.function_name, [])
            varlen_map = {buf_idx: (len_idx, rel) for buf_idx, len_idx, rel in api_varlen}

            # 分析参数
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

            # 分析返回值
            if api.return_info and api.return_info.type not in ['void', '']:
                api_req['return'] = {
                    'type': api.return_info.type,
                    'name': f"ret_{api.function_name}"
                }

            requirements[api.function_name] = api_req

        return requirements

    def _is_input_param(self, arg: Arg) -> bool:
        """判断是否是输入参数"""
        # const指针或值传递通常是输入
        if arg.is_const and any(arg.is_const):
            return True
        if '*' not in arg.type:
            return True
        return False

    def _is_output_param(self, arg: Arg) -> bool:
        """判断是否是输出参数"""
        # 非const指针通常是输出
        if '*' in arg.type and (not arg.is_const or not any(arg.is_const)):
            return True
        return False

    def _is_callback_param(self, arg: Arg) -> bool:
        """判断是否是回调参数"""
        type_str = arg.type
        # 函数指针特征
        if '(*)' in type_str or '(*' in type_str:
            return True
        # 常见回调typedef
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
        """生成变量声明"""
        declared_vars: Set[str] = set()

        for api_name, req in var_requirements.items():
            # 返回值变量
            if req['return']:
                ret_name = req['return']['name']
                if ret_name not in declared_vars:
                    var = self._create_variable_for_type(
                        ret_name, req['return']['type']
                    )
                    skeleton.add_variable(var)
                    declared_vars.add(ret_name)

            # 参数变量
            for arg_info in req['args']:
                var_name = f"{arg_info['name']}_{api_name}"
                if var_name not in declared_vars:
                    var = self._create_variable_for_param(var_name, arg_info, skeleton)
                    if var:
                        skeleton.add_variable(var)
                        declared_vars.add(var_name)

    def _create_variable_for_type(self, name: str, c_type: str) -> SkeletonVariable:
        """为类型创建变量"""
        is_pointer = '*' in c_type

        # 确定初始值
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
        """为参数创建变量"""
        c_type = arg_info['type']
        is_pointer = '*' in c_type

        # 回调参数 - 创建Hole
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

        # 输入buffer参数 - 可能需要从fuzz输入获取
        if arg_info['is_input'] and is_pointer:
            # 检查是否有var-len关系
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
                    init_value="(void*)data"  # 默认使用fuzz数据
                )

        # 输出参数 - 需要分配buffer
        if arg_info['is_output'] and is_pointer:
            # 创建数组长度Hole
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

        # 普通参数
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
        """生成API调用序列"""

        for api in apis:
            # 检查是否需要循环
            loop_info = loop_patterns.get(api.function_name, {})
            if loop_info.get('needs_loop'):
                self._generate_loop_call(skeleton, api, loop_info)
            else:
                self._generate_single_call(skeleton, api)

    def _generate_single_call(self, skeleton: DriverSkeleton, api: Api) -> None:
        """生成单次API调用"""

        # 构建参数列表
        args = []
        for idx, arg in enumerate(api.arguments_info):
            var_name = f"{arg.name or f'arg{idx}'}_{api.function_name}"
            if var_name in skeleton.variables:
                var = skeleton.variables[var_name]
                if var.is_array:
                    args.append(var.name)  # 数组名即地址
                elif var.is_pointer:
                    args.append(var.name)
                else:
                    args.append(var.name)
            else:
                # 变量未声明，使用占位符
                hole = InitValueHole(
                    name=f"param_{self._next_hole_id()}",
                    target_type=arg.type,
                    is_pointer='*' in arg.type
                )
                skeleton.add_hole(hole)
                args.append(hole.get_placeholder())

        # 构建调用代码
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

        # 添加错误检查（如果返回指针）
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
        """生成循环API调用"""

        loop_type = loop_info.get('loop_type', 'iterator')

        # 创建循环条件Hole
        cond_hole = create_loop_condition_hole(
            name=f"loopcond_{self._next_hole_id()}",
            loop_type=loop_type,
            api_return_type=api.return_info.type if api.return_info else ""
        )
        skeleton.add_hole(cond_hole)

        # 创建循环边界Hole
        bound_hole = LoopBoundHole(
            name=f"loopbound_{self._next_hole_id()}",
            suggested_bound=loop_info.get('max_iterations', 100)
        )
        skeleton.add_hole(bound_hole)

        # 循环开始
        loop_start = SkeletonStatement(
            kind=StatementKind.LOOP_START,
            code=f"int __iter_count = 0;\nwhile ({cond_hole.get_placeholder()} && __iter_count++ < {bound_hole.get_placeholder()}) {{",
            holes=[cond_hole.name, bound_hole.name]
        )
        skeleton.add_statement(loop_start)

        # 循环体内的API调用
        self._generate_single_call(skeleton, api)

        # 循环结束
        loop_end = SkeletonStatement(
            kind=StatementKind.LOOP_END,
            code="}"
        )
        skeleton.add_statement(loop_end)

    def _generate_cleanup(self, skeleton: DriverSkeleton) -> None:
        """生成清理代码"""

        # 创建资源清理Hole
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
        """获取下一个变量ID"""
        self._var_counter += 1
        return self._var_counter

    def _next_hole_id(self) -> int:
        """获取下一个Hole ID"""
        self._hole_counter += 1
        return self._hole_counter


# =============================================================================
# 骨架渲染器
# =============================================================================

class SkeletonRenderer:
    """
    骨架渲染器

    将DriverSkeleton渲染为C代码字符串
    """

    def render(self, skeleton: DriverSkeleton) -> str:
        """渲染骨架为C代码"""
        lines = []

        # 1. Includes
        for inc in skeleton.includes:
            lines.append(inc)
        lines.append("")

        # 2. Stub函数
        for stub in skeleton.stub_functions:
            lines.append(stub)
            lines.append("")

        # 3. Fuzz函数签名
        lines.append("extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {")

        # 4. 最小size检查
        lines.append("    if (size < 1) return 0;")
        lines.append("")

        # 5. 变量声明
        for var_name, var in skeleton.variables.items():
            decl = var.get_declaration()
            lines.append(f"    {decl};")
        lines.append("")

        # 6. 语句
        for stmt in skeleton.statements:
            indent = "    " * stmt.indent
            for code_line in stmt.code.split('\n'):
                lines.append(f"{indent}{code_line}")

        lines.append("")

        # 7. 清理
        for stmt in skeleton.cleanup_statements:
            indent = "    " * stmt.indent
            for code_line in stmt.code.split('\n'):
                lines.append(f"{indent}{code_line}")

        # 8. 返回
        lines.append("    return 0;")
        lines.append("}")

        return "\n".join(lines)

    def render_with_holes_marked(self, skeleton: DriverSkeleton) -> str:
        """渲染骨架，标记所有Hole的位置"""
        code = self.render(skeleton)

        # 为每个Hole添加注释
        for hole in skeleton.holes:
            placeholder = hole.get_placeholder()
            if placeholder in code:
                comment = f"/* HOLE[{hole.kind.name}]: {hole.name} */"
                code = code.replace(placeholder, f"{placeholder} {comment}")

        return code


# =============================================================================
# 工具函数
# =============================================================================

def generate_skeleton_for_sequence(
    api_sequence: List[Api],
    varlen_relations: Optional[Dict] = None,
    loop_patterns: Optional[Dict] = None,
    callback_infos: Optional[Dict] = None,
    driver_name: str = "fuzz_driver"
) -> DriverSkeleton:
    """便捷函数：为API序列生成骨架"""
    generator = SkeletonGenerator()
    return generator.generate(
        api_sequence,
        varlen_relations,
        loop_patterns,
        callback_infos,
        driver_name
    )


def render_skeleton(skeleton: DriverSkeleton, mark_holes: bool = False) -> str:
    """便捷函数：渲染骨架"""
    renderer = SkeletonRenderer()
    if mark_holes:
        return renderer.render_with_holes_marked(skeleton)
    return renderer.render(skeleton)
