#!/usr/bin/env python3
"""
项目级 Driver 生成器

基于 Liberator 的静态建模功能，对整个项目生成 driver，不需要指定单个 API。

功能：
1. 提取项目中的所有 API
2. 生成类型依赖图
3. 生成语义序列（Grammar）
4. 管理约束条件（ConditionManager）
5. 生成 driver 代码
"""
import logging
import os
import subprocess
from typing import Dict, List, Set, Optional
from pathlib import Path

from liberator_adapter.adapter import LiberatorAPIAdapter
from liberator_adapter.dependency import DependencyGraph, TypeDependencyGraphGenerator
from liberator_adapter.grammar import GrammarGenerator, NonTerminal, Terminal, Grammar
from liberator_adapter.constraints import ConditionManager
from liberator_adapter.common import Api, FunctionConditionsSet, DataLayout
from liberator_adapter.common.utils import Utils
from liberator_adapter.driver import Driver
from liberator_adapter.driver.factory import Factory
from liberator_adapter.driver.factory.only_type import OTFactory
from liberator_adapter.driver.factory.constraint_based import CBFactory
from liberator_adapter.bias import Bias
from liberator_adapter.backend.libfuzz import LFBackendDriver

logger = logging.getLogger(__name__)


class ProjectDriverGenerator:
    """
    项目级 Driver 生成器
    
    使用 Liberator 的完整静态建模功能：
    - 类型系统：类型依赖图
    - 语义序列：语法生成器
    - 约束管理：ConditionManager
    """
    
    def __init__(
        self,
        project_name: str,
        benchmark=None,
        use_clang_llvm: bool = True,
        work_dir: Optional[str] = None
    ):
        """
        初始化项目级 driver 生成器
        
        Args:
            project_name: 项目名称
            benchmark: Benchmark 对象（当 use_clang_llvm=True 时必需）
            use_clang_llvm: 是否使用 Clang/LLVM 直接提取（推荐）
            work_dir: 工作目录（用于存储生成的 driver）
        """
        self.project_name = project_name
        self.work_dir = Path(work_dir) if work_dir else Path(f"./workdir_{project_name}")
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        # 初始化适配器
        self.adapter = LiberatorAPIAdapter(
            project_name=project_name,
            use_clang_llvm=use_clang_llvm,
            benchmark=benchmark
        )
        
        # 组件（延迟初始化）
        self.all_apis: Set[Api] = set()
        self.dependency_graph: Optional[DependencyGraph] = None
        self.grammar = None
        self.condition_manager: Optional[ConditionManager] = None
        self.function_conditions: Optional[FunctionConditionsSet] = None
        self.extract_metadata: Dict = {}
        
        logger.info(f"✅ ProjectDriverGenerator initialized for {project_name}")
    
    def extract_all_apis(
        self,
        function_signatures: Optional[List[str]] = None,
        include_dir: Optional[str] = None,
        public_headers_file: Optional[str] = None,
        bc_file: Optional[str] = None,
        compile_project: bool = True
    ) -> Set[Api]:
        """
        提取项目中的所有 API
        
        Args:
            function_signatures: 要提取的函数签名列表（可选，None 表示提取所有）
            include_dir: 头文件目录
            public_headers_file: 公共头文件列表
            bc_file: bitcode 文件路径
            compile_project: 是否编译项目
        
        Returns:
            API 集合
        """
        logger.info(f"📦 Extracting all APIs for project {self.project_name}...")
        
        if not self.adapter.use_clang_llvm:
            logger.warning("extract_all_apis requires use_clang_llvm=True")
            return set()
        
        # Auto-fetch source from OSS-Fuzz style docker image if paths are not provided
        include_dir, public_headers_file = self._ensure_sources(
            include_dir=include_dir,
            public_headers_file=public_headers_file
        )
        
        # 使用适配器提取所有 API
        apis_dict = self.adapter.extract_all_apis(
            function_signatures=function_signatures,
            include_dir=include_dir,
            public_headers_file=public_headers_file,
            bc_file=bc_file,
            compile_project=compile_project
        )
        # 保存提取元数据（如 apis_llvm/conditions/data_layout 路径）
        try:
            self.extract_metadata = getattr(self.adapter, "last_metadata", {}) or {}
        except Exception:
            self.extract_metadata = {}
        
        self.all_apis = set(apis_dict.values())
        logger.info(f"✅ Extracted {len(self.all_apis)} APIs")
        
        return self.all_apis
    
    def build_dependency_graph(
        self,
        function_conditions: Optional[FunctionConditionsSet] = None,
        enable_provenance_filter: bool = True,
        enable_z3_pruning: bool = False
    ) -> DependencyGraph:
        """
        构建类型依赖图

        Args:
            function_conditions: 函数约束条件集合（可选，用于provenance过滤）
            enable_provenance_filter: 是否启用provenance过滤（默认True）
            enable_z3_pruning: 是否启用Z3约束剪枝（需要安装z3-solver）

        Returns:
            类型依赖图
        """
        if not self.all_apis:
            raise RuntimeError("No APIs extracted. Call extract_all_apis() first.")

        logger.info("🔗 Building type dependency graph...")
        if enable_z3_pruning:
            logger.info("   Z3 constraint pruning: enabled")

        # 如果启用provenance过滤但没有提供条件，尝试加载
        if enable_provenance_filter and function_conditions is None:
            conditions_file = None
            apis_llvm_file = None
            if self.extract_metadata:
                local_meta = self.extract_metadata.get("local", {})
                conditions_file = local_meta.get("conditions")
                apis_llvm_file = local_meta.get("apis_llvm")
            if conditions_file and apis_llvm_file:
                try:
                    function_conditions = Utils.prase_function_conditions(conditions_file, apis_llvm_file)
                    logger.info(f"✅ Loaded function conditions for provenance filtering")
                except Exception as e:
                    logger.warning(f"Failed to load conditions for provenance filtering: {e}")
                    logger.warning("Continuing with provenance filter disabled")
                    enable_provenance_filter = False

        # 使用 TypeDependencyGraphGenerator 生成依赖图
        dep_gen = TypeDependencyGraphGenerator(
            list(self.all_apis),
            function_conditions=function_conditions,
            enable_provenance_filter=enable_provenance_filter,
            enable_z3_pruning=enable_z3_pruning
        )
        self.dependency_graph = dep_gen.create()

        logger.info(f"✅ Dependency graph built: {len(self.dependency_graph.graph)} nodes")

        return self.dependency_graph
    
    def build_grammar(self) -> Grammar:
        """
        从依赖图生成语法规则（语义序列）
        
        Returns:
            语法对象
        """
        if not self.dependency_graph:
            raise RuntimeError("No dependency graph. Call build_dependency_graph() first.")
        
        logger.info("📝 Generating grammar from dependency graph...")
        
        # 创建语法生成器
        start_term = NonTerminal("start")
        end_term = Terminal("end")
        grammar_gen = GrammarGenerator(start_term, end_term)
        
        # 从依赖图生成语法
        self.grammar = grammar_gen.create(self.dependency_graph)
        
        logger.info(f"✅ Grammar generated: {self.grammar.num_symbols()} symbols")
        
        return self.grammar
    
    def build_condition_manager(
        self,
        function_conditions: Optional[FunctionConditionsSet] = None
    ) -> ConditionManager:
        """
        构建约束管理器
        
        Args:
            function_conditions: 函数约束条件集合（可选，如果为 None 则创建空的）
        
        Returns:
            ConditionManager 实例
        """
        if not self.all_apis:
            raise RuntimeError("No APIs extracted. Call extract_all_apis() first.")
        
        logger.info("🔒 Building condition manager...")
        
        # 如果没有提供约束条件，尝试从提取的 conditions.json 解析
        if function_conditions is None:
            parsed = None
            conditions_file = None
            apis_llvm_file = None
            if self.extract_metadata:
                local_meta = self.extract_metadata.get("local", {})
                conditions_file = local_meta.get("conditions")
                apis_llvm_file = local_meta.get("apis_llvm")
            if conditions_file and apis_llvm_file:
                try:
                    parsed = Utils.prase_function_conditions(conditions_file, apis_llvm_file)
                    logger.info(f"✅ Parsed function conditions from {conditions_file}")
                except Exception as e:
                    logger.warning(f"Failed to parse function conditions ({conditions_file}): {e}")
            function_conditions = parsed or FunctionConditionsSet()
            if parsed is None:
                logger.warning("No function conditions provided, using empty set")
        
        self.function_conditions = function_conditions
        
        # 获取 ConditionManager 实例并设置
        condition_manager = ConditionManager.instance()
        condition_manager.setup(
            api_list=self.all_apis,
            api_list_all=self.all_apis,  # 使用相同的 API 列表
            conditions=function_conditions
        )
        
        self.condition_manager = condition_manager
        
        logger.info("✅ Condition manager built")
        logger.info(f"   - Source APIs: {len(condition_manager.get_source_api())}")
        logger.info(f"   - Sink APIs: {len(condition_manager.get_sink_api())}")
        logger.info(f"   - Init APIs: {len(condition_manager.get_init_api())}")
        
        return condition_manager
    
    def build_data_layout(
        self,
        apis_clang_path: Optional[str] = None,
        apis_llvm_path: Optional[str] = None,
        incomplete_types_path: Optional[str] = None,
        data_layout_path: Optional[str] = None,
        enum_types_path: Optional[str] = None
    ):
        """
        初始化 DataLayout（类型布局信息）
        
        Args:
            apis_clang_path: Clang API 文件路径
            apis_llvm_path: LLVM API 文件路径
            incomplete_types_path: 不完整类型列表路径
            data_layout_path: 数据布局文件路径
            enum_types_path: 枚举类型列表路径
        """
        logger.info("📊 Building data layout...")
        
        data_layout = DataLayout.instance()
        
        # 如果提供了路径，则设置 DataLayout
        if all([apis_clang_path, apis_llvm_path, incomplete_types_path, 
                data_layout_path, enum_types_path]):
            data_layout.setup(
                apis_clang_p=apis_clang_path,
                apis_llvm_p=apis_llvm_path,
                incomplete_types_p=incomplete_types_path,
                data_layout_p=data_layout_path,
                enum_types_p=enum_types_path
            )
            logger.info("✅ Data layout initialized from files")
        # 尝试使用提取元数据自动配置
        elif self.extract_metadata:
            local_meta = self.extract_metadata.get("local", {})
            ac = local_meta.get("apis_clang")
            al = local_meta.get("apis_llvm")
            inc = local_meta.get("incomplete_types")
            dl = local_meta.get("data_layout")
            et = enum_types_path  # 仍允许外部传入
            if all([ac, al, inc, dl, et]):
                data_layout.setup(
                    apis_clang_p=ac,
                    apis_llvm_p=al,
                    incomplete_types_p=inc,
                    data_layout_p=dl,
                    enum_types_p=et
                )
                logger.info("✅ Data layout initialized from extraction metadata")
            else:
                logger.warning("Data layout files not provided (metadata incomplete), using default")
        else:
            logger.warning("Data layout files not provided, using default")
    
    def generate_drivers(
        self,
        num_drivers: int = 10,
        driver_size: int = 5,
        policy: str = "only_type",
        enable_z3_validation: bool = False
    ) -> List[Driver]:
        """
        生成 driver 列表

        Args:
            num_drivers: 要生成的 driver 数量
            driver_size: 每个 driver 中的 API 调用数量
            policy: 生成策略（"only_type" 或 "constraint_based"）
            enable_z3_validation: 是否启用Z3序列验证（仅constraint_based策略）

        Returns:
            Driver 列表
        """
        if not self.grammar:
            raise RuntimeError("No grammar. Call build_grammar() first.")

        logger.info(f"🚀 Generating {num_drivers} drivers (size={driver_size}, policy={policy})...")
        if enable_z3_validation and policy == "constraint_based":
            logger.info("   Z3 sequence validation: enabled")

        drivers = []

        # 根据策略选择 Factory
        if policy == "only_type":
            factory = self._create_ot_factory(driver_size)
        elif policy == "constraint_based":
            factory = self._create_cb_factory(driver_size, enable_z3_validation)
        else:
            raise ValueError(f"Unknown policy: {policy}. Supported: 'only_type', 'constraint_based'")
        
        # 生成 driver
        for i in range(num_drivers):
            try:
                driver = factory.create_random_driver()
                drivers.append(driver)
                logger.debug(f"Generated driver {i+1}/{num_drivers}")
            except Exception as e:
                logger.warning(f"Failed to generate driver {i+1}: {e}")
        
        logger.info(f"✅ Generated {len(drivers)} drivers")
        
        return drivers
    
    def generate_all(
        self,
        num_drivers: int = 10,
        driver_size: int = 5,
        policy: str = "only_type",
        function_conditions: Optional[FunctionConditionsSet] = None,
        **extract_kwargs
    ) -> List[Driver]:
        """
        完整的生成流程：提取 API -> 构建依赖图 -> 生成语法 -> 管理约束 -> 生成 driver
        
        Args:
            num_drivers: 要生成的 driver 数量
            driver_size: 每个 driver 中的 API 调用数量
            policy: 生成策略
            function_conditions: 函数约束条件（可选）
            **extract_kwargs: 传递给 extract_all_apis 的参数
        
        Returns:
            Driver 列表
        """
        logger.info("🎯 Starting complete driver generation pipeline...")
        
        # 1. 提取所有 API
        self.extract_all_apis(**extract_kwargs)
        
        # 2. 构建依赖图
        self.build_dependency_graph()
        
        # 3. 生成语法
        self.build_grammar()
        
        # 4. 构建约束管理器
        self.build_condition_manager(function_conditions)
        
        # 5. 生成 driver
        drivers = self.generate_drivers(
            num_drivers=num_drivers,
            driver_size=driver_size,
            policy=policy
        )
        
        logger.info("✅ Complete pipeline finished")
        
        return drivers
    
    def save_drivers(self, drivers: List[Driver], output_dir: Optional[str] = None):
        """
        保存生成的 driver 到文件
        
        Args:
            drivers: Driver 列表
            output_dir: 输出目录（默认使用 work_dir/drivers）
        """
        if output_dir is None:
            output_dir = self.work_dir / "drivers"
        else:
            output_dir = Path(output_dir)
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"💾 Saving {len(drivers)} drivers to {output_dir}...")
        
        # TODO: 实现 driver 序列化和保存逻辑
        # 这需要实现 backend（如 LibFuzzerBackend）来将 Driver 对象转换为代码
        logger.warning("Driver saving not yet implemented")
        
        return output_dir
    
    def _create_ot_factory(self, driver_size: int):
        """
        创建 OTFactory（only_type 策略）
        """
        if not self.grammar:
            raise RuntimeError("No grammar available for OTFactory")
        if not self.all_apis:
            raise RuntimeError("No APIs available for OTFactory")

        return OTFactory(
            api_list=self.all_apis,
            driver_size=driver_size,
            grammar=self.grammar
        )
    
    def _create_cb_factory(self, driver_size: int, enable_z3_validation: bool = False):
        """
        创建 CBFactory（constraint_based 策略）

        Args:
            driver_size: driver 中 API 调用的数量
            enable_z3_validation: 是否启用Z3序列验证
        """
        if not self.dependency_graph:
            raise RuntimeError("No dependency graph available for CBFactory")
        if not self.all_apis:
            raise RuntimeError("No APIs available for CBFactory")
        if not self.condition_manager:
            raise RuntimeError("No condition manager available for CBFactory. Call build_condition_manager() first.")

        bias = Bias()

        return CBFactory(
            api_list=self.all_apis,
            driver_size=driver_size,
            dgraph=self.dependency_graph,
            conditions=self.function_conditions or FunctionConditionsSet(),
            bias=bias,
            enable_z3_validation=enable_z3_validation
        )
    
    def create_backend(
        self,
        backend_type: str = "libfuzz",
        headers_dir: Optional[str] = None,
        public_headers_file: Optional[str] = None,
        num_seeds: int = 10
    ):
        """
        创建 Backend 用于生成 driver 代码
        
        Args:
            backend_type: backend 类型（目前只支持 "libfuzz"）
            headers_dir: 头文件目录
            public_headers_file: 公共头文件列表文件路径
            num_seeds: 每个 driver 的种子数量
        
        Returns:
            BackendDriver 实例
        """
        if backend_type != "libfuzz":
            raise ValueError(f"Unsupported backend type: {backend_type}. Only 'libfuzz' is supported.")
        
        if not headers_dir:
            # 尝试从 extract_metadata 获取
            if self.extract_metadata:
                local_meta = self.extract_metadata.get("local", {})
                headers_dir = local_meta.get("headers_dir")
        
        if not headers_dir:
            raise ValueError("headers_dir is required for LibFuzzer backend")
        
        if not public_headers_file:
            # 尝试从 extract_metadata 获取
            if self.extract_metadata:
                local_meta = self.extract_metadata.get("local", {})
                public_headers_file = local_meta.get("public_headers")
        
        if not public_headers_file:
            raise ValueError("public_headers_file is required for LibFuzzer backend")
        
        drivers_dir = self.work_dir / "drivers"
        seeds_dir = self.work_dir / "seeds"
        drivers_dir.mkdir(parents=True, exist_ok=True)
        seeds_dir.mkdir(parents=True, exist_ok=True)
        
        return LFBackendDriver(
            working_dir=str(drivers_dir),
            seeds_dir=str(seeds_dir),
            num_seeds=num_seeds,
            headers_dir=headers_dir,
            public_headers=public_headers_file
        )
    
    # === Internal helpers ===
    def _ensure_sources(
        self,
        include_dir: Optional[str],
        public_headers_file: Optional[str]
    ):
        """
        Ensure include_dir and public_headers_file are available.
        If not provided, try to fetch sources from OSS-Fuzz docker image.
        """
        fetched_src_dir = None
        
        if not include_dir:
            try:
                fetched_src_dir = self._fetch_source_from_oss_fuzz_image()
                include_dir = fetched_src_dir
                logger.info(f"📥 Fetched source from OSS-Fuzz image: {include_dir}")
            except Exception as e:
                logger.warning(f"Failed to fetch source from OSS-Fuzz image: {e}")
        
        if not public_headers_file and include_dir:
            try:
                headers_path = Path(self.work_dir) / "public_headers.txt"
                self._generate_public_headers_file(include_dir, headers_path)
                public_headers_file = str(headers_path)
                logger.info(f"📄 Generated public headers list: {public_headers_file}")
            except Exception as e:
                logger.warning(f"Failed to generate public headers list: {e}")
        
        # record into metadata for downstream usage
        local_meta = self.extract_metadata.get("local", {}) if self.extract_metadata else {}
        if include_dir:
            local_meta["headers_dir"] = include_dir
        if public_headers_file:
            local_meta["public_headers"] = public_headers_file
        if fetched_src_dir:
            local_meta["source_dir"] = fetched_src_dir
        if local_meta:
            self.extract_metadata["local"] = local_meta
        
        return include_dir, public_headers_file
    
    def _fetch_source_from_oss_fuzz_image(self) -> str:
        """
        Pull source code out of the OSS-Fuzz style docker image.
        
        Returns:
            Path to the extracted source directory.
        """
        image = f"gcr.io/oss-fuzz/{self.project_name}"
        logger.info(f"📦 Creating container to fetch sources from {image}")
        cid = subprocess.check_output(
            ["docker", "create", image],
            text=True
        ).strip()
        
        src_out = Path(self.work_dir) / "src_ossfuzz" / self.project_name
        src_out.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            subprocess.check_call(
                ["docker", "cp", f"{cid}:/src/{self.project_name}", str(src_out.parent)]
            )
        finally:
            subprocess.call(["docker", "rm", "-f", cid])
        
        if not src_out.exists():
            raise RuntimeError(f"Copied source not found at {src_out}")
        
        return str(src_out)
    
    def _generate_public_headers_file(self, include_dir: str, output_path: Path):
        """
        Scan include_dir for header files and write to output_path.
        """
        header_exts = {".h", ".hpp", ".hxx", ".hh"}
        header_paths = []
        for root, _, files in os.walk(include_dir):
            for f in files:
                if Path(f).suffix.lower() in header_exts:
                    header_paths.append(os.path.relpath(os.path.join(root, f), include_dir))
        
        if not header_paths:
            raise RuntimeError(f"No headers found under {include_dir}")
        
        with open(output_path, "w") as f:
            for h in sorted(header_paths):
                f.write(h + "\n")
    
    def save_drivers(
        self,
        drivers: List[Driver],
        backend: Optional[LFBackendDriver] = None,
        output_dir: Optional[str] = None
    ):
        """
        保存生成的 driver 到文件（使用 backend 生成代码）
        
        Args:
            drivers: Driver 列表
            backend: BackendDriver 实例（如果为 None，会尝试自动创建）
            output_dir: 输出目录（已弃用，backend 会使用自己的 working_dir）
        
        Returns:
            保存的 driver 文件列表
        """
        if backend is None:
            logger.info("No backend provided, attempting to create LibFuzzer backend...")
            try:
                backend = self.create_backend()
            except Exception as e:
                raise RuntimeError(
                    f"Failed to create backend automatically: {e}\n"
                    f"Please provide backend explicitly or ensure headers_dir and public_headers_file are available."
                ) from e
        
        logger.info(f"💾 Saving {len(drivers)} drivers using {type(backend).__name__}...")
        
        saved_files = []
        for driver in drivers:
            try:
                driver_filename = backend.get_name()
                backend.emit_driver(driver, driver_filename)
                backend.emit_seeds(driver, driver_filename)
                saved_files.append(driver_filename)
                logger.debug(f"Saved driver: {driver_filename}")
            except Exception as e:
                logger.warning(f"Failed to save driver: {e}")
        
        logger.info(f"✅ Saved {len(saved_files)} drivers")
        
        return saved_files

