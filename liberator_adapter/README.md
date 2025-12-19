# Liberator Adapter

将 Liberator 的 API 建模技术集成到 LogicFuzz 的适配器模块。

## 数据源

适配器支持两种数据源：

1. **FuzzIntrospector API**（默认）
   - 使用 `APIContextExtractor` 从 FuzzIntrospector 提取函数信息
   - 通过适配器推断 `flag`、`size`、`const` 等信息
   - 适用于快速原型和测试
   - **注意**：此模式下需要 FuzzIntrospector API 可用

2. **Clang/LLVM 直接提取**（推荐，更精确）⭐
   - 使用 Liberator 工具直接从源代码提取
   - Clang 提取：从头文件提取 `type_clang` 和 `const` 信息
   - LLVM 提取：从 bitcode 提取 `flag` 和 `size` 信息
   - 提供更精确的 API 信息
   - **重要**：此模式下**不再需要 FuzzIntrospector** 来提取 context
   - 直接从源代码分析，不依赖外部 API

### 关于 FuzzIntrospector 的说明

- **在 `LiberatorAPIAdapter` 中**：
  - Clang/LLVM 模式（`use_clang_llvm=True`）：**不需要** FuzzIntrospector
  - FuzzIntrospector 模式（默认）：**需要** FuzzIntrospector API

- **在整个 LogicFuzz 系统中**：
  - FuzzIntrospector 仍被其他模块使用（如 `api_dependency_analyzer`、`api_composition_analyzer` 等）
  - 这些模块的用途与 `LiberatorAPIAdapter` 不同，主要用于 API 依赖分析和组合分析

### 使用 Clang/LLVM 提取器

```python
from experiment.benchmark import Benchmark
from liberator_adapter.adapter import LiberatorAPIAdapter

# 创建基准对象
benchmark = Benchmark(project='zlib', ...)

# 使用 Clang/LLVM 模式
adapter = LiberatorAPIAdapter(
    project_name='zlib',
    use_clang_llvm=True,
    benchmark=benchmark
)

# 提取单个函数
api = adapter.convert_to_liberator_api(
    'int adler32(unsigned int adler, const unsigned char *buf, unsigned int len)'
)

# 或提取所有 API
all_apis = adapter.extract_all_apis(
    function_signatures=['int adler32(...)', 'int crc32(...)']
)

# 清理资源
adapter.cleanup()
```

更多信息请参考 [extractors/README.md](extractors/README.md)。

## 目录结构

```
liberator_adapter/
├── __init__.py
├── adapter.py              # 适配器接口
├── common/                 # 核心数据结构
│   ├── api.py             # Api, Arg 类
│   ├── conditions.py      # 条件约束相关类
│   ├── datalayout.py      # 类型布局管理
│   └── utils.py           # 工具函数
├── dependency/            # 依赖图生成
│   ├── DependencyGraph.py
│   ├── DependencyGraphGenerator.py
│   └── type/
│       └── TypeDependencyGraphGenerator.py
├── constraints/           # 约束管理
│   ├── ConditionManager.py
│   ├── Conditions.py
│   └── RunningContext.py
├── grammar/               # 语法生成
│   ├── GrammarGenerator.py
│   └── ...
└── driver/                # 最小化驱动接口
    ├── ir/                # 中间表示
    │   ├── Type.py
    │   └── PointerType.py
    └── factory/            # 工厂类
        └── Factory.py
```

## 核心功能

### 1. API 建模
- `Api` 和 `Arg` 类：结构化的 API 表示
- 支持类型、参数、返回值等完整信息

### 2. 依赖图生成
- `TypeDependencyGraphGenerator`：基于类型匹配生成 API 依赖图
- `DependencyGraph`：表示 API 之间的依赖关系

### 3. 约束管理
- `ConditionManager`：管理 API 调用的约束条件
- 支持 source、sink、init 等 API 分类

### 4. 语法生成
- `GrammarGenerator`：从依赖图生成语法规则
- 支持上下文无关语法生成

## 使用示例

```python
from liberator_adapter.adapter import LiberatorAPIAdapter
from liberator_adapter.dependency import TypeDependencyGraphGenerator

# 创建适配器
adapter = LiberatorAPIAdapter(project_name="my_project")

# 转换函数为 Api 对象
api = adapter.convert_to_liberator_api("int curl_easy_setopt(CURL *, int, ...)")

# 生成依赖图
apis_list = [api1, api2, ...]  # 收集所有相关 API
dep_gen = TypeDependencyGraphGenerator(apis_list)
dep_graph = dep_gen.create()
```

## 注意事项

1. **DataLayout 初始化**：某些功能需要先初始化 `DataLayout.instance()`，提供类型布局信息
2. **最小化实现**：`driver` 模块只包含类型规范化所需的最小功能
3. **依赖关系**：部分高级功能（如 `ConditionManager` 的完整功能）可能需要额外的 driver 类

## 与 Liberator 的区别

- **独立模块**：完全独立的代码，不依赖原 liberator 文件夹
- **适配 LogicFuzz**：针对 LogicFuzz 的使用场景进行了适配
- **最小化依赖**：只包含核心功能，减少不必要的依赖

## 项目级 Driver 生成

### ProjectDriverGenerator

`ProjectDriverGenerator` 提供了完整的项目级 driver 生成功能，不需要指定单个 API。

**功能特性：**
- ✅ 提取项目中的所有 API
- ✅ 生成类型依赖图
- ✅ 生成语义序列（Grammar）
- ✅ 管理约束条件（ConditionManager）
- ✅ 生成 driver 代码

**使用示例：**

```python
from experiment.benchmark import Benchmark
from liberator_adapter.project_driver_generator import ProjectDriverGenerator

# 创建 Benchmark 对象
benchmark = Benchmark(project='zlib', ...)

# 创建项目级 driver 生成器
generator = ProjectDriverGenerator(
    project_name='zlib',
    benchmark=benchmark,
    use_clang_llvm=True,
    work_dir='./workdir_zlib'
)

# 完整流程：生成 driver
drivers = generator.generate_all(
    num_drivers=10,
    driver_size=5,
    policy='only_type'
)
```

**分步执行：**

```python
# 1. 提取所有 API
generator.extract_all_apis()

# 2. 构建类型依赖图
generator.build_dependency_graph()

# 3. 生成语义序列（Grammar）
generator.build_grammar()

# 4. 构建约束管理器
generator.build_condition_manager()

# 5. 生成 driver
drivers = generator.generate_drivers(num_drivers=10, driver_size=5)
```

更多信息请参考 [project_driver_generator.py](project_driver_generator.py) 和 [project_driver_generator_example.py](project_driver_generator_example.py)。

## 已接入的 Liberator 功能

### ✅ 已接入
1. **类型系统**：类型依赖图生成（`TypeDependencyGraphGenerator`）
2. **语义序列**：语法生成器（`GrammarGenerator`）
3. **约束管理**：条件管理器（`ConditionManager`）
4. **项目级生成**：`ProjectDriverGenerator` 支持对整个项目生成 driver

### 🚧 部分实现
1. **Driver Factory**：基础 Factory 已实现，完整的 OTFactory/CBFactory 需要进一步实现
2. **Backend**：Driver 代码生成和保存功能需要实现

## 下一步

1. ✅ 集成到 LogicFuzz 的 API 依赖分析流程
2. ✅ 实现混合分析器（结合 Liberator 和 LogicFuzz 的分析方法）
3. ✅ 实现项目级 driver 生成
4. 🚧 完善 Factory 实现（OTFactory/CBFactory）
5. 🚧 实现 Backend（LibFuzzerBackend）用于生成和保存 driver 代码

