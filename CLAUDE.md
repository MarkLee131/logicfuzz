# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LogicFuzz is an LLM-powered automated fuzz driver generation system that uses LangGraph-based agent workflows to generate LibFuzzer fuzz targets for C/C++ libraries. It extends and adapts the Liberator framework (FSE'25) with LLM-assisted semantic analysis.

## Build & Environment Setup

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# For Liberator condition extractor (optional, for deeper static analysis):
cd liberator_adapter
./setup_environment.sh  # Installs SVF, Z3, LLVM dependencies to ~/logicfuzz_deps
cd liberator/condition_extractor && ./bootstrap.sh
```

Environment variables (set in `logicfuzz.env`):
- `DASHSCOPE_API_KEY` - Qwen/DashScope API key
- `OPENAI_API_KEY` - OpenAI API key
- `DEEPSEEK_API_KEY` - DeepSeek API key

## Running Experiments

```bash
# Run on a single benchmark
python3 run_logicfuzz.py --benchmark-yaml comparison/cjson.yaml

# Run with specific model
python3 run_logicfuzz.py --benchmark-yaml comparison/curl.yaml --model gpt-4

# View LLM logs
python3 scripts/view_llm_logs.py
```

Benchmark YAML files in `comparison/` define "target projects" to fuzz.

---

## 核心架构

### Agent框架

基于LangGraph的多Agent协作系统：

| Agent | 文件 | 功能 |
|-------|------|------|
| **LangGraphPrototyper** | `src/agents/prototyper.py` | 生成fuzz target代码，使用synthesized drivers作为LLM refinement基础 |
| **LangGraphCoverageAnalyzer** | `src/agents/coverage_analyzer.py` | 分析覆盖率，提取改进建议 |
| **LangGraphCrashAnalyzer** | `src/agents/crash_analyzer.py` | 使用GDB+Bash工具分析crash |
| **LangGraphCrashFeasibilityAnalyzer** | `src/agents/crash_feasibility_analyzer.py` | 判断crash可行性 |
| **LangGraphFixer** | `src/agents/fixer.py` | 修复编译/运行时错误 |
| **LangGraphImprover** | `src/agents/improver.py` | 基于覆盖率分析改进fuzz target |

**ToolCallingMixin** (`src/agents/tool_calling_mixin.py`):
- ReAct风格的工具调用循环
- 支持并行工具执行（最多4个worker）
- 自动检测结论并终止循环

### LLM工具：FuzzIntrospector集成

LLM agents使用FuzzIntrospector工具获取原始信息，自行分析特殊模式（var-len、loop、callback、TLV）：

| Tool | 功能 | 用途 |
|------|------|------|
| `get_function_implementation` | 获取函数源码 | 理解函数内部逻辑 |
| `get_sample_cross_references` | 获取调用示例 | 学习正确的调用模式 |
| `get_function_signature` | 获取函数签名 | 确认参数类型 |
| `get_tests_for_functions` | 获取测试用例 | 参考测试代码 |

**设计原则**：
- 直接使用FI获取**原始信息**（源码、示例）
- **不依赖静态分析结论** - 静态分析可能误导LLM
- LLM基于源码和示例**自行判断**特殊模式

**实现文件**: `src/tools/langchain_adapters.py`

### 数据流

```
ProjectDriverGenerator
    ↓ 提取APIs, 构建grammar
FuzzingContext.prepare_project_level()
    ↓ 生成API序列
CBFactory (Z3引导合成)
    ↓ 约束求解 + 增量验证生成skeleton drivers
LangGraphPrototyper
    ↓ LLM refinement
FuzzTarget (可编译的driver)
```

### 关键数据结构

**FuzzingContext** (`src/context/data_context.py`):
- 不可变dataclass，存储fuzzing工作流所有数据
- `project_apis`: 提取的所有API
- `api_sequences`: 从grammar生成的调用序列
- `dependency_graph`: 类型依赖图
- `pattern_analysis`: VarLen/Loop/Callback/TLV分析结果
- `skeleton_drivers`: 预生成的driver骨架
- `synthesized_drivers`: CBFactory生成的完整drivers

---

## Liberator静态分析瓶颈与解决策略

### 瓶颈分类总览

| ID | 问题 | 影响 | 解决策略 | 状态 |
|----|------|------|----------|------|
| **L1** | 类型依赖过度连接 | 误报多 | LLM语义过滤 | ✅ 已实现 |
| **L2** | Var-len关系硬编码 | 不完整 | LLM推断 | ✅ 已实现 |
| **L3** | 回调函数处理 | 丢失路径 | Stub + LLM补全 | ✅ 已实现 |
| **L4** | 循环API调用 | 不支持 | 模式识别 | ✅ 已实现 |
| **L5** | API角色识别 | 启发式 | LLM分类 | ✅ 已实现 |
| **L6** | 生命周期追踪 | 不精确 | LLM验证 | ✅ 已实现 |
| **L7** | Guard条件提取 | 未实现 | 延后 | ❌ 延后 |

---

### L1. 类型依赖过度连接

**问题**: 类型匹配 ≠ 调用依赖
```
所有返回 cJSON* 的函数 → 被认为是所有接受 cJSON* 参数的函数的依赖
结果: 依赖数量虚高 (最多79个依赖)
```

**解决策略**: ✅ 已实现
- **ProvenanceChecker** (`liberator_adapter/constraints/provenance_checker.py`): 区分指针来源
  - 支持多种provenance tag: HEAP_MALLOC, RETURN_OPAQUE, PARAM_BORROWED等
  - 兼容性规则过滤不合理的依赖路径
- **LLMSequenceFilter** (`liberator_adapter/constraints/sequence_filter.py`): 两阶段过滤
  - 基础过滤: 空序列、长度限制(max 20)
  - LLM语义验证: 批量API分类

---

### L2. Var-len关系硬编码

**问题**: 数组长度与size参数的关系是启发式猜测
```c
void process(char* data, size_t len);  // data长度 = len?
void read(void* buf, size_t size, size_t count, FILE* f);  // buf长度 = size*count?
```

**解决策略**: ✅ 已实现 `VarLenAnalyzer`

**实现**: `liberator_adapter/constraints/special_patterns.py:65-348`

- **Phase 1 (静态分析)**:
  - 识别(pointer, integer)参数对
  - 指针类型模式: `char*`, `void*`, `uint8_t*`等
  - 命名模式: `buf/buffer/data` + `len/length/size`
  - 相邻参数检测

- **Phase 2 (LLM确认)**:
  - 可选的LLM验证语义关系
  - 处理复杂关系: `size*count`, headers等
  - 当LLM不可用时fallback到启发式

- **缓存**: 按API缓存分析结果

---

### L3. 回调函数(Function Pointer)处理

**问题**: 静态分析无法追踪函数指针的实际目标
```c
typedef void (*callback_t)(void* data, int result);
void async_operation(callback_t cb, void* user_data);
```

**解决策略**: ✅ 已实现 `CallbackAnalyzer`

**实现**: `liberator_adapter/constraints/special_patterns.py:612-902`

- **Phase 1 (模式检测)**:
  - 函数指针类型识别: `(*)(...)`, `type (*)(...)`
  - 关键词检测: `_func`, `_callback`, `_handler`, `_hook`
  - 基于类型的分类

- **Phase 2 (LLM生成)**:
  - 可选的LLM生成专用stub
  - 预置8种回调类型模板:
    - COMPARATOR: qsort风格
    - READER/WRITER: 流式读写
    - ALLOCATOR/DEALLOCATOR: 内存管理
    - VISITOR: 树遍历
    - HANDLER: 事件回调

- **DriverEnhancer集成** (`liberator_adapter/driver/driver_enhancer.py`):
  - `EnhancedCallbackStubGenerator`: 基于CallbackAnalyzer生成定制stub

---

### L4. 循环API调用

**问题**: 图遍历不处理循环依赖
```
A → B → C → A  (循环)
result: 无限展开 或 截断
```

**解决策略**: ✅ 已实现 `LoopPatternAnalyzer`

**实现**: `liberator_adapter/constraints/special_patterns.py:375-572`

- **Phase 1 (命名模式检测)**:
  - 迭代器模式: `_next`, `_iterate`, `_foreach`, `get_next`
  - 增量模式: `_read`, `_recv`, `_fetch`, `_pull`
  - 状态机模式: `_process`, `_run`, `_execute`, `_tick`
  - 返回类型分析: bool/int/ssize_t/size_t 表示继续条件

- **Phase 2 (LLM确认)**:
  - 细化循环类型和终止条件
  - 生成代码模板

- **循环类型**: ITERATOR, INCREMENTAL, STATE_MACHINE, NONE
- **安全限制**: 最大迭代100次

---

### L5. API角色识别

**问题**: 依赖函数名模式匹配
```
*_create, *_new → CREATE
*_free, *_destroy → CLEANUP
```

**解决策略**: ✅ 已实现 `LLMLifecycleValidator`

**实现**: `liberator_adapter/constraints/sequence_filter.py:87-366`

- 完全使用LLM进行语义分类，移除硬编码启发式
- **生命周期阶段**: CREATE, INIT, USE, CLEANUP, UNKNOWN
- **批量操作**: 单次LLM调用处理多个API
- **缓存**: 字典缓存避免重复查询
- **Fallback**: LLM不可用时优雅降级

---

### L6. 生命周期追踪

**问题**: `Access`枚举过于简化
```python
class Access(Enum):
    READ, WRITE, RETURN, CREATE, DELETE, NONE
```

**解决策略**: ✅ 已实现 LLM验证
- `LLMLifecycleValidator.validate_sequence()`: 完整序列生命周期验证
- 检测生命周期违规: use-after-free, double-free等
- 返回`LifecycleValidationResult`包含violation列表

---

### L7. Guard条件提取

**问题**: 未提取API调用的前提条件
```c
if (ctx->initialized) {
    process(ctx);  // Guard: ctx->initialized == true
}
```

**影响**: 生成的driver可能违反前提条件

**状态**: ❌ 延后实现
- 需要更复杂的静态分析
- 可以用LLM从文档/注释推断

---

### 特殊场景实现状态

| 场景 | Phase 1 (静态) | Phase 2 (LLM) | Driver生成 | 实现位置 |
|------|----------------|---------------|------------|----------|
| **S1. Var-len** | ✅ 类型+命名匹配 | ✅ LLM确认 | ✅ 模板生成 | `VarLenAnalyzer` |
| **S2. TLV** | ✅ 解析函数识别 | ✅ LLM确认 | ✅ 格式检测 | `TLVAnalyzer` |
| **S3. Loop** | ✅ 模式识别 | ✅ LLM确认 | ✅ 有界循环 | `LoopPatternAnalyzer` |
| **S4. Callback** | ✅ 函数指针检测 | ✅ LLM生成 | ✅ 8种Stub模板 | `CallbackAnalyzer` |

**统一接口**: `SpecialPatternAnalyzer` (`special_patterns.py:1110-1200`)
- 协调所有四种分析器
- 提供便捷方法: `get_varlen_relations()`, `needs_loop()`, `get_callbacks()`, `is_structured_parser()`

**TLVAnalyzer** (`special_patterns.py:931-1093`):
- 解析函数识别: `_parse`, `_decode`, `_deserialize`, `_unmarshal`, `_unpack`
- 格式类型: TLV, FIXED_HEADER, LENGTH_PREFIXED, RAW, UNKNOWN
- 提取magic bytes和约束条件

---

## 程序合成

### CBFactory (Z3引导合成)

**位置**: `liberator_adapter/driver/factory/constraint_based/CBFactory.py`

基于约束的driver合成，Z3作为**核心决策参与者**（非后置验证器）:

#### 核心改进：Z3引导决策

**原流程问题**:
```
暴力尝试source APIs → 暴力尝试producers → 生成driver → Z3验证(失败就reject)
```

**新流程**:
```
Z3评估source APIs可行性 → 返回排序列表
    ↓
Z3引导producer选择 → 只尝试SAT的选项
    ↓
每添加API增量验证 → 早期发现冲突
    ↓
UNSAT时分析core → 智能backtrack
```

#### 关键组件

| 组件 | 文件 | 功能 |
|------|------|------|
| `IncrementalZ3Solver` | `constraints/z3_guided_synthesis.py` | Push/pop增量求解，支持checkpoint回滚 |
| `Z3GuidedSynthesisController` | `constraints/z3_guided_synthesis.py` | 高层协调器，管理资源追踪和候选评估 |
| `UnsatCoreDiagnoser` | `constraints/z3_guided_synthesis.py` | 分析unsat core，诊断失败原因并建议恢复策略 |

#### 决策点集成

**D1: Source API选择** (`_try_all_source_apis`):
```python
# Z3评估每个source API
for api in source_apis:
    result = z3_controller.solver.check_candidate(api, required_types, produced_types)
    if result.is_feasible:
        candidates.append((api, result.score + complexity_score))

# 按score排序，优先尝试简单的
candidates.sort(key=lambda x: x[1])
```

**D2: 初始化链查找** (`_try_find_init_chain`):
```python
# Z3评估producer可行性
for producer in producers:
    result = z3_controller.solver.check_candidate(producer, ...)
    if result.is_feasible:
        producer_candidates.append((producer, score))

# 每添加producer都增量验证
z3_controller.add_api_to_sequence(producer, position, required, produced)
```

**D3: 候选API评估** (`_evaluate_candidates_with_z3`):
```python
# 在主循环中评估下一个API候选
scored = z3_controller._evaluate_candidates_with_z3(candidates, position)
best_api = scored[0]  # 选择最优候选
```

#### 资源追踪

```python
# 追踪已产生的资源类型
z3_controller.solver.add_resource_produced("cJSON*", "cJSON_Parse", "var_0")

# 检查所需资源是否可用
z3_controller.solver.add_resource_required("cJSON*", "cJSON_Print")

# check_candidate会验证资源可用性
result = solver.check_candidate("cJSON_Print", required=["cJSON*"], produced=["char*"])
# result.is_feasible = True (因为cJSON*已被cJSON_Parse产生)
```

#### 失败诊断

```python
class DiagnosisType(Enum):
    MISSING_RESOURCE    # 缺少所需资源 → 建议ADD_PRODUCER
    LIFECYCLE_VIOLATION # 生命周期违规 → 建议REORDER_APIS
    TYPE_MISMATCH       # 类型不兼容 → 建议TRY_DIFFERENT_SOURCE
    ORDER_VIOLATION     # 顺序约束违规 → 建议REORDER_APIS
```

#### 配置选项

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `enable_z3_guidance` | `True` | 启用Z3引导决策 |
| `z3_strict_mode` | `True` | 严格模式：Z3失败时报错（便于调试） |
| `z3_timeout_ms` | `1000` | Z3求解超时（毫秒） |

#### 其他组件

- **ConditionManager**: 约束管理，识别source/sink/init APIs
- **RunningContext**: 管理变量和约束状态
- **DriverEnhancer**: 生成增强callback stub

### 序列生成

**函数**: `_generate_sequences_from_grammar()` (`src/context/data_context.py`)

从grammar生成API调用序列:
1. 从起始符号随机展开grammar
2. 非终结符展开（带回溯）
3. 提取终结符作为API序列
4. 过滤（最少2个API调用）
5. 展开失败时fallback到简单API列表

---

## 不处理的Corner Cases（scope外）

1. **跨线程/全局状态协议** - 需要动态分析
2. **复杂所有权转移** - borrowed pointer, refcount协议
3. **异步/重入回调** - event loop, reentrancy
4. **宏展开** - 除非在编译后IR上做
5. **Deep alias精确性** - 只做may-alias

---

## 已完成

1. [x] **Z3引导合成** (`liberator_adapter/constraints/z3_guided_synthesis.py`)
   - Z3从后置验证器转变为核心决策参与者
   - 增量求解 + checkpoint回滚
   - Source API可行性评估和排序
   - 初始化链的Z3引导查找
   - Unsat core诊断和恢复建议

---

## 待完成

1. [ ] **从OSS-Fuzz drivers提取状态机知识**
   - 分析现有fuzz drivers的API调用模式
   - 提取跨项目的通用状态机规则
   - 目前延后，后面根据driver问题来确定提取内容

2. [ ] **public headers信息获取**
   - 使用fuzz introspector获取
   - 或使用逆拓扑排序手动获取

3. [ ] **Guard条件提取 (L7)** - 延后

4. [ ] **DriverEnhancer完善**
   - Callback stub生成已完成
   - VarLen、Loop、TLV的driver集成待完善

5. [ ] **核心功能识别**
   - 识别并标注library的核心功能（如lcms的颜色转换cmsCreateTransform+cmsDoTransform）
   - 从现有fuzzers中提取API使用pattern（如"必须先创建两个profile，再创建transform"）