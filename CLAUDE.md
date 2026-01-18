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

## Architecture

### LangGraph Workflow (`agent_graph/`)
The core fuzzing loop is a LangGraph state machine:
- **State**: `FuzzingWorkflowState` in `state.py` - shared state across all nodes
- **Workflow**: `FuzzingWorkflow` in `workflow.py` - orchestrates the agent graph
- **Nodes** (`nodes/`):
  - `function_analyzer_node.py` - Analyzes target function requirements
  - `prototyper_node.py` - Generates initial fuzz target
  - `execution_node.py` - Builds and runs the fuzzer
  - `supervisor_node.py` - Routes between nodes based on results
  - `crash_analyzer_node.py` - Analyzes crashes

### Liberator Adapter (`liberator_adapter/`)
Integrates Liberator's static analysis for API modeling:
- `adapter.py` - Main adapter interface (`LiberatorAPIAdapter`)
- `common/api.py` - `Api` and `Arg` data structures
- `dependency/type/TypeDependencyGraphGenerator.py` - Builds API dependency graphs based on type matching
- `constraints/` - Constraint management (`ConditionManager`, `RunningContext`)
- `grammar/GrammarGenerator.py` - Generates API call sequences from dependency graph
- `project_driver_generator.py` - End-to-end driver generation for a project

### Prompts (`prompts/`)
Agent prompts are file-based for easy modification:
- `{agent_name}_system.txt` - System prompt defining agent role
- `{agent_name}_prompt.txt` - User prompt template with `{PLACEHOLDER}` syntax

Load prompts via `agent_graph/prompt_loader.py`:
```python
from agent_graph.prompt_loader import get_prompt_manager
pm = get_prompt_manager()
system = pm.get_system_prompt("prototyper")
prompt = pm.build_user_prompt("prototyper", project_name="zlib", ...)
```

---

### 可丢弃的Corner Cases（论文中说明）

1. **跨线程/全局状态协议** - 需要动态分析才可靠
2. **复杂所有权转移** - 如borrowed pointer, refcount复杂协议
3. **异步/重入回调** - event loop, reentrancy
4. **宏展开导致的guard/field write** - 除非在编译后IR上做
5. **Deep alias精确性** - 只做may-alias，不做must-alias


---

## Liberator静态分析瓶颈与解决策略

### 瓶颈分类总览

| ID | 问题 | 影响 | 解决策略 |
|----|------|------|----------|
| **L1** | 类型依赖过度连接 | 误报多 | LLM语义过滤 |
| **L2** | Var-len关系硬编码 | 不完整 | LLM推断 |
| **L3** | 回调函数处理 | 丢失路径 | Stub + LLM补全 |
| **L4** | 循环API调用 | 不支持 | 模式识别 |
| **L5** | API角色识别 | 启发式 | LLM分类 |
| **L6** | 生命周期追踪 | 不精确 | LLM验证 |
| **L7** | Guard条件提取 | 未实现 | 延后 |

---

### L1. 类型依赖过度连接

**问题**: 类型匹配 ≠ 调用依赖
```
所有返回 cJSON* 的函数 → 被认为是所有接受 cJSON* 参数的函数的依赖
结果: 依赖数量虚高 (最多79个依赖)
```

**当前状态**: 接受过度连接，后续用LLM过滤

**解决策略**:
- ✅ Provenance追踪（已实现）: 区分指针来源
- ✅ LLM语义验证（已实现）: `LLMSequenceFilter`

---

### L2. Var-len关系硬编码

**问题**: 数组长度与size参数的关系是启发式猜测
```c
void process(char* data, size_t len);  // data长度 = len?
void read(void* buf, size_t size, size_t count, FILE* f);  // buf长度 = size*count?
```

**Liberator做法**: 硬编码 `len_depends_on` 字段

**局限性**:
- 无法处理复杂计算: `len = size * count + header_size`
- 无法处理间接关系: 长度存在struct字段里
- 无法处理条件关系: `if (flag) len = a; else len = b;`

**解决策略**: LLM推断
```python
# Prompt: 分析函数参数间的长度关系
VARLEN_ANALYSIS_PROMPT = '''
Analyze the relationship between buffer and size parameters:
Function: {signature}
Which parameter specifies the length/size of which buffer?
'''
```

---

### L3. 回调函数(Function Pointer)处理

**问题**: 静态分析无法追踪函数指针的实际目标
```c
typedef void (*callback_t)(void* data, int result);
void async_operation(callback_t cb, void* user_data);
```

**Liberator做法**: 生成stub函数
```c
void stub_callback(void* data, int result) {
    // 空实现
}
```

**局限性**:
- 丢失回调内的资源操作
- 无法验证回调的约束条件
- 异步/事件驱动API不完整

**解决策略**:
1. **保守策略**: 保留stub，接受不完整
2. **LLM补全**: 让LLM生成合理的回调实现
3. **模式库**: 收集常见回调模式（如comparator, visitor）

---

### L4. 循环API调用

**问题**: 图遍历不处理循环依赖
```
A → B → C → A  (循环)
result: 无限展开 或 截断
```

**常见需要循环的模式**:
```c
// 迭代器模式
while ((item = get_next(iter)) != NULL) {
    process(item);
}

// 增量读取
while (bytes_read < total) {
    bytes_read += read(buf, remaining);
}
```

**解决策略**:
1. 识别常见循环模式
2. 生成有界循环（最多N次）
3. LLM识别是否需要循环

---

### L5. API角色识别

**问题**: 依赖函数名模式匹配
```
*_create, *_new → CREATE
*_free, *_destroy → CLEANUP
```

**局限性**:
- 命名不规范的API漏识别
- 语义复杂的API误判（如`realloc`既是CREATE又是CLEANUP）
- 项目特定命名无法覆盖

**解决策略**: ✅ 已实现 `LLMLifecycleValidator`
- 移除硬编码启发式
- 完全使用LLM进行语义分类

---

### L6. 生命周期追踪

**问题**: `Access`枚举过于简化
```python
class Access(Enum):
    READ, WRITE, RETURN, CREATE, DELETE, NONE
```

**局限性**:
- 无法追踪多阶段生命周期: UNINITIALIZED → ALIVE → DEAD
- 无法检测: use-after-free, double-free, uninitialized use
- 无法处理所有权转移

**解决策略**: ✅ 已实现 LLM验证
- `LLMLifecycleValidator.validate_sequence()`
- 检测生命周期违规

---

### L7. Guard条件提取

**问题**: 未提取API调用的前提条件
```c
if (ctx->initialized) {
    process(ctx);  // Guard: ctx->initialized == true
}
```

**影响**: 生成的driver可能违反前提条件

**解决策略**: 延后实现
- 需要更复杂的静态分析
- 可以用LLM从文档/注释推断

---

### 特殊场景实现状态

| 场景 | Phase 1 (静态) | Phase 2 (LLM) | Driver生成 |
|------|----------------|---------------|------------|
| **S1. Var-len** | ✅ 类型+命名匹配 | ✅ LLM确认 | ⚠️ 模板 |
| **S2. TLV** | ✅ 解析函数识别 | ✅ LLM确认 | ⚠️ 模板 |
| **S3. Loop** | ✅ 模式识别 | ✅ LLM确认 | ⚠️ 模板 |
| **S4. Callback** | ✅ 函数指针检测 | ✅ LLM生成 | ✅ Stub模板 |

**实现文件**: `liberator_adapter/constraints/special_patterns.py`
- `VarLenAnalyzer` - 变长参数分析
- `LoopPatternAnalyzer` - 循环模式分析
- `CallbackAnalyzer` - 回调函数分析
- `TLVAnalyzer` - TLV格式分析
- `SpecialPatternAnalyzer` - 统一分析器

---

### 解决策略总结

| 策略 | 适用瓶颈 | 实现状态 |
|------|----------|----------|
| **Provenance追踪** | L1 | ✅ 已实现 |
| **LLM语义过滤** | L1, L5, L6 | ✅ 已实现 |
| **LLM角色分类** | L5 | ✅ 已实现 |
| **LLM生命周期验证** | L6 | ✅ 已实现 |
| **Var-len分析** | L2, S1 | ✅ 已实现 |
| **TLV格式识别** | S2 | ✅ 已实现 |
| **循环模式识别** | L4, S3 | ✅ 已实现 |
| **回调Stub生成** | L3, S4 | ✅ 已实现 |
| **Guard提取** | L7 | ❌ 延后 |

---

### 设计原则

1. **宁可误报，不可漏报**: 静态分析Phase 1允许误报，Phase 2用LLM过滤
2. **LLM作为语义增强层**: 静态分析提供候选，LLM确认语义正确性
3. **渐进式改进**: 先处理高频场景，低频corner case延后
4. **可观测性**: 每个决策都有reason，便于调试
5. **模板化生成**: 常见模式使用预定义模板，减少LLM负担

---

### 不处理的Corner Cases（scope外）

1. **跨线程/全局状态协议** - 需要动态分析
2. **复杂所有权转移** - borrowed pointer, refcount协议
3. **异步/重入回调** - event loop, reentrancy
4. **宏展开** - 除非在编译后IR上做
5. **Deep alias精确性** - 只做may-alias

---

2026/01/15 
合方案：Path A + Path B 组件增强

                      Path A 基础架构
                            │
      ┌─────────────────────┼─────────────────────┐
      │                     │                     │
      ▼                     ▼                     ▼
  ┌─────────┐        ┌───────────┐        ┌───────────────┐
  │ CBFactory│        │ Driver IR │        │ LFBackendDriver│
  │ (约束求解)│        │ (11种语句) │        │ (代码生成)     │
  └────┬────┘        └─────┬─────┘        └───────┬───────┘
       │                   │                      │
       │    Path B 组件增强  │                      │
       ▼                   ▼                      ▼
  ┌─────────────┐   ┌────────────┐        ┌─────────────┐
  │DriverEnhancer│   │ Hole系统   │        │ Stub增强生成 │
  │ (已完成)     │   │ (待集成)   │        │ (待增强)     │
  └─────────────┘   └────────────┘        └─────────────┘

  可以替换/增强的部分
  ┌────────────────┬────────────────────────┬──────────────────────────┬────────┐
  │      组件      │   当前状态 (Path A)    │   增强方案 (用 Path B)   │ 复杂度 │
  ├────────────────┼────────────────────────┼──────────────────────────┼────────┤
  │ Callback Stub  │ 简单 MD5 命名 + 空实现 │ ✅ 已集成 DriverEnhancer │ 已完成 │
  ├────────────────┼────────────────────────┼──────────────────────────┼────────┤
  │ 循环模式       │ 展平为多次调用         │ ✅ 已集成到序列生成      │ 已完成 │
  ├────────────────┼────────────────────────┼──────────────────────────┼────────┤
  │ Var-len 约束   │ 硬编码 len_depends_on  │ 可用 VarLenAnalyzer 增强 │ 低     │
  ├────────────────┼────────────────────────┼──────────────────────────┼────────┤
  │ 错误处理       │ 固定 AssertNull        │ 可用 LLM 生成智能检查    │ 中     │
  ├────────────────┼────────────────────────┼──────────────────────────┼────────┤
  │ 资源清理       │ 固定 CleanBuffer       │ 可用 LLM 优化顺序        │ 中     │
  ├────────────────┼────────────────────────┼──────────────────────────┼────────┤
  │ TLV/结构化数据 │ counter_size 硬编码    │ 可用 TLVAnalyzer 增强    │ 中     │
  └────────────────┴────────────────────────┴──────────────────────────┴────────┘




### 待完成

1. 查看results文件夹下，生成的driver是否存在问题。 同时，run.log有运行的终端输出。


2. [ ] **从OSS-Fuzz drivers提取状态机知识**
   - 分析现有fuzz drivers的API调用模式
   - 提取跨项目的通用状态机规则
   - 目前延后了。后面打算根据driver问题来确定我们这里提取什么

3. [ ] **public headers信息获取**
   - 使用fuzz introspector获取
   - 或使用逆拓扑排序手动获取 （？）

4. [ ] Guard条件提取 (L7) - 延后