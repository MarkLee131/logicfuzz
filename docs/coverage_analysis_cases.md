# Coverage Analysis Cases

记录各项目的 coverage diff 分析，用于识别跨项目的共性问题，避免局部最优设计。

## 分析框架

每个项目按以下维度分析：

1. **基线数据**: OSS-Fuzz 原始覆盖率、函数覆盖率、静态可达性
2. **LogicFuzz 结果**: coverage diff、生成的 sequences 数量
3. **Filter Pipeline 效果**: L0→L1→L2→L3→L4 各层过滤比例
4. **API 覆盖分析**: 高价值未覆盖 APIs、Entry Point 识别情况
5. **瓶颈识别**: 限制覆盖率提升的主要因素
6. **改进方向**: 针对该项目的潜在优化点

---

## Case 1: libucl

**测试时间**: 2026-04-03

### 基线数据 (OSS-Fuzz)

| 指标 | 数值 |
|------|------|
| Line Coverage | 14.35% (1,117/7,785) |
| Function Coverage | 5.67% (17/300) |
| Static Reachability | 70.1% |
| 现有 Fuzzer | `ucl_add_string_fuzzer` (仅字符串解析) |

### LogicFuzz 结果

| 指标 | 数值 |
|------|------|
| Coverage Diff | **~9.7%** (平均) |
| 最终 Line Coverage | ~20.76% |
| 生成 Sequences | **5** (从 134 APIs) |
| Trial 结果一致性 | 高 (9.46% - 9.74%) |

### Filter Pipeline 效果

```
134 APIs → L0 Type → ??? → L1 Entry → ??? → L2 Lifecycle → ??? → L3 StateMachine → ??? → L4 Ranking → 5 sequences
```

**问题**: 过滤后只剩 5 个 sequences，丢失了大量潜在覆盖。

### API 覆盖分析

**API 分类**:
- 37 parsers
- 10 creators
- 8 accessors
- 14 mutators

**高价值未覆盖 APIs** (来自 FuzzIntrospector 推荐):

| API | 潜在复杂度增益 | 未覆盖原因 |
|-----|---------------|-----------|
| `ucl_emit_yaml_start_array` | +109 | 需要 `ucl_object_t*` 输入 |
| `ucl_hash_sort` | +81 | 需要 hash 对象 |
| `ucl_object_merge` | +55 | 需要两个 `ucl_object_t*` |
| `ucl_emit_msgpack_elt` | +55 | 需要 emitter context |
| `ucl_object_compare` | +44 | 需要两个 `ucl_object_t*` |

**Entry Point 识别问题**:

libucl 的真正入口点是"间接入口点"模式：
```c
// 需要先创建 parser handle
ucl_parser *parser = ucl_parser_new(0);
// 然后才能消费 fuzzer data
ucl_parser_add_chunk(parser, data, size);
```

当前 L1 filter 要求直接消费 `(uint8_t* data, size_t)` 的模式，导致很多 sequences 被过滤。

### 瓶颈识别

| 瓶颈 | 影响程度 | 说明 |
|------|---------|------|
| **L1 Entry Point 过严** | 高 | 不支持间接入口点模式 |
| **Post-parse 操作缺失** | 高 | Sequences 止步于 `get_object`，未延伸到 emit/compare/merge |
| **Sequence 数量受限** | 中 | Top-K 选择后仅 5 个 |
| **API 依赖链复杂** | 中 | emit 需要 emitter_context，merge 需要两个 object |

### 理论 vs 实际

| 指标 | 理论潜力 | 实际结果 | Gap |
|------|----------|----------|-----|
| 可达覆盖率 | 70.1% | 20.76% | **49.3%** |
| Coverage Diff | ~55% | 9.7% | **45.3%** |

### 改进方向

1. **支持间接入口点**: L1 filter 识别 `init() → consume_data()` 模式
2. **自动追加 post-parse 操作**: 在 parse sequence 后追加 emit/compare/merge
3. **多阶段 sequence 生成**: 分别生成 parse 路径和 post-parse 路径，再组合
4. **增加 sequence 多样性**: 不仅优化数量，还要确保覆盖不同功能模块

---

## Case 2: libaom

**测试时间**: 2026-04-04 (进行中)

### 基线数据 (OSS-Fuzz)

| 指标 | 数值 |
|------|------|
| Line Coverage | 61.36% (48,101/78,392) |
| Function Coverage | - |
| Static Reachability | - |

### LogicFuzz 结果

*待填充*

### 分析

*待填充*

---

## Case 3: re2

**测试时间**: 2026-04-04 (进行中)

### 基线数据 (OSS-Fuzz)

| 指标 | 数值 |
|------|------|
| Line Coverage | 30.77% (10,071/32,725) |
| Function Coverage | ~0.78% (36/4,615) |
| Static Reachability | 52.99% |

**特点**: 函数覆盖率极低，潜力大

**高复杂度未覆盖函数**:
- `Compiler::PostVisit()` - complexity 4,997
- `Prefilter::DebugString()` - complexity 4,046

### LogicFuzz 结果

*待填充*

### 分析

*待填充*

---

## Case 4: sqlite3

**测试时间**: 2026-04-04 (进行中)

### 基线数据 (OSS-Fuzz)

| 指标 | 数值 |
|------|------|
| Line Coverage | 79.27% (66,467/83,850) |
| Function Coverage | ~79% (2,759 functions) |
| Static Reachability | - |

**特点**: 覆盖率已高，提升空间有限

**高复杂度未覆盖函数**:
- `jsonExtractFunc` - 838 unreached complexity
- `resolveExprStep` - 501 unreached complexity (cyclomatic: 128)
- `strftimeFunc` - 245 unreached complexity

### LogicFuzz 结果

*待填充*

### 分析

*待填充*

---

## 跨项目模式总结

*待测试完成后填充*

### 共性问题

1. *待识别*

### Filter Pipeline 优化方向

1. *待识别*

### 项目特征分类

| 类型 | 特征 | 代表项目 | 优化策略 |
|------|------|---------|---------|
| 间接入口点 | 需先创建 handle | libucl | 支持 init→consume 模式 |
| 低基线高潜力 | 覆盖率<30%，可达性>50% | re2 | *待分析* |
| 高基线低潜力 | 覆盖率>70% | sqlite3 | *待分析* |
