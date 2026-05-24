# LogicFuzz 系统设计：当前状态 + 待办

> 写于 2026-05-23。这是 `docs/` 下唯一的"当前设计快照 + 待办"文档。
> 历史性的诊断、提案、修复记录都在 commit 历史里，不再单独成 doc。
> 子系统深 dive (automaton / merge_drivers / llm-vs-traditional /
> upstream-liberator-diffs) 单独留在 docs/。

> **⚠️ 生成阶段方向已变 (2026-05-23)。** 经第一性原理诊断，生成阶段的
> Phase A repair + Tier 1 F1–F4 是"先错后补"的并发症，被
> **`docs/generation_stage_redesign.md`** 取代（建 APISemanticModel 上游、
> construct-from-model、按 reachability 选择）。**生成阶段的任何工作以
> redesign doc 为准**；本文 §2–§4 里跟 repair / Phase A / F1–F4 相关的条目
> 视为历史，不要据此开发。本文继续作为 5-phase 全景 + 非生成阶段
> (Phase C/G 反馈、merge) 的状态快照。

---

## §1. 工具目的（不要忘）

给 C/C++ 库自动生成 fuzz drivers，使得 fuzzing：
- **(a) 匹配 baseline** — 复杂库追上手写 OSS-Fuzz drivers 的总覆盖
- **(b) 发现 novel paths/bugs** — 探到 baseline 没探的角落，触发错误路径深处的 bug

这两半是双目标，**任何设计决策都用这两半校准**。

---

## §2. 5-phase 系统设计（roadmap）

```
                          ┌─ 闭环反馈（待做）─────────────┐
                          ↓                                ↑
         L4 random walk (api_sequences)
                          ↓
         Phase D Planner: idiom-align rerank + synthesize_missing
                          ↓
         Phase A Repair Engine: graft creator prefix
                          ↓
         Z3 lifecycle (#4 位置化编码) + RunningContext binding
                          ↓
         skeleton_drivers
                          ↓
         Prototyper (Phase B idioms in prompt)
                          ↓
         N trials × parallel
                          ↓
         merge_drivers
                          ↓
         Phase C: IterationSnapshot → coverage_memory.json
                          ↓
         [Phase E Adaptive Shape — 待做]
                          │
                          └─ frontier 反馈 → Planner（待做）
```

| Phase | Status | 实际能力 | 已知边界 |
|-------|--------|---------|---------|
| A Repair Engine | ⚠️ **superseded** by redesign G2 | graft_creator_prefix；按位置化 lifecycle 验证 | repair 是 IR 误分类的症状；correct model → 无可修。`generation_stage_redesign.md` 删除 |
| B Distillation | ✓ landed (`c10f807b`, `2a1be6a8`) | 10 种 L1 deterministic 模式；持久化 idioms.json；进 prototyper prompt | 无 L2 LLM-tier idioms；无置信度更新机制 |
| C Foundation | ✓ landed (`50856f95`, `2a1be6a8`) | CoverageMemory 数据模型；post-merge IterationSnapshot；is_saturated 函数 | **没 loop driver**；frontier 计算未实现；snapshot write-only 没人读 |
| D Planner | ✓ landed (`effdf034`) | Idiom-alignment 打分 + 重排 + synthesize_missing (限 context_null_pass) | Stateless（不看上轮）；不读 frontier；无 score→coverage 校准 |
| E Adaptive Shape | ✗ | — | driver_size 固定；happy-path only；无 error injection |

---

## §3. 11 个实际信息流问题（按严重）

### 严重：跨 phase 通讯断裂

**P1 — JSON 状态文件全是 write-only**  
`repair_log.json`、`idioms.json`、`coverage_memory.json`、`plan_ledger.json` 都没有 cross-iter consumer。实际跨 phase 通讯 100% 走 in-memory `existing_driver_knowledge` dict（无 schema）。

**P2 — Phase A 用 graft 但看不到 idioms**  
RepairEngine 的 `graft_fn=automaton_artifact.graft_creator_prefix`。Phase B idioms（蒸馏出 canonical creator）**没传给 Phase A**。后果：lcms 上 graft 选 `cmsFreeToneCurveTriple`（IR 假阳标 CREATE），idioms 知道真 creator 是 `cmsCreateContext` 但 Phase A 拿不到。**这是 lcms 0/10 被 graft 救不回的根因。**

**P3 — Phase D 打分 stateless**  
Planner 不读上轮 repair_log 也不读 coverage_memory。每轮从零打分，无校准、无积累。

**P4 — Phase C snapshot 看不到 repair_log 详情**  
`harvest_trial_outcomes` 有匹配 repair trace 的逻辑但 trial_results 不带 sequence key 来匹配 → 死代码。snapshot 的 `skeleton_repair_applied` 永远是 False。

**P5 — Phase A 没"换策略"机制**  
RepairEngine 设计是策略链但只插了 1 个 strategy。graft 失败时无 fallback。

### 中等：冗余 + 结构问题

**P6 — `distill_idioms` 一轮跑两次**  
Step 10（Planner 用）+ Step 12（写 idioms.json）。同输入同输出，纯浪费。

**P7 — `existing_driver_knowledge` 是事实上的 WorkingMemory 但无 schema**  
plain dict，每个 consumer 各自 `.get()`。新增字段没人知道。

**P8 — Phase D `synthesize_missing` 替 Phase E 做了 shape 决策**  
合成 candidate 时把 length 固定 1。Phase E 存在的话应该说"context_null_pass 类入口要配 short driver"。现在 Phase D 替决。

### 边缘：orphan signals

**P9 — `AutomatonAcceptanceGuard.stats` 不报告**  
n_pruned / n_passed / n_relaxes 收集但没人读。

**P10 — Comprehender 的 `patched_sequence` 是 "advisory"**  
Comprehender 给修补意见但 code 明确写"not applied"。Phase A repair 做同一件事但两个系统不互通。

**P11 — `AutomatonArtifact.acceptance_score` positive-only**  
计算但不参与决策。Planner / Repair / 下游都没用它。

---

## §4. 待办 — 按价值密度

### Tier 1：~~必做~~ 已 landed，但被 redesign 取代

> **SUPERSEDED (2026-05-23)。** F1–F4 已实现 (`51024b9d` `b013be02`
> `07c13e70` `dc162fa5`) 并跑过 A/B —— 结果证伪了"缝合信号"路线：
> emit 数升 (c-ares 6→7) 但总覆盖降 (412→81)，lcms 仍 0。F1/F2/F4 是
> "先错后补"的下游补丁，由 `generation_stage_redesign.md` 的 G1/G2 删除
> (F3 是纯效率修，保留)。**不要再按这张表开发。** 下面内容仅作历史。

| # | Fix | 解什么问题 | 估算 |
|---|-----|----------|------|
| **F1** | idioms payload 传给 RepairEngine, graft 选 creator 时验证 idiom-aligned | P2 — lcms 一半 graft 错误选择 | 30 min |
| **F2** | 同 iter 内把 repair_log 失败 strategy 反馈给 Planner | P3 部分 | 1 小时 |
| **F3** | 合并 Step 10 早期 distill + Step 12 distill 为一次 | P6 + Step 顺序整理 | 2 小时 |
| **F4** | 让 Comprehender patched_sequence 走 Repair 通道 | P10 | 1-2 小时 |

执行完这 4 件，**当前架构的天花板就到了**。

### Tier 2：必做（要真闭环 + 找深 bug，绕不开）

**3 个大动作**

| # | Action | 解什么 | 涉及 |
|---|--------|-------|------|
| **F5** | **Phase E Adaptive Shape**（含 error injection 维度）| 单一形态走 happy-path，找不到深 bug | prototyper prompt 模板 + skeleton_generator + planner shape API |
| **F6** | **Phase C CEGAR loop driver**（多 iter + frontier + saturation 触发）| 没闭环 = 没"持续学习" | workflow orchestration + frontier 提取 |
| **F7** | **Phase B L2 LLM idioms**（MULTI_STAGE_PARSE / EDGE_CASE_TRICK）| L1 只抽表面，深 idiom 抓不到 | idiom_distiller 加 LLM agent |

F5 + F6 + F7 全做完才算"工具目的的两半"都触达。

### Tier 3：架构基础（前提）

**WorkingMemory** — 把分散的 JSON 状态文件中心化成 Python 对象，跨 iter 持有 idiom 置信度 / frontier / 策略成功率 / score 校准等历史。**不上 WorkingMemory，F6 CEGAR loop 没地方放迭代状态**。

设计要点（详见决策时再展开）：
- 单 `ProjectWorkingMemory` 类，所有 phase 用 `mem.record_/mem.get_` 接口
- 当前 JSON 文件保留作为派生视图（debug + 跨 run inspection）
- `begin_iteration` / `end_iteration` 生命周期方法
- 跨 phase 查询接口：`get_frontier`、`get_idiom_confidence`、`get_repair_strategy_success_rate`、`is_saturated`、`should_pivot`
- 更新接口：`record_repair_attempt`、`record_plan`、`record_trial_outcome`、`refine_idiom_confidence`

**用户当前决策**：暂不上 WorkingMemory。这意味着 Tier 2 中的 F6 也暂不动。Tier 1 的 4 件 + Tier 2 的 F5 / F7 可以先在当前架构里推。

### Tier 4：明确不做（被其他 phase 吃了）

| 项 | 为啥不做 |
|----|---------|
| §10B v1/v2 搬到 post-merge | 被 F6 CEGAR loop 包含；单独做没意义 |
| Phase A nullable_handle_fill strategy | 被 Phase B+D context_null_pass 吃了 |
| IR-side role splitting (Liberator C++ 改) | Phase D idiom-based synthesis 已绕过 lcms 一类 IR 污染 |
| Phase A topological_reorder strategy | 边际收益小（cjson 1 个 unrepairable）;可选, 不优先 |

---

## §5. 实证数据点（最近 A/B 跑出来的）

| Bench | L4 候选 | Planner reordered | Phase A repaired | Z3 emitted | trials | merge |
|-------|---------|-------------------|------------------|------------|--------|-------|
| cjson  | 10 | True | 2 | **9** | 9 | 9 drivers |
| c-ares | 10 (无 cache) | True | 0 | 6 | 6 | (待 lcms 结束)|
| lcms   | 10 | (待 lcms 结束) | 0 (graft 选错) | (待) | (待) | (待) |

cjson 的 7/10 → 9/10 是 Phase A 主要功劳。c-ares 这次 cache 清掉后产 10 candidates 但 emitted 只 6（4 个 graft 救不回），表现还不如带 cache 跑（5/5）— L4 random walk 噪声。

lcms 数据待 A/B 跑完。

---

## §6. 已决定保留的子系统 docs

| Doc | 范围 |
|-----|------|
| `automaton.md` | PTA + EDSM project automaton + knowledge layer (comprehender) |
| `merge_drivers.md` | `tools/merge_drivers` 多 driver harness 合成 |
| `llm_vs_traditional_choices.md` | 每个 LLM 调用点对应的 symbolic 方案对比 + 选择理由 |
| `upstream_liberator_diffs.md` | Upstream Liberator 在 adapter 修过的 bug 清单 |

历史性内容（cjson run5 诊断、§10B v1/v2 提案、Z3 UNSAT 分析、multi-hop 提案、refactor 浪潮 review log、知识层 T1/T2/T3 设计）全部在 git 历史里。要查具体设计决定 → `git log --grep` 关键词。

---

## §7. 决策队列（用户回应）

按现在的状态，最有用的下一步选项：

1. **F1-F4 4 件小修**（半天）— 把当前架构的信号缝合到天花板
2. **F5 Phase E (Adaptive Shape)** — 多大投入看做到什么程度
3. **WorkingMemory + F6 CEGAR loop**（必须配对做）— 真闭环
4. **F7 Phase B L2 LLM idioms** — 复杂库深 know-how

按优先级：1 → 2 → (3 ↔ 4 并行) — F5 不依赖 WorkingMemory，可以先做。F6 必须 WorkingMemory 先。

进哪个？
