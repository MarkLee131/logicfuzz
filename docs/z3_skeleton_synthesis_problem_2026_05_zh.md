# Z3 约束求解全 UNSAT 问题剖析（中文版）

> 写于 2026-05-22。配套的英文版在 `z3_skeleton_synthesis_problem_2026_05.md`。
> 内容覆盖同样的范围但用中文重新组织语言，方便和国内专家交流。

---

## §1. 现象与影响

LogicFuzz 的多 trial 评测流水线大致是这样：

```
L4 排好序的 API 序列  ──▶  CBFactory.create_skeleton_for_sequence(seq)
       (每个项目 N 条)                       │
                                            ▼
                          validate_sequence_with_z3(seq)
                                            │
                              ┌─────────────┴──────────────┐
                              │                            │
                            SAT                          UNSAT
                              │                            │
                              ▼                            ▼
                  生成 DriverSkeleton                  return None
                  （含 holes，交给 LLM 改）                ↑
                              │                       全军覆没的源头
                              ▼
                  作为一个 trial 跑下去
                              │
                              ▼
                       多个 trial 并行
                              │
                              ▼
                       --merge-drivers
                       合成多任务 harness
```

实测在两个项目上反复出现 "**N 条候选序列，0 条被 Z3 接受**" 的现象：

- **cjson**：78 个 API，L4 排好 10 条候选 → Z3 全拒，0 skeleton
- **lcms**：297 个 API，L4 排好 10 条候选 → Z3 全拒，0 skeleton
- **c-ares**：138 个 API，5 条候选 → Z3 全接受，5 skeleton

后果是连环倒：

```
Z3 拒 10/10
    ↓
缓存里 0 个 skeleton
    ↓
runner 退化到 num_samples = 1（兜底）
    ↓
单 trial 跑完一条 freeform LLM driver
    ↓
merge 没东西可合
    ↓
"per-trial coverage_diff" 这个指标就成了单点噪声
    ↓
§10B v1/v2 的 baseline-regression 报警在单 trial 上吵
```

也就是说，**所有下游评测指标的可靠性都依赖于 Z3 能把 L4 候选过几条进来**。
Z3 全拒就把整套多 trial × merge 的设计架空了。

---

## §2. 当前的约束编码

代码在 `liberator_adapter/constraints/z3_solver.py`。简化讲：

### 2.1 变量

对每个 API 名字 `f`：

| 变量 | 类型 | 含义 |
|------|------|------|
| `api_f` | `Bool` | 这个 API 在序列里是否被调用 |
| `order_f` | `Int` | 这个 API 出现在第几位 |

对每个类型 `T`：

| 变量 | 类型 | 含义 |
|------|------|------|
| `type_T` | `Int` | 类型 ID（用于 TYPE_MATCH 约束） |

**关键属性**：`order_f` 是**按 API 名索引**的，不是按序列位置。
所以 `[f, g, f]` 这种重复 API 的序列里，只有两个 order 变量（`order_f`、`order_g`），
但有三个槽位。代码里 `add_api_sequence_constraint` 的处理办法是：
**只把 `order_f` 钉到第一次出现的位置**，后续出现的同名 API 直接跳过：

```python
seen = set()
for i, api in enumerate(api_sequence):
    if api in seen:
        continue   # ← 重复 API 在 order 编码里隐身
    seen.add(api)
    order_var = self._get_or_create_order_var(api)
    order_exprs.append(order_var == i)
```

这就是 `CLAUDE.md` "Failed Attempts" 段里写的"权宜之计"（papered over）。

### 2.2 四类硬约束

每次验证一条序列，会向 solver 里 push 四种约束：

**TYPE_MATCH**（`add_type_match_constraint`）：当 API `g` 的某参依赖 API `f` 的返回，
检查类型是否兼容：
- 兼容：写 `type_T_f == type_T_g`（恒真）
- 不兼容：写 `¬(api_f ∧ api_g)`（互斥）

**ACCESS_ORDER**（`add_access_order_constraint`）：当 `creator_c` 和 `deleter_d`
都涉及类型 `T`：
```
delete_called → (create_called ∧ order_create < order_delete)
```
还有 CREATE→USE、USE→DELETE 两个对称版本。

**SEQUENCE_ORDER**（`add_api_sequence_constraint`）：把每个 unique API 名钉到首次出现位置：
```
order_f == 首次出现下标(f)
```

**LENGTH_DEP**（`add_dependency_constraint`）：参数 i 的长度由参数 j 决定。

四类都是通过 `solver.add(expr)` 加进去的**硬约束**。代码里有一个
`get_unsat_core()` 但它没正确用 `assert_and_track`，所以无论 UNSAT 什么时候触发，
返回的 core 永远是空 list — **现成的诊断接口实际上是坏的**。

### 2.3 lifecycle 角色从哪来

`_add_lifecycle_constraints` 读上游 Liberator 的 `FunctionConditions`：

```python
for at in cond.return_at.ats:
    if at.access == Access.CREATE:
        creates.setdefault(at.type_string, []).append(api.function_name)

for arg_cond in cond.argument_at:
    for at in arg_cond.ats:
        if at.access == Access.DELETE:
            deletes.setdefault(type_str, []).append(api.function_name)
        elif at.access in (Access.READ, Access.WRITE):
            uses.setdefault(type_str, []).append(api.function_name)
```

`Access` 这套枚举由 `ConditionManager` 从 LLVM IR 的副作用分析里推断出来。
每个 API 的每个参数位 + 返回位都会被打上 `{NONE, READ, WRITE, CREATE, DELETE, ...}`
其中之一的标签。

---

## §3. UNSAT 的根因（cjson 实证）

我把 cjson 的 `conditions.json` 里所有 API 按角色聚合，得到了下面这张表：

```
creates[%struct.cJSON*] = 30 个 API
  {cJSON_Parse, cJSON_ParseWithLength, cJSON_ParseWithOpts,
   cJSON_CreateObject, cJSON_CreateArray, cJSON_CreateNull, ...
   cJSON_AddBoolToObject, cJSON_AddArrayToObject,
   cJSON_AddObjectToObject, cJSON_AddNumberToObject, ...}

deletes[%struct.cJSON*] = 3 个 API
  {cJSON_Delete, cJSON_DetachItemViaPointer, cJSON_ReplaceItemViaPointer}

uses[%struct.cJSON*] = 54 个 API
  {cJSON_AddBoolToObject, cJSON_AddArrayToObject, ...
   cJSON_Delete, cJSON_GetArrayItem, cJSON_Compare, ...}
```

**注意 `creates` 和 `uses` 的交集不空**。`cJSON_AddBoolToObject` 同时出现在两边：

- 它的返回值类型是 `cJSON*`，返回位的 access 是 `create`（在父对象里挂了个新子节点）
- 它的第 0 个参数也是 `cJSON*`，参数位的 access 是 `write`（修改了传入的父对象）

这两个标签从 IR 分析的角度都是**正确**的 — 这函数确实既新建节点又改动入参。
问题出在下游约束生成器：

```python
for type_str in set(creates) & set(uses):   # cJSON* 落在这里
    for c in creates[type_str]:             # 30 个 API
        for u in uses[type_str]:            # 54 个 API
            if c != u:
                self.builder.add_access_order_constraint(c, u)
                # 等价于断言 order_c < order_u
```

它在**按 API 名集合**做全配对量化。对 cjson 序列 5
`[cJSON_Parse, cJSON_AddBoolToObject, cJSON_AddArrayToObject, cJSON_AddItemToArray]`
按顺序钉好 `{Parse:0, AddBool:1, AddArray:2, AddItem:3}` 之后，生成的 12 条配对约束包括：

- `order_Parse (0) < order_AddBool (1)` ✓
- `order_AddBool (1) < order_Parse (0)` ✗ **UNSAT**

后者出现是因为 AddBool 同时在 creates 和 uses 里，Parse 也同时在 creates 和 uses 里，
全配对的另一个方向就把"AddBool 先于 Parse"也写进去了。任何一对相向的硬约束碰头就足以
让整条序列 UNSAT。

**这种链式构造器风格的 API 一旦超过 2 个就必然出现循环约束**。cjson 的 `cJSON_Add*`
家族正是典型例子；lcms 的 `cmsHTRANSFORM` 流水线可能是另一例。c-ares 之所以能过，
是因为它的 API 风格比较干净：`ares_init` 只创建，`ares_query` 只读，`ares_destroy`
只销毁 — 三种角色互不重叠，全配对的方向就是单调的。

### 一句话总结根因

**编码的意图**是 "*某个值*的创建者要先于*这个值*的使用者"（按 value-instance 量化），
**实际写出来的语义**是 "*所有*被打过 CREATE 标签的 API 要先于*所有*被打过 USE 标签的 API"
（按 API-name 量化）。这两种语义在角色互斥的库上重合，在链式构造器的库上分叉，
后者的表现就是全 UNSAT。

---

## §4. 诊断手段（best practice #1）

虽然代码里有 `UnsatCoreDiagnoser`，但前面提到它的 `get_unsat_core()` 调用顺序是错的
（没用 `assert_and_track`），返回的 core 永远是空。要拿到真正的 minimal core，需要：

1. **重新接入 tracking literal**：把 `solver.add(expr)` 全部改成
   `solver.assert_and_track(expr, Bool(f"c_{tag}_{i}"))`
2. **逐条序列复跑**：对 cjson 的 10 条 + lcms 的 10 条都跑一遍
3. **抓 core**：unsat 时 `solver.unsat_core()` 给出最小不可满足子集
4. **聚合**：按约束家族（TYPE_MATCH / ACCESS_ORDER / SEQUENCE_ORDER / LENGTH_DEP）
   归类，看到底哪一类把所有序列毙了

实际上**§3 的人工聚合已经替代了这步**。`conditions.json` 里 cJSON* 同时出现在
creates 和 uses 的 fact 已经把根因坐死了。Z3 unsat core 只是确认这个事实在 SMT
层面发作的过程，分析上已经不缺了。

---

## §5. 介入方案（按经典文献归口）

下面 5 个方案是 SMT-guided 程序合成领域 30 年的标准工具箱。我把它们和 cjson
具体场景对应起来。

### 5.1 #1 UNSAT Core 提取

**文献锚**：Z3 / CVC4 内置接口；Lynce & Marques-Silva 在 SAT 2004
"On Computing Minimum Unsatisfiable Cores"；用在软件模型检验、规划、形式化验证里。

**做法**：每条硬约束打 tracking literal，UNSAT 时拿 minimal core。

**对我们**：诊断价值 ★★★，但**前面已经诊断完了**，编码层面的修复才是关键。
core 提取作为基础设施值得修（让以后类似问题不用人工聚合），但不解决眼下问题。

### 5.2 #2 MaxSMT / 软约束（Soft Constraints）

**文献锚**：Bjørner & Phan, *νZ - An Optimizing SMT Solver*, TACAS 2014；
Sketch (Solar-Lezama 2008)；SyGuS-IF 标准。

**做法**：把约束分级：
- **硬约束**：违反就编译过不去（TYPE_MATCH）
- **软约束（高权重）**：违反就运行时崩（LENGTH_DEP、CREATE→USE 真正缺失）
- **软约束（中权重）**：违反就资源泄漏（CREATE→DELETE 缺失）
- **软约束（低权重）**：违反 ≈ 我们*希望* fuzzer 找出来（USE→DELETE 倒置 = use-after-free）

用 `z3.Optimize` 求 max-weight-partial-sat，总能给一个"最不坏"的方案。

**对我们**：值得做但**优先级降到了 ★**。因为 #4（见下）之后剩下的拒绝都是真错误，
没有冤枉的需要"软化救回来"的候选。MaxSMT 留给未来 length-dep 类约束真的撞车
的时候再上。

### 5.3 #3 CEGAR（Counter-Example Guided Abstraction Refinement）

**文献锚**：Clarke, Grumberg, Jha, Lu, Veith 在 CAV 2000 的奠基论文；
SLAM、BLAST、IMPACT、SeaHorn 都用这套；CPAchecker 是开源实现。

**做法**：从最弱的约束子集开始合成 → build & run → build/run 失败反馈成新约束 →
回炉求解。LogicFuzz 现有的"先 Z3 综合 → 后 build & fixer" 已经是 CEGAR 的近亲，
只是反馈循环没回到 Z3 那里，而是回到 LLM Fixer。

**对我们**：重设计成本 ≥ 1 周。眼下 #4 的局部修就够用，CEGAR 留作长远规划。

### 5.4 #4 位置化编码（Position-Indexed Encoding）

**文献锚**：SyGuS 比赛主流 solver（CVC4-SY、EUSolver）的标准 unfold 编码；
Bornholt 的 Rosette；同样思路也用在 Reynolds 1970 的 anti-unification 衍生工作里。

**做法**：放弃"按 API 名"的变量编码，改成"按序列位置"。每个位置 `i ∈ [0, n)`
配自己的 `called_i`、`order_i = i`（常量），约束改写成：

```
∀ j ∈ [0, n)， 对于 j 位置上 USE 类型 T 的 API：
    ∃ k < j ：k 位置上的 API 创建了 T
```

这条等价于把"是否有覆盖者"的检查放到位置层做，**完全绕过了 API 名集合上的全配对量化**。
重复 API 名也不再有歧义（每个位置自己一套变量）。

**对我们**：眼下最优解。已落地，详见 §6。

### 5.5 #5 Portfolio Fallback

**文献锚**：SAT 比赛的 ManySAT、Plingeling；Z3 的 `using-params then` tactic。

**做法**：编码 A 拒绝时，自动切到更宽松的编码 B，仍拒就 LLM-only。

**对我们**：实际上**已经存在**（0 skeleton 时 num_samples 回落 1，跑 freeform）。
缺的是诊断信号，那个加点 log 就好。

---

## §6. 实际落地的修复：#4

**Commit `f7001cf7`，2026-05-22**。改动局限在
`liberator_adapter/constraints/z3_solver.py`：

### 6.1 删了什么

- `add_api_sequence_constraint`（按 API 名钉位置的 order 编码）
- `add_access_order_constraint`（CREATE→USE / CREATE→DELETE / USE→DELETE 的全配对生成器）
- `_add_lifecycle_constraints`（调度上面那俩的入口）

这三个方法是同一根藤上的，没有外部调用者，整体下线。CLAUDE.md "Failed Attempts"
段里的"papered over"权宜之计也一并废除。

### 6.2 加了什么

`Z3SequenceValidator._check_lifecycle_position_indexed` — 确定性左到右遍历：

```python
def _check_lifecycle_position_indexed(api_sequence, function_conditions):
    # 1. 每个位置抽取 (creates, uses, deletes) 三元组
    per_position = [_role_sets(api) for api in api_sequence]

    # 2. 算出"本序列里有谁能创建"的类型集合
    creatable = set().union(*[c for c, _, _ in per_position])

    # 3. 左到右遍历，维护一个 ever_created 集合
    ever_created = set()
    violations = []
    for j, api in enumerate(api_sequence):
        creates_j, uses_j, deletes_j = per_position[j]
        # 只对本序列里能被创建的类型查前置
        for T in uses_j & creatable:
            if T not in ever_created:
                violations.append(f"位置 {j} ({api.name}) 用 {T} 但前面没人造")
        for T in deletes_j & creatable:
            if T not in ever_created:
                violations.append(f"位置 {j} ({api.name}) 删 {T} 但前面没人造")
        ever_created |= creates_j
    return violations
```

几个关键点：

1. **量化对象是位置不是 API 名**：根本上绕开 §3 的循环约束
2. **`creatable` 过滤**：序列里没人创建的类型（比如 `i8*` 是 fuzzer 输入，
   `i32` 是返回 bool）不要求有前置创建者 — 这等价于 legacy 代码里
   `set(creates) & set(uses)` 的隐式过滤
3. **没用 Z3**：固定序列的 lifecycle 检查塌缩成 O(n²) 遍历，求解器没必要介入。
   Z3 只留给 LENGTH_DEP 那一类还有"两个参数互推长度"的约束

### 6.3 实测效果

在 cjson 那 10 条 L4 候选上重测：

| 结果 | Legacy | 位置化（#4 后） |
|------|--------|----------------|
| SAT（接受） | 0 | **7** |
| Reject — 真 USE-before-CREATE | 0 | 3 |
| Reject — 循环约束（误报） | 10 | 0 |

剩下 3 条被拒的是 L4 随机游走偶尔吐出来的真错序列：

- **seq 3**：`[cJSON_IsArray, cJSON_ParseWithLength, ...]` — `IsArray`
  在任何创建者之前就解引用 `cJSON*`，会 null deref
- **seq 6**：`[cJSON_DetachItemViaPointer, cJSON_CreateNumber, ...]` — 同样的模式
- **seq 9**：`[cJSON_IsInvalid, cJSON_IsFalse, ...]` — 多个 cJSON* 谓词函数堆在前面

这些 reject 是**正确**的。直接接受会导致下游 driver crash 或 LLM 浪费 token 修一个
本就该被拒的序列。

### 6.4 测试

新增 `tests/test_p1_z3_position_indexed_lifecycle.py`，11 个测试钉住核心边界：

- 链式构造器序列必须 pass（legacy 必 UNSAT 的 cjson Add* 模式）
- USE-before-CREATE / DELETE-before-CREATE 必须 reject
- fuzzer-input 原始类型（`i8*`）单独出现必须 pass
- 重复链式构造器必须 pass（之前因 first-occurrence-pin 必 UNSAT）
- **byte-buffer 豁免**（2026-05-22 残留 fix）：
  - entry-point API 在位置 0 用 `i8*` 必须 pass（lcms `cmsOpenProfileFromMem` 场景）
  - 即使序列里有 API 返回 `i8*`（`cmsMLUgetASCII` 把 i8* 拖进 creatable），
    其他位置用 i8* 仍然免检
  - 真 handle 类型（`%struct.*`）必须仍然受 lifecycle 检查

全套 77/77 通过。

### 6.5 lcms 残留：byte-buffer 类型豁免（commit `<待填>` ）

第一版 #4 在 lcms 上仍然 0/10：lcms 有 c-string 返回的 API（`cmsMLUgetASCII` 等）
返回 `i8*`，把它拖进了 `creatable` 集合，于是 entry-point `cmsOpenProfileFromMem`
在位置 0 用 fuzzer 输入 `i8*` 时被判"前面没人造"。

修法：lifecycle 检查只对**生命周期管理类型**（`%struct.*` / `%class.*` 指针）启用。
原始字节缓冲（`i8*` / `char*` / `void*` / `uint8_t*` 等在 LLVM IR 里都映射成
`i8*`）没有有意义的所有权契约，一律免 lifecycle 检查。

判定函数加在 `_check_lifecycle_position_indexed` 里：

```python
def _is_lifetime_managed(type_str: str) -> bool:
    ts = type_str.strip()
    return ts.startswith("%struct.") or ts.startswith("%class.")
```

只把 lifetime-managed 类型放进 `creatable_types`。其他类型在 `uses_j & creatable_types`
那一步就自然过滤掉。

实测确认（离线 smoke）：lcms 风格的 entry-point + c-string-returning API 组合从 0 通过率
变成正常通过；cjson 7/10 不变；真 struct handle 上的 USE-before-CREATE 仍然正确拒绝。

### 6.6 lcms 完整流水实测：撞到第二个独立失败模式

`#73` 落地后清 lcms 缓存重跑 `--eval`（`logs/lcms_post73/lcms.log`，2026-05-22 19:20）。
结果：**仍然 emitted=0**。

但**原因不是 #73 没起作用**。日志 grep 后发现：

```
z3_rejected=10
但 "Z3 rejected viable-candidate" 只打了 1 条
```

剩下 9 条没在 lifecycle 层拒，是在更后面的 `_compute_arg_bindings_via_running_context`
（RunningContext 的 alias/binding 推导）里**默默返回 None**，外层
`_synthesize_skeletons_per_sequence` 不分青红皂白都计成 `z3_rejected += 1`。

那 1 条**真的** lifecycle 拒绝：
```
cmsReverseToneCurve 在位置 4 用 %struct._cms_curve_struct*，但前 4 个 API
(cmsGBDFree, cmsCreateNULLProfile, cmsSetDeviceClass, cmsCreateInkLimitingDeviceLink)
都不创建 curve_struct
```
这条是 L4 random walk 的真错序列，应该拒（性质和 cjson 那 3 条被拒的 USE-before-CREATE
一模一样）。

剩下 9 条 → **第二个独立失败模式，跟 #4 / #73 无关**：RunningContext 在
`try_to_instantiate_api_call` 阶段对 lcms 的某种 API 形态推导不出参数绑定，silently
返回 None。这是个跟约束求解完全分离的故障路径，要单独立 task 去查（已记为 task #75）。

**修正后的结论矩阵**：

| 项目 | #4 前 | #4 后 | #73 后 | 备注 |
|------|-------|-------|--------|------|
| cjson | 0/10 | 7/10 ✅ | 7/10 | #4 直接解决，#73 不影响（没踩 i8* 拖入） |
| c-ares | 5/5 | 5/5 | 5/5 | 一直没问题 |
| lcms | 0/10 | 0/10 | **0/10 + 1 真错** | #73 让 1 条暴露真问题，9 条仍卡在 RunningContext binding（task #75） |

#73 的修复**在离线 smoke 里被验证有效**（i8* 类型在 entry-point 位置 0 不再卡），
但 lcms 的完整流水还有第二个瓶颈。不是 #4/#73 的失败，是另一个相邻但独立的故障路径。

---

## §7. 还能留给专家讨论的开放问题

#4 解决了眼下 cjson/lcms 的全 UNSAT 问题，但下面这些设计抉择我自己没把握，
想找做过 SMT-guided synthesis 的专家聊聊：

1. **软约束权重该怎么定**？  
   SyGuS 比赛和 MaxSMT 比赛有没有沉淀下来的"通用权重族"？还是说必须**领域内
   实证调参**？我们如果将来真要上 MaxSMT，是用 lexicographic（按优先级排）还是
   weighted-sum（按权重总分），哪种在我们这种"候选少、序列短"的场景更稳？

2. **CEGAR vs MaxSMT 的适用边界**？  
   我的直觉：CEGAR 适合"约束本来是对的，规模太大解不动"（模型检验场景）；
   MaxSMT 适合"约束是人手写的，可能过度保守"（合成场景）。我们的场景更像后者，
   所以 #2 MaxSMT 比 #3 CEGAR 更对症。这个判断对吗？

3. **UNSAT core 怎么 minimize**？  
   Z3 默认给的 core 不一定是 minimal。文献上常用的 minimization 路径是
   one-at-a-time deletion（删一条约束再求解，能 SAT 就说明这条是 core 的一部分）。
   有标准工具/tactic 自动跑这步吗？还是自己手写？

4. **位置化编码的可扩展性**？  
   现在序列长度 ≤ 12，编码大小线性增长。如果未来 sequence 长度长到 30 ~ 50，
   Z3 求解时间会不会爆？经验上分水岭在哪？

5. **要不要直接换成 SyGuS-IF**？  
   我们其实在做的事 — 约束基的组件合成 + 类型/lifecycle predicate — 是 SyGuS 比赛的
   核心问题。直接换成 SyGuS 形式（用 CVC4-SY 或 EUSolver 作 backend）是不是
   比手维护一套 z3_solver.py 长期更划算？还是说 SyGuS 的表达力对我们其实超了？

---

## §8. 时间线

| 时间 | 事件 |
|------|------|
| 之前 | CBFactory 的 "one position per API" Z3 模型被发现有 named-collision 问题；
| | 加了 boundary-dedup 权宜之计（CLAUDE.md "Failed Attempts" 段记录） |
| 2026-05-12 | 跑 cjson run4，发现 Z3 全拒 10/10，automaton 在背锅 |
| 2026-05-12 | Phase H AutomatonAcceptanceGuard 改成 positive-only signal，洗清自动机嫌疑 |
| 2026-05-21 | 修 `run_single_fuzz.py:494` 的 dead key bug（`synthesized_drivers`
| | → `skeleton_drivers`）；num_samples 终于不再强行回落 1 |
| 2026-05-22 | 重提取 cjson conditions，按角色聚合证实 creates ∩ uses 不空，
| | 定位根因到约束生成器按 API 名集合做全配对量化 |
| 2026-05-22 | #4 位置化编码落地（commit `f7001cf7`）；cjson 0/10 → 7/10 |
| 进行中 | 清空 cjson + lcms 缓存的全流水 A/B 验证（`logs/ab_2026_05_22_v2/`） |

---

## §9. 参考文献

- Bjørner, N. & Phan, A.-D. (2014). νZ - An Optimizing SMT Solver. *TACAS*.
- Solar-Lezama, A. (2008). *Program Synthesis by Sketching* (PhD 论文, UC Berkeley).
- Lynce, I. & Marques-Silva, J. (2004). On Computing Minimum Unsatisfiable Cores. *SAT*.
- Clarke, E. M., Grumberg, O., Jha, S., Lu, Y. & Veith, H. (2000). Counterexample-Guided Abstraction Refinement. *CAV*.
- SyGuS-IF 标准：https://sygus.org/
