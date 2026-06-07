# 生成阶段信息利用审计 —— 待决策项 + 未来计划（2026-06）

> **实现状态**：第一梯队的确定性项（T1/T2/T3/T5/T6/T8、SVF⊕typestate⊕LLM 紧密结合、CALLSPEC 默认化）
> 与 breadth + low-FP 优化轮（B 优雅降级 / density / hard-guard / top_k / keep-best / pre-ship 隔离 /
> crash-frame classifier / build-cache）**均已落地**。完整管线 + 每条杠杆的 flag/文件/实测数据见
> **`docs/generation.md`**（生成阶段 SoT）。
>
> **本文档只保留**：仍需你拍板的**决策项**、待批准的**新技术**、以及**未来路线图**。已完成任务的实现细节
> 不再重复（见 generation.md / contributions_and_related_work.md / CLAUDE.md）。

**审计范围**：只审计**驱动生成**阶段。**要回答的问题**：喂给 LLM 的是*对的*信息还是*最多*的信息？符号方法（静态分析 + Z3 + 程序合成）与 LLM 的分工，是否各扬其长？

**核心判断（仍成立）**：大方向上分工是对的——Z3 + use-def + typestate 负责程序*结构*（生命周期、句柄接线、调用顺序），LLM 负责*软*决策（取值、语义、填洞）。这一季把"信息在每道边界上漏"的问题大部分堵上了（schema 化喂 LLM、确定性抽取常量/契约/producer）。**剩下的开放项集中在两类**：(1) 跨项目知识与新技术（需你拍板）；(2) binding 层与多项目验证（路线图）。

---

# 一、待决策的开放项

## B1-① 跨项目知识检索（T7，需讨论）
**事实**：我们**没有**策略级全局 planner。`PathPlanner`（Phase D，`src/state/path_planner.py`）是**确定性候选重排器**（按 idiom/覆盖前沿打分、重排、补合成），夹在 L4 与 Z3 之间，**不做"用不用跨项目"这种策略决策**；`supervisor_node` 是逐 trial 控制流路由，也不是策略 planner。

**思路——拆成「检索」+「决策」两层，各扬其长**：
- **检索（传统、轻量、可缓存）**：给 `extracted_fuzz_drivers/`（必要时拉更大 OSS-Fuzz 语料）建一个**「API 形态签名」索引**——不用重型 embedding，用结构特征：不透明句柄目录、creator/parser 入口类型、return-on-error 模式、调用序列 n-gram。对目标项目算同样签名、取 top-k 同类驱动。
- **决策（选不选 / 选哪个），两层把关**：
  1. **要不要跨项目** = 确定性规则触发（省 token、可控）：判据是"目标项目自身资料够不够"（有没有自己的 OSS-Fuzz 驱动 / doxygen / tests）；够就不触发，资料稀薄才触发。放进 `PathPlanner` 或一个轻量"策略"前置步，**不用 LLM**。
  2. **选哪 1–2 个** = 让 **LLM 在已检索的 k 个里做语义精选**——只在 k 个里挑、token 可控。
- **注入**：选中的不给原文，压成 CALLSPEC 风格（呼应 ②′ schema）。
- **选择方法**：不要 top-N，要 *scope + 相关性阈值*——结构签名（主，确定性、精确：{API 集、句柄类型目录、生命周期 n-gram、creator/parser 入口类型}重叠）打分，取所有 score ≥ τ 的、按分排直到 token 预算；无人过 τ 取最佳 1 个（资料稀薄库的兜底）。embedding 仅用于跨命名残差（同领域、不同 API 命名的兄弟库），**先结构、量化它漏了什么、只为跨命名残差补 embedding**。

**待你拍板（三问）**：(a) 要不要**显式策略 planner 节点**（可演进成 LLM 决策），还是先把触发规则塞进 `PathPlanner`？（倾向后者起步）；(b) 语料范围：只用本地 `extracted_fuzz_drivers/`（现只 3 项目、太少）还是拉更大 OSS-Fuzz？(c) 要不要让它**统一调度本次生成的"信息预算"**（跨项目/文档/种子各取多少）。

## B2 · 静态分析残留
绝大部分已落地（T1 set_by / T2 enum / T3 NULL 契约 / T5 producer 接线，见 generation.md）。**仍开放**：
- **没有真正的 CFG 可达性**——L4 的"可达性"是自动机协议接受度，不是"这个 API 把守多少未覆盖块"。**T9 已实测否决**（依赖图太平 max depth 1-3、盲点 depth-无关）→ 根因指向 binding 层（见路线图 #14）。
- **set_by 字段写掩码 / `len_depends_on`** 与现有 LENGTH/OUTPUT intent 重叠，留后续（empirical-before-parametric：等下游真需要再拆）。

## B3 · LLM 上下文 schema 的多项目端到端 A/B（开放）
CALLSPEC 已默认化、砍掉冗余块（见 generation.md §2）。**仍开放**：CALLSPEC 这类重构**会以单测无法捕捉的方式改变 LLM 行为**，要确认它真能提覆盖、不致退化，需要一次更大样本、**多项目**的端到端 A/B（旧/新提示词在 cjson/zlib/lcms 各跑、比覆盖 + token）。已跑的是冒烟级（c-ares best 1440>804；lcms 88>0），线上完整 prepare() 的多项目覆盖对照仍欠。

## B4 · 符号放弃点 → 新技术（待批准）
**一句话**：凡符号层"给不出确定答案、放弃了"的地方，本可把"已知半截信息"传给 LLM 去补。其中 1/3 已做（T2 ✅ / T5 ✅），**2/4/5 需新技术、待你批**：

| # | 符号层在哪放弃 | 丢了什么信息 | LLM 被迫猜什么 | 对应 |
|---|---|---|---|---|
| 2 | 解析器入口字节怎么构造 | 入口**魔数/长度/版本校验**（只硬编 ICC/IT8 两种） | 怎么拼字节过 front-gate 进深层 | **T10** |
| 4 | 只会生成 happy-path 骨架 | （根本没把错误形态告诉 LLM） | —（错误分支从构造上不可达） | **T11** |
| 5 | 跑出来的可用取值丢了 | 某次 trial **真进了深层分支的那个取值**（`coverage_memory.json` 只写不读） | 下一轮又从头猜 | **T12** |

**统一修法** = 在符号放弃的每个点，把"已知半截信息"作为结构化 `value_intent` 塞进 schema，让 LLM 有据补全而非凭空猜。

---

# 二、第二梯队 / 新技术（先报你批准）

| # | 改动 | 为什么需要你拍板 | 状态 |
|---|------|------------------|------|
| T7 | **跨项目驱动检索**：给 `extracted_fuzz_drivers/`（+拉更大 OSS-Fuzz 语料）建索引，按 API 形态签名取 k-NN 同类驱动注入资料稀薄的库。 | 最大的一块输入信号，但要建语料 + 检索组件。 | **需讨论**（见 B1-① 三问）|
| T10 | **泛化格式入口解码器**：用符号常量传播去推解析器入口的校验（替掉硬编的 2 种格式）。 | **新技术：轻量符号执行 / 取值约束分析。** | 待批（B4 #2）|
| T11 | **符号化形态变体骨架**（NULL_INJECT / double-free / 乱序销毁），让错误路径分支可达（LLM 仍只填叶子取值）。 | 中等；改动骨架发射器结构（F5）。 | 待批（B4 #4）|
| T12 | **动态取值反馈闭环**：编译并跑一个微探针（或从某次 trial 挖出存活取值），把可用叶子取值/初始化链钉进下一个骨架的洞（Phase C 的「读」侧）。 | **新技术：轻量动态运行。** | 待批（B4 #5）|

> **已否决（别再 re-litigate）**：**T9**（gap API 的静态 CFG 可达性权重）——`scripts/l4_reachability_probe.py` 实测 c-ares/lcms/zlib 依赖图很平（max depth 1-3），deep gap API 仅 7.1%；planner 盲点是 depth-无关的，重排权重救不了。根因是 **binding 层**（#14）。

> **TLR（fse26）参考价值**：借鉴价值有限，**不在那个"秀的自动机 formalism"上**（领域不同：它建内存错误 typestate，我们已有 API 协议 typestate；阶段不同：它是事后 replay 已知轨迹，我们是前向合成无轨迹）。唯一过硬的一条原则——ablation 证"用 typestate 选择性投喂 > 全量倒"——**正是我们 ②′ schema 已在走的方向**，降格为"related-work 里的一个引用 + 设计 sanity-check"即可。唯一"如果……才"的例外：将来上 T12 时，它"只在 typestate 跳变点快照"的工程小技巧可复用，保持运行时 trace 精简。

---

# 三、开放路线图（收尾记录，后续做）

按杠杆排序：

1. **binding 层 #14（已重新 scope，框架已变）**：**"绑定失败→丢 API"那条已经修好了**——实测 lcms56 skeleton 合成 `z3_rejected=0`、226 序列全 emit（220 经 unchecked 路径），即 **B 优雅降级 + unchecked render 已把所有 opaque/无-producer API 当洞-skeleton 救回**，不再被丢。**真正剩下的是两件、都不是"API 被丢"**：
   - **(a) 贪心选择重叠 —— ✅ 已实现（`LOGICFUZZ_DIVERSITY_SELECT`，默认关）**：根因查清——`_greedy_select` 名为 max-coverage 实为"走 acceptance 排序、接受≥1-new"的过滤，从不按边际挑。改成真 budgeted-max-coverage(每步挑边际新 API 最多、acceptance 破并列、覆盖完即停)。**离线 A/B(lcms,scripts/diversity_probe.py)**:top_k=10 39→75(+92%)、30 63→108、56 120→134、150 194/194(119→116 drv)——同 driver 数低 top_k 广度近翻倍,高 top_k 收敛到池 union(194/297)且 driver 更少。**剩余**:(i) 真覆盖 A/B(docker)确认广度转深覆盖、不伤可达性 → 再默认化;(ii) 池 union 只 194/297,要破 194 需扩 construct 覆盖(wire `build_gap_reaching_seqs` 给那 103 个无序列的 API 发最小 carrier)——但 truly-opaque 的 carrier 仍受 (b) 限制(被调但覆盖~0)。
   - **(b) opaque 参数的【覆盖】—— ✅ 工厂链已实现（`LOGICFUZZ_FACTORY_CHAIN`，默认关）**：根因实测纠正——不是"递归没做",是 `typedef void* cmsHTRANSFORM` 的【返回】类型脱糖成 void* → `extract_produced_handles` 记空 → 29/52 lcms CREATOR 的 produces 为空 → producer 索引无该类型 → 前缀=[]。修法 = naming-based producer recovery：把"被 require 但无 producer 的【非指针】opaque 句柄"按命名惯例(cmsHTRANSFORM→transform→cmsCreate*Transform*,非指针判别 + camelCase 词边界防误配)映射到 CREATOR,喂给【现有】递归 resolve 自动传递链到字节叶子。**离线 A/B(scripts/factory_chain_probe.py lcms)**:deep opaque args satisfied **0→77/128**、recovered types 0→2、avg prefix 0.15→0.89;`cmsDoTransform → [cmsOpenProfileFromMem, cmsCreateProofingTransform, cmsDoTransform, cmsDeleteTransform]`。单调:8 个其它项目 0 变化(无误配/不 regress)。**剩余**:(i) docker 真覆盖确认(FACTORY_CHAIN=1 跑 cmsDoTransform driver,offline 是代理);(ii) 命名惯例不符的库不触发(回退洞,by design);(iii) 工厂的【其它】参数仍是洞由 LLM 填(入口路径已得,非保证全非-NULL)。配合 producer-channel(zlib z_stream,见 memory)。详见 memory `project_binding_layer_unsat`。
2. **多项目 coverage_diff 验证 + vs PromeFuzz/CKGFuzzer 补盲区对比**：把 lcms 的 PoC（876 行 IT8/CGATS 人写 driver 没覆盖、但互补）坐实成 contribution——需 (a) 跨项目可复现 + (b) 证我们补的 existing-driver gap 比 baseline 多。两者皆未测（见 generation.md §5）。
3. **24h union 真跑**对标 PromeFuzz Table 2 绝对覆盖（成本已 OK，deferred）。这是真正的 headline test。
4. **精益模式 —— ✅ 已实现（`LOGICFUZZ_LEAN_MODE`，默认关）**：`supervisor.py` 里 `_lean_crash_triage` 用 `crash_frame.py` 确定性 ASan 帧归因替 2 次 LLM crash 分析(合成 verdict 注入【现有】router;library→END 留真 bug、driver→fixer、unknown→回退 LLM),+ 干净成功直接 END 跳 per-driver optimize → **8.5 → ~3 LLM calls/driver**。off 路径逐字不变,6 路由单测。
5. **build-cache 扩展（机制已查清）**：pub-llm 的 OFG 缓存 = 存在门控 `fuzzer_build_script/<project>` + 缓存镜像 + **重跑原 build.sh（靠幂等,make 变 no-op）**——脚本内容不被应用。lcms 已工作（build.sh 幂等）。**c-ares —— 🔶 代码就绪、卡 fork push**：实测唯一非幂等点 = `cd $SRC/googletest; mkdir build`(File exists);默认路径每次 fresh re-clone `MarkLee131/oss-fuzz`,所以持久修法 = **fork 的 `projects/c-ares/build.sh` 改 `mkdir -p build`**(1 行);gate 文件 `fuzzer_build_script/c-ares` 已备好但**未提交**(fork 没修前提交会激活坏缓存)。本环境 gh 未认证,push 是用户动作。cjson 单文件库廉价、跳过。详见 generation.md §4。

> **未走的方法论修法**（audit §6.4，deferred）：#3 漏斗容错（靠 LangGraph fixer 救回编译失败、像 PromeFuzz 那样 loss-tolerant）、#4 按子系统多生成 driver（lcms postscript/tag/optimizer 聚类）、§6.5 "放松一点 correctness 让 LLM 试硬 API"。目前优雅降级已在不牺牲主线的前提下拿到广度，这几条留作后续；其中"放松 correctness"与"correct-by-construction 无 repair"主线**有张力**，是否走需你定（倾向：符号保证可连核心、孤岛 API 给最大 hint 让 LLM best-effort、失败交 fixer——优雅降级而非硬丢）。
