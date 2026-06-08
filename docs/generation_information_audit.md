# 生成阶段信息利用审计 —— 待决策项 + 未来计划（2026-06）

> **实现状态**：第一梯队的确定性项（T1/T2/T3/T5/T6/T8、SVF⊕typestate⊕LLM 紧密结合、CALLSPEC 默认化）、
> breadth + low-FP 优化轮（B 优雅降级 / density / hard-guard / top_k / keep-best / pre-ship 隔离 /
> crash-frame classifier / build-cache），**以及第二梯队新技术 T10/T11/T12**（格式入口→synth seed /
> 错误形态变体骨架 / 动态取值闭环；均 **gated**、coverage A/B 待测）**均已落地**。完整管线 + 每条杠杆的
> flag/文件/实测数据见 **`docs/generation.md`**（生成阶段 SoT）。
>
> **本文档只保留**：仍需你拍板的**决策项**（T7）、以及**实验类未来计划**（多项目 coverage-diff、24h union、
> 各 gated 特性的 docker 覆盖 A/B）。**全部清空 = audit 可删。** 已完成任务的实现细节不再重复
> （见 generation.md / contributions_and_related_work.md / CLAUDE.md）。

**审计范围**：只审计**驱动生成**阶段。**要回答的问题**：喂给 LLM 的是*对的*信息还是*最多*的信息？符号方法（静态分析 + Z3 + 程序合成）与 LLM 的分工，是否各扬其长？

**核心判断（仍成立）**：大方向上分工是对的——Z3 + use-def + typestate 负责程序*结构*（生命周期、句柄接线、调用顺序），LLM 负责*软*决策（取值、语义、填洞）。这一季把"信息在每道边界上漏"的问题大部分堵上了（schema 化喂 LLM、确定性抽取常量/契约/producer）。**剩下的开放项集中在两类**：(1) 跨项目知识与新技术（需你拍板）；(2) binding 层与多项目验证（路线图）。

---

# 一、待决策的开放项

## B1-① 跨项目知识检索（T7）—— 已实现为可选组件（gated），设计移交 CLAUDE.md
完整设计 + 用户拍板的决策（语料=经 FI API 拉全部 OSS-Fuzz driver、offline 一次性索引；
**优先同项目 driver**；结构签名为主、embedding 作精度不足时的 fallback；scope+阈值选择、
LLM 在 k 个里精选 1–2、兜底 best-1；触发规则起步于 `PathPlanner`、不用 LLM；CALLSPEC 注入）
已搬到 **`CLAUDE.md` Open TODOs 的 T7 条目**。MVP 已实现为 **gated 可选组件
（`LOGICFUZZ_CROSS_PROJECT`）**,A/B 待测后再定是否默认化。实现见
`liberator_adapter/analysis/cross_project_retrieval.py`。

## B2 · 静态分析残留
绝大部分已落地（T1 set_by / T2 enum / T3 NULL 契约 / T5 producer 接线，见 generation.md）。**仍开放**：
- **没有真正的 CFG 可达性**——L4 的"可达性"是自动机协议接受度，不是"这个 API 把守多少未覆盖块"。**T9 已实测否决**（依赖图太平 max depth 1-3、盲点 depth-无关）→ 根因指向 binding 层（见路线图 #14）。
- **set_by 字段写掩码 / `len_depends_on`** 与现有 LENGTH/OUTPUT intent 重叠，留后续（empirical-before-parametric：等下游真需要再拆）。

## B3 · LLM 上下文 schema 的多项目端到端 A/B（开放）
CALLSPEC 已默认化、砍掉冗余块（见 generation.md §2）。**仍开放**：CALLSPEC 这类重构**会以单测无法捕捉的方式改变 LLM 行为**，要确认它真能提覆盖、不致退化，需要一次更大样本、**多项目**的端到端 A/B（旧/新提示词在 cjson/zlib/lcms 各跑、比覆盖 + token）。已跑的是冒烟级（c-ares best 1440>804；lcms 88>0），线上完整 prepare() 的多项目覆盖对照仍欠。

## B4 · 符号放弃点 → 新技术（待批准）
**一句话**：凡符号层"给不出确定答案、放弃了"的地方，本可把"已知半截信息"传给 LLM 去补。**全部已实现**：T2 ✅ / T5 ✅；**#2/#4/#5 = T10/T11/T12 ✅ 已实现（gated，coverage A/B 待测）**——见 generation.md §6：

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
| T7 | **跨项目驱动检索**：按 API 形态签名取同类驱动注入资料稀薄的库（设计 + 用户决策见 CLAUDE.md / B1-①）。 | — | **✅ MVP 已实现（gated `LOGICFUZZ_CROSS_PROJECT`, A/B 待测）** `cross_project_retrieval.py`;语料起步=本地 `extracted_fuzz_drivers/`,scale-up=FI API 全 OSS-Fuzz |
| T10 | **泛化格式入口→synth seed**（`LOGICFUZZ_FORMAT_INFER`）：无真实 seed 时，从推断的 FormatSpec（seed 采样 > 魔数注册表 > header `#define` 魔数）合成最小过-门 seed。*Scope*：确定性常量推断,非全 IR 符号执行(IR 无分支谓词)→ 过前导 magic 门、非深层校验;真实 seed 优先。 | **✅ 已实现（gated, A/B 待测）** `format_inference.py`→`seed_discovery`;15 测试 |
| T11 | **错误形态变体骨架**（`LOGICFUZZ_ERROR_VARIANTS`）：对**命中 gap** 的序列发测-guard 形态(SKIP_INIT/DOUBLE_DESTROY 默认;UAF 仅 `_AGGRESSIVE`),让库错误分支可达;LLM 仍只填叶子;崩溃交 crash-frame classifier。 | **✅ 已实现（gated, A/B 待测）** `sequence_constructor.error_shape_variants`;13 测试(含经 construct_sequences 集成) |
| T12 | **动态取值闭环**（`LOGICFUZZ_VALUE_FEEDBACK`）：捕获 trial 填的洞值,下轮把最深覆盖的值钉进**同 API 序列**的洞——按**序列内容哈希**匹配(非位置名,防误配)。跨 run,Phase C「读」侧。 | **✅ 已实现（gated, A/B 待测）** `coverage_memory.{record,proven,attach}`;13 测试(含 no-mispin 回归) |

> **已否决（别再 re-litigate）**：**T9**（gap API 的静态 CFG 可达性权重）——`scripts/l4_reachability_probe.py` 实测 c-ares/lcms/zlib 依赖图很平（max depth 1-3），deep gap API 仅 7.1%；planner 盲点是 depth-无关的，重排权重救不了。根因是 **binding 层**（#14）。

> **TLR（fse26）参考价值**：借鉴价值有限，**不在那个"秀的自动机 formalism"上**（领域不同：它建内存错误 typestate，我们已有 API 协议 typestate；阶段不同：它是事后 replay 已知轨迹，我们是前向合成无轨迹）。唯一过硬的一条原则——ablation 证"用 typestate 选择性投喂 > 全量倒"——**正是我们 ②′ schema 已在走的方向**，降格为"related-work 里的一个引用 + 设计 sanity-check"即可。唯一"如果……才"的例外：将来上 T12 时，它"只在 typestate 跳变点快照"的工程小技巧可复用，保持运行时 trace 精简。

---

# 三、开放路线图（收尾记录，后续做）

按杠杆排序：

1. **binding 层 #14（已重新 scope，框架已变）**：**"绑定失败→丢 API"那条已经修好了**——实测 lcms56 skeleton 合成 `z3_rejected=0`、226 序列全 emit（220 经 unchecked 路径），即 **B 优雅降级 + unchecked render 已把所有 opaque/无-producer API 当洞-skeleton 救回**，不再被丢。**真正剩下的是两件、都不是"API 被丢"**：
   - **(a) 贪心选择重叠 —— ✅ 已实现并默认开（gate 已移除）**：根因查清——`_greedy_select` 名为 max-coverage 实为"走 acceptance 排序、接受≥1-new"的过滤，从不按边际挑。改成真 budgeted-max-coverage(每步挑边际新 API 最多、acceptance 破并列、覆盖完即停)。**离线 A/B(lcms,scripts/diversity_probe.py)**:top_k=10 39→75(+92%)、30 63→108、56 120→134、150 194/194(119→116 drv)——同 driver 数低 top_k 广度近翻倍,高 top_k 收敛到池 union(194/297)且 driver 更少。**剩余**:(i) 真覆盖 A/B(docker)确认广度转深覆盖、不伤可达性 → 再默认化;(ii) 池 union 只 194/297,要破 194 需扩 construct 覆盖(wire `build_gap_reaching_seqs` 给那 103 个无序列的 API 发最小 carrier)——但 truly-opaque 的 carrier 仍受 (b) 限制(被调但覆盖~0)。
   - **(b) opaque 参数的【覆盖】—— ✅ 工厂链已实现并默认开（gate 已移除）**：根因实测纠正——不是"递归没做",是 `typedef void* cmsHTRANSFORM` 的【返回】类型脱糖成 void* → `extract_produced_handles` 记空 → 29/52 lcms CREATOR 的 produces 为空 → producer 索引无该类型 → 前缀=[]。修法 = naming-based producer recovery：把"被 require 但无 producer 的【非指针】opaque 句柄"按命名惯例(cmsHTRANSFORM→transform→cmsCreate*Transform*,非指针判别 + camelCase 词边界防误配)映射到 CREATOR,喂给【现有】递归 resolve 自动传递链到字节叶子。**离线 A/B(scripts/factory_chain_probe.py lcms)**:deep opaque args satisfied **0→77/128**、recovered types 0→2、avg prefix 0.15→0.89;`cmsDoTransform → [cmsOpenProfileFromMem, cmsCreateProofingTransform, cmsDoTransform, cmsDeleteTransform]`。单调:8 个其它项目 0 变化(无误配/不 regress)。**剩余**:(i) docker 真覆盖确认(FACTORY_CHAIN=1 跑 cmsDoTransform driver,offline 是代理);(ii) 命名惯例不符的库不触发(回退洞,by design);(iii) 工厂的【其它】参数仍是洞由 LLM 填(入口路径已得,非保证全非-NULL)。配合 producer-channel(zlib z_stream,见 memory)。详见 memory `project_binding_layer_unsat`。
2. **多项目 coverage_diff 验证 + vs PromeFuzz/CKGFuzzer 补盲区对比**：把 lcms 的 PoC（876 行 IT8/CGATS 人写 driver 没覆盖、但互补）坐实成 contribution——需 (a) 跨项目可复现 + (b) 证我们补的 existing-driver gap 比 baseline 多。两者皆未测（见 generation.md §5）。
3. **24h union 真跑**对标 PromeFuzz Table 2 绝对覆盖（成本已 OK，deferred）。这是真正的 headline test。
4. **精益模式 —— ✅ 已实现并默认开（gate 已移除）+ per-driver optimize 子系统已删除**：`crash_frame.py` 确定性 ASan 帧归因替 2 次 LLM crash 分析(合成 verdict 注入【现有】router;library→END 留真 bug、driver→fixer、unknown→回退 LLM),干净成功直接 END。orphaned optimize 子系统(coverage_analyzer/improver/§10B)已**整体删除**(见 CLAUDE.md)。**8.5 → ~3 LLM calls/driver**(projected,docker 待确认)。
5. **build-cache 扩展（机制已查清）**：pub-llm 的 OFG 缓存 = 存在门控 `fuzzer_build_script/<project>` + 缓存镜像 + **重跑原 build.sh（靠幂等,make 变 no-op）**——脚本内容不被应用。lcms 已工作（build.sh 幂等）。**c-ares —— ✅ 已完成**：唯一非幂等点 `cd $SRC/googletest; mkdir build` → **fork 改 `mkdir -p build`**(MarkLee131/oss-fuzz master `bf0d3ee`,SSH push)+ gate 文件 `fuzzer_build_script/c-ares` 已提交(`ab904b7b`)。默认路径 fresh re-clone fork → 自动生效。(注:gh CLI 未认证,但 git 走 SSH key 能 push MarkLee131 仓库。)cjson 单文件库廉价、跳过。详见 generation.md §4。

> **未走的方法论修法**（audit §6.4，deferred）：#3 漏斗容错（靠 LangGraph fixer 救回编译失败、像 PromeFuzz 那样 loss-tolerant）、#4 按子系统多生成 driver（lcms postscript/tag/optimizer 聚类）、§6.5 "放松一点 correctness 让 LLM 试硬 API"。目前优雅降级已在不牺牲主线的前提下拿到广度，这几条留作后续；其中"放松 correctness"与"correct-by-construction 无 repair"主线**有张力**，是否走需你定（倾向：符号保证可连核心、孤岛 API 给最大 hint 让 LLM best-effort、失败交 fixer——优雅降级而非硬丢）。
