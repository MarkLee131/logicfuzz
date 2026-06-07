# 生成阶段信息利用审计（2026-06）

**范围**：只审计**驱动生成（driver-generation）**阶段；修复、优化驱动、根因分析暂时搁置。
**要回答的问题**：当前工具有没有把输入、以及自身分析里有价值的信息榨干？喂给 LLM 的是**对的**信息，还是**最多**的信息？符号方法（静态分析 + Z3 + 程序合成）和 LLM 之间的分工，有没有像人类专家那样各司其职、各扬其长？

**方法**：四个维度的对抗式审计（输入来源、静态分析、LLM 输入、符号↔LLM 协同），每条结论都落到 `file:line`。

---

## 核心判断

**大方向上分工是对的**——Z3 + use-def + typestate 负责程序*结构*（生命周期、句柄接线、调用顺序），LLM 负责*软*决策（取值、语义、填洞）。问题出在**信息在每一道边界上都在漏**：丰富的信号被算出来之后，还没传到真正需要它的那个决策点，就被丢掉了；与此同时，LLM 又被灌进大量低信号、重复的文本。**工具把自己算出来的东西一股脑全倒给 LLM，却把本该提炼出来的关键信息扔了。**

人类专家恰好相反：只看*几条*精确的事实（头文件里的枚举、解析器入口的魔数/长度校验、`@return` 的 NULL 契约、同类项目现成驱动的调用链），就能写出一个紧凑到位的驱动。这份审计，量的就是两者之间的差距。

---

## 收敛结论：信息在 5 道边界上流失

### B1. 输入来源 → 知识层（维度一）——榨取严重不足
- **完全没有跨项目迁移。** 给项目 X 生成时，只读 X 自己的驱动（`_resolve_drivers_root(project_name)` 严格按项目名取键，`data_context.py:2157`）；grep 检索/迁移/相似一类逻辑，一处都没有。仓库里其实已经攒了一份语料（`extracted_fuzz_drivers/`，而且 GCS 拉取脚本是按「所有项目」拉的）。一个全新的、自身资料稀薄的库，就什么都拿不到——哪怕有一个结构上很接近的库（另一个 JSON/图像/编解码解析器）已经有一份久经考验的驱动，清清楚楚演示了 creator→parse→consume→free 这套惯用法。**这是最大的一块免费、高信号来源，利用率为零。**
这里需要优化。但是要注意，具体怎么使用跨项目知识还需要思考更合理的方法（兼顾系统和轻量）。 可以考虑传统方法，也可以考虑是否用当前的agent 自己去判断？ 我们是否有一个全局planner？ 如果有，可以让他来决定？  选不选跨项目，如何选？ 怎么选？ 

- **现成驱动的调用序列 + 实参来源被丢掉了。** 只有 3 份原文 + 10 条正则惯用法（`idiom_distiller.py`）留了下来；最权威的 API n-gram 序列、以及「哪个返回值喂给哪个实参」的来源图，从没被重建过。自动机（automaton）从 tests/examples 里学序列，却*偏偏不从驱动源码里学*——而驱动恰恰是「合法 fuzz 入口序列」最权威的范例。

这个可以直接优化。

- **文档先验默认关闭**（`--use-doxygen-priors` / `--use-readme-purpose`）。默认跑法下，库的用途是从项目名硬编出来的，从不读 `@param` 的所有权语义、也不读 `@return`/`@retval` 的 NULL 契约——而这恰恰是「生成的驱动漏掉对 creator 返回值的 NULL 检查」那条记忆所需要的信号。
- README 里的 **Quick-Start 代码块**（一个免费的可运行示例）被显式剥掉了；**种子语料**（真实输入格式 / 魔数）只在 fuzz 阶段用，对生成阶段不可见；**build.sh/.dict/.options**（必需的 `-D` 宏、格式字典、`max_len`）也没被挖。 

这功能直接开启，不允许关闭。 需要注意的是： 是否费token。 quick-start 不确定有没有用，因为我们当前直接用的oss-fuzz docker。


### B2. 静态分析 → 模型（维度二）——丰富的 SVF 数据在边界处被销毁
- **整个 per-param `access_type_set` 被压成了一个布尔值。** `usedef.py:363` 把每参数约 969 处字段级 struct 访问 + create/delete 来源 + 逐字段写掩码（lcms 数据）统统压成 `_svf_writes` 一个 bool，其余全扔。
- **`set_by`（参数→参数 的初始化依赖图，lcms 上约 75 条边）** 没被提升进 `APISemanticModel` / 序列构造器——模型的 requires/produces 纯按句柄类型建键，根本表达不了「arg0 这个 struct 是由 param_2/param_3 填充的」。
- **没有抽取错误返回 / NULL 后置条件**（IR 里的 `if (p==NULL) return; if (rc<0) goto err`）——这些从 extractor 已经加载的 bitcode 里完全恢复得出来。这*就是*那个 NULL 检查 bug 的根。
- **没有真正的 CFG 可达性。** L4 所谓「可达性优先」其实是自动机*接受度*（协议顺序匹配），不是对未覆盖基本块的静态可达性；gap 信号只是函数级的有/无。
- **没有 CONFIG 标量参数的枚举/取值域**（switch 表、enum 定义、相等性守卫，本可界定哪些取值能进到有意思的代码）。

这里的思路需要讨论解决方案。



### B3. 模型 → LLM（维度三）——喂得太多、重复、过时
- **两套冗余的 role 分类**同时塞进提示词（被降级的命名启发式 `classify_project_apis`，以及已经协调过的 `APISemanticModel` roles）。
- **3 份完整的现成驱动源码**被原样倒进提示词（单项最大的 token 消耗），还跟已经提炼好的 `<library_idioms>` / `<code_patterns>` 大量重叠。
- **系统提示词还在宣传一个已删除的工具**：`fuzz_introspector_query` 加 4 处「去查源码」/「去查用法示例」的指令，可 `get_tools()==[]` → 诱发幻觉工具调用、白白消耗注意力。
- 多个重叠的 API 视图（`<api_sequences>` / `<sequence_api_signatures>` / `<project_apis>` / `<dependency_graph>`）、重复的 skeleton 渲染、「多调几个 API」这条规则重复说了 3–4 遍，而且没有全局 token 预算。

这个是要重点压缩的。我们要严格把控给LLM 什么信息，从哪里搞来哪些信息。哪怕定义一个LLM 专属的DSL 表或者类似的元组。 我们要讨论。


### B4. 符号方法在它放弃的地方，把锅甩给 LLM 去猜（维度四）
- **CONFIG/枚举参数**只拿到 `VARY_RANGE：覆盖合法与非法取值`（`hole_semantics.py:96`）；LLM 只能*猜*合法值（lcms `TYPE_RGB_8`、intent 0–3；zlib level 0–9）。其实按参数 typedef 去扫一下头文件的 enum/#define，就能确定性地给出这些值。
- **格式入口（front-gate）只硬编了 2 种格式**（ICC `acsp@36`、IT8）；其余一律给一句含糊的 header/body 提示 → 解析器只能浅尝辄止（即「已覆盖函数内部仍有未覆盖分支」那条教训）。
- **绑定失败的原因沦为只写不读的遥测。** `try_to_get_var` 抛 `ConditionUnsat`（incomplete_opaque / struct_needs_init / has_source）时，原因——现在由新加的 `_record_binding_rejection` 记下来了——却从没流到 `create_skeleton_unchecked` 路径上的洞标注里，于是 LLM 永远不知道「这个参数需要一条初始化链 / 是不透明类型」。
- **只走 happy-path 的骨架**（create→use(合法)→destroy）——错误处理 / UAF / 把 NULL 当句柄 / 乱序销毁这些分支，从构造上就*不可能*被覆盖到。
- **没有动态取值反馈。** Phase C 的 `coverage_memory.json` 只写不读；某次 trial 好不容易让一个取值进到了深层分支，这个事实却丢了。

这里暴露的问题我没看懂。我们需要弄清楚问题，然后交互讨论。



### B5. 人类专家对照（统一版）
一个专家给 lcms `cmsDoTransform` / zlib deflate 链写高覆盖驱动时会做五件事：(1) 读头文件**枚举**拿合法常量；(2) 读解析器**源码/IR**拿入口字节谓词（魔数 / 长度前缀 / 版本）；(3) 读 **@return** 拿 NULL 契约；(4) **照抄**本项目或同类项目现成驱动的调用序列 + 输入分发；(5) 从**调用图**判断哪个 API 把守着最多未覆盖代码。工具在（生命周期 + 句柄接线）上很强，但 (1)–(5) 基本都跳过了。

---

## 优先级方案

我们需要根据上述讨论之后，更新下面的方案。

### 第一梯队——确定性、低风险、高杠杆（不需要新技术；先做）
每一条都用工具已有的、或能廉价拿到的数据，去堵一道边界泄漏：

| # | 改动 | 边界 | 杠杆/工作量 | 状态（按讨论刷新 2026-06-06） |
|---|------|------|------------|------|
| T1 | **别再把 SVF 压成一个 bit。** 把 per-arg 字段写掩码 + `set_by` 初始化依赖边 + `len_depends_on`/`is_array` 从 conditions.json 提升进 `APISemanticModel` 和 G4 洞的取值意图。 | B2 | 高/中 | ✅ **已落地（set_by 部分）**：`_build_svf_index` 从 conditions.json 抽 set_by，洞标注写 `POPULATED_FROM argX,argY`。验证 lcms 75 条（`cmsAppendNamedColor.arg0`→arg2,3）。+4 测试。（len_depends_on/字段掩码与现有 LENGTH/OUTPUT 重叠，留后续） |
| T2 | **为 CONFIG 参数做符号化 enum/#define 抽取。** 扫头文件拿到参数 typedef 的合法枚举/常量集，用真实取值集替换泛泛的 `VARY_RANGE`。 | B4 | 高/中 | ✅ **已完成 + 已闭环**（`named_constants.py`；lcms 11 枚举、zlib `Z_*`）。**fan-out 补**：`<library_constants>` 词表此前算了却没渲染进提示词，现已注入（annotate_skeletons 挂块 + prototyper 渲染）|
| T3 | **逐 API 抽取错误返回 / NULL 后置条件**，作为强制的洞/守卫约束（修掉 creator NULL 检查 bug）。 | B2 | 高/中 | ✅ **已落地**（`error_contracts.py`，fan-out 子代理产出）：从 conditions.json return 指针 + doxygen @return 抽 NULL/error 契约，洞标注出 `⚠ returns NULL → NULL-check`。lcms 85 creators / c-ares 12 / cjson 18。+9 测试 |
| T4 | **LLM 瘦身 → 一张 typed CALLSPEC 表。** 砍掉 3 份原文驱动 + 一套 role 分类 + 过时指令；把重叠的 API/skeleton 视图收成「每调用一块」typed 元组；加全局 token 预算。 | B3 | 高/中 | 🚧 **进行中**：✅ 删过时工具指令；✅ **step1 CALLSPEC 渲染器**（`render_callspec`，按 §5.3 字段 + kind 轻拆，additive，+4 测试）。**待做**：step2 接入实时 prompt + 砍冗余块（门控 `LOGICFUZZ_CALLSPEC`，**需 docker 端到端 A/B**）；step3 scope-restrict；step4 §5.5 相关性选范例 |
| T5 | **把绑定失败原因 + 分析器找到的 producer**，标到 unchecked-skeleton 路径的洞上。 | B4 | 高/小 | ✅ **已落地**：从模型已有的 produces/requires 建 producer 索引，洞标注按序列写"needs handle T: produced by X,Y / 或 无 producer→构造或 NULL"；producer 在前则静默。离线验证 c-ares（`ares_cancel`→`ares_init`）；纯增量、不丢序列；+6 测试，181 pass |
| T6 | **文档先验默认开 + @return 结构化契约 + README 代码块。** | B1 | 高/小 | 🚧 **部分**：① 默认开+删 opt-out = ✅ **已完成**（B1-③，token 已查清为负）；② `@return`/`@retval` → 结构化 NULL/所有权契约 = ✅ **已落地**（并入 T3 的 `error_contracts.py`）；③ README quick-start = ❌ **不做**（oss-fuzz docker 下"可运行范例"=项目自身驱动，交给 T8） |
| T8 | **从本项目自己的驱动里挖调用序列 + 实参来源**喂进自动机/构造器（复用 `static_trace.extract_project_traces`，也跑在驱动 `.c` 上，而不只 tests）。 | B1 | 中 | ✅ **已落地**：Step 5e2 把驱动语料目录追加进 automaton 的 consumer_paths。离线验证 c-ares 3 驱动→3 trace（含真实 `LLVMFuzzerTestOneInput: malloc→ares_create_query→free→free`）。构造式 EDSM 低风险；门控 + `LOGICFUZZ_DISABLE_DRIVER_TRACES=1` 杀手锏；175 tests。probe: `scripts/t8_driver_traces_probe.py` |

### 第二梯队——更大，或需要新技术（先报你批准）

| # | 改动 | 为什么需要你拍板 | 讨论结论 |
|---|------|------------------|------|
| T7 | **跨项目驱动检索**：给 `extracted_fuzz_drivers/`（外加拉取更大的 OSS-Fuzz 语料）建索引，按 API 形态签名取 k-NN 同类驱动注入到资料稀薄的库。 | 最大的一块输入信号，但要建语料 + 检索组件。 | **需讨论**（B1-①）。拆「检索（传统轻量）+ 决策（规则触发是否跨项目 → LLM 在 k 个里精选）」两层。**三个待拍板**：(a) 显式策略 planner 还是先塞进 PathPlanner；(b) 语料范围（本地 3 项目 vs 拉 OSS-Fuzz）；(c) 是否让它统一调度"信息预算"。 |
| T9 | **给 gap API 加静态 CFG 可达性权重**进 L4。 | 需要对 bitcode 做一遍调用图分析。 | ❌ **不做（实测否决）**：`scripts/l4_reachability_probe.py` 测 c-ares/lcms/zlib——依赖图很平（max depth 1-3），deep gap API 仅 7.1%(32/452) 且集中在 c-ares 一族；planner 盲点是 depth-无关的（302/452 缺失、多为 shallow，重排权重救不了）。根因仍是 **binding 层**（#1）→ 这才是下一步真正的杠杆 |
| T10 | **泛化格式入口解码器**：用符号常量传播去推解析器入口的校验（替掉硬编的 2 种格式）。 | **新技术：轻量符号执行 / 取值约束分析。** | 对应 B4 表 #2。待你批新技术。 |
| T11 | **符号化的形态变体骨架**（NULL_INJECT / double-free / 乱序销毁），让错误路径分支变得可达（LLM 仍只填叶子取值）。 | 中等；改动骨架发射器结构（generation.md F5）。 | 对应 B4 表 #4。 |
| T12 | **动态取值反馈闭环**：编译并跑一个微探针（或从某次 trial 里挖出存活的取值），把可用的叶子取值/初始化链钉进下一个骨架的洞（Phase C 的「读」侧）。 | **新技术：轻量动态运行。** | 对应 B4 表 #5。待你批新技术。 |

### 起步顺序（按讨论刷新）
- **第一梯队确定性项已全部落地**：T1 ✅ T2 ✅(+闭环) T3/T6② ✅ T4① ✅ T5 ✅ T6① ✅ T8 ✅；外加 fan-out 的 **role-precision 修复**（SVF read-only 否决错误 OUTPUT）。共 198 测试全绿。
- **实测否决**：**T9**（依赖图太平 + 盲点 depth-无关）→ 指向 binding 层。
- **要你先拍板再动**：**T4 的 CALLSPEC 字段集**（B3 重点，最高杠杆）、**T7 的跨项目三问**（B1-①）、**T10/T12 新技术**（B4 #2/#5）。
- **新的最高杠杆候选**：**binding 层**（task #14 / CLAUDE.md #1）——T9 的实测把"缺失的 gap API 多为 shallow、根因是 try_to_get_var 合成不出 opaque/void* 参数"坐实了。

> 说明：T4 的 CALLSPEC 重构会**以单测无法捕捉的方式改变 LLM 行为**，要确认它真能提覆盖、且不致退化，需要一次端到端 A/B（用旧/新提示词在 cjson/zlib/lcms 上各跑一遍、比覆盖率）。



我们客观分析一下 @ /docs/fse26_tlr.pdf 里的自动机建模对于我们当前的工具设计有无参考意义。如果有，哪部分是中规中矩可以迁移的。如果没有，那我们继续推进我们自己的路线。

---

# 二、回应批注 · 优化与实现思路（供逐条深入）

> 每条按「确认 / 需讨论」分开。需讨论的给出**优化方向 + 实现路径 + 留给你拍板的开放问题**。

## B1 · 输入来源

### B1-① 跨项目知识（需讨论）
**先回答你的事实问**：我们**没有**策略级全局 planner。`PathPlanner`（Phase D，`src/state/path_planner.py`）是**确定性候选重排器**（按 idiom/覆盖前沿打分、重排、补合成），夹在 L4 与 Z3 之间，**不做"用不用跨项目"这种策略决策**；`supervisor_node` 是逐 trial 的控制流路由，也不是策略 planner。

**思路——把它拆成「检索」+「决策」两层，各扬其长**：
- **检索（传统、轻量、可缓存）**：给 `extracted_fuzz_drivers/`（必要时拉更大 OSS-Fuzz 语料）建一个**「API 形态签名」索引**——不用重型 embedding，用结构特征：不透明句柄目录、creator/parser 入口类型、return-on-error 模式、调用序列 n-gram。对目标项目算同样签名、取 top-k 同类驱动。
- **决策（选不选 / 选哪个），两层把关**：
  1. **要不要跨项目** = 确定性规则触发（省 token、可控）：判据是"目标项目自身资料够不够"（有没有自己的 OSS-Fuzz 驱动 / doxygen / tests）；够就不触发，资料稀薄才触发。放进 `PathPlanner` 或一个轻量"策略"前置步，**不用 LLM**。
  2. **选哪 1–2 个** = 让 **LLM 在已检索的 k 个里做语义精选**（"这套调用惯用法能不能迁过来"）——LLM 擅长的软判断，且只在 k 个里挑、token 可控。
- **注入**：选中的不给原文，压成 CALLSPEC 风格（呼应 B3）。

**待你拍板**：(a) 要不要**显式的策略 planner 节点**（可演进成 LLM 决策），还是先把触发规则塞进 `PathPlanner`？（我倾向后者起步）；(b) 语料范围：只用本地 `extracted_fuzz_drivers/`（现只有 3 个项目、太少）还是拉更大的 OSS-Fuzz？(c) 要不要让这个 planner **统一调度本次生成的"信息预算"**（跨项目/文档/种子各取多少）——这其实把 B1/B3 收敛到一个"信息调度"决策上。

### B1-② 本项目驱动的调用序列+实参来源（你已确认：可直接做）
**确认 = T8。** 复用现成 `static_trace.extract_project_traces`（已是 libclang use-def 走查），把它也跑在驱动 `.c` 上（不只 tests），重建 API n-gram 序列 + "哪个返回喂哪个实参"的来源图，喂进自动机/构造器。驱动是"合法 fuzz 入口序列"最权威的范例，确定性、复用已有走查，我可直接做。

### B1-③ 文档先验 / README / 种子 / build.sh（你已确认：默认开、不可关）
- **① 默认开 + 删 opt-out = ✅ 已落地**（commit B1-③）：`prepare()` 两个先验参数默认 `True`，删掉 `--use-doxygen-priors`/`--use-readme-purpose` 两个 CLI 开关，CLI 层不可关（参数保留仅供测试程序化 A/B）。
- **token（你顾虑的点，已查清=不费反省）**：doxygen 先验**省 token**——某 API 有实质 docstring（≥40 字符）时，comprehender 直接用它组 usage 行、**跳过该 API 的 LLM 调用**（`comprehender.py:_doc_derived_usage`）；readme 只一次性加一段 3–15 行 purpose，可忽略。
- **② `@return`/`@retval` → 结构化 NULL/所有权契约 = 待做**（这是真正修"creator 返回值漏 NULL 检查"的料），并入 T3 一起做。
- **③ quick-start = ❌ 不做（你说得对）**：当前直接用 oss-fuzz docker，"可运行范例"其实就是项目自己的 OSS-Fuzz 驱动（B1-② 在挖），README 代码块价值存疑且易重复 → 把"范例"交给 B1-②（本项目驱动）+ B1-①（同类驱动）。**种子语料**先不进生成阶段，留到 T10/T12 一起考虑。

## B2 · 静态分析（需讨论）
"算出来没用上 / 本可算没算"，逐子项：
- **T1 · 别把 SVF access_set 压成一个 bit**（确定性、数据已有，建议先做）：`conditions.json` 里**已经**有 per-arg 字段写掩码 + `set_by`（参数→参数 初始化依赖）边，`usedef.py:363` 只取了 1 个 bool。把它们原样带进 `APISemanticModel` 的 per-arg 记录、再渲染进 CALLSPEC 的 `value_intent`（"arg0 这个 struct 的字段 X/Y 由 param_2 填充"）→ LLM 知道该先备哪个入参、哪个字段必须初始化。**纯接线，不需要新分析。**
- **T3 · 抽 NULL/错误返回后置条件**（中等）：从已加载 bitcode 抽 creator"可能返回 NULL/负值"后置条件，作为**强制守卫**注入洞约束（`if(!h) return 0;`），直接修 SEGV-poison merged-harness 那条 bug。需要一遍 IR 后置条件分析。
- **T9 · gap API 的 CFG 可达性权重**（需调用图，建议先量化再定）：现在 L4 的"可达性"是自动机协议接受度，不是"这个 API 把守多少未覆盖块"。建议先**量化**当前 L4 错配了多少高价值 gap API，再决定值不值得做调用图分析。
- **T2 · enum 取值域**：已做。

**待你拍板**：T1/T3 用现成数据、确定性，建议直接进第一梯队；T9 取决于上面的量化。

## B3 · 给 LLM 喂什么、从哪来（需讨论，重点）—— CALLSPEC DSL
你的方向（严格把控 + 定义 LLM 专属 DSL/元组）正确，且 TLR 给了 ablation 背书（见第三节）。设计：

**一张 `CALLSPEC` = LLM 在生成阶段唯一需要的"事实"。每个调用一个块：**
```
step │ api │ role │ ret(type, nullable?) │
     args[(i, type, argrole, value_intent, pairs_with)] │
     needs[live handle vars] │ produces[handle] │ precond │ cleanup
```
外加 3 个 token-bounded 的项目级小块：`<library_constants>`（T2 常量词表）、`<idioms>`（已有 Phase B）、**1 个**压缩过的 worked example（来自 B1-②/B1-①，**非原文**）。

**每个字段标"来源"，"喂什么/从哪来"完全可审计**：role/argrole←`APISemanticModel`；value_intent←`hole_semantics`（含 T2 常量、T1 字段依赖、T5 绑定原因）；needs/produces←use-def；precond/cleanup←lifecycle/typestate；ret.nullable←T3。

**砍掉**：两套 role 分类只留 reconciled；3 份原文驱动→CALLSPEC+1 压缩示例；过时工具指令（已删）；重叠 API 视图合进 CALLSPEC；重复规则说一遍；skeleton 在场只渲一次 + 全局 token 预算仲裁。

**待你拍板**：(a) 字段集 + 渲染形态（一张表 vs 每调用一块——我倾向每调用一块，因为带 args 子列表）；(b) 留不留任何压缩原文示例（TLR 结论"结构化 trace > 原文"，我倾向只留压缩示例）；(c) **A/B 验证**（旧 vs 新提示词在 cjson/zlib/lcms 比覆盖 + token）——这步必须有。

## B4 · 先把问题讲清楚（你说没看懂）
一句话：**凡是符号层"给不出确定答案、放弃了"的地方，本可把"已知的半截信息"传给 LLM 去补；但现在要么传一句泛泛提示、要么啥都不传，于是 LLM 在信息真空里硬猜。** 5 个例子：

| # | 符号层在哪放弃 | 丢了什么信息 | LLM 被迫猜什么 | 对应 |
|---|---|---|---|---|
| 1 | CONFIG/枚举参数填值 | 头文件里**确切的合法常量集** | 一个 int 填啥（猜 `TYPE_RGB_8`？还是乱填 0） | T2 ✅ |
| 2 | 解析器入口字节怎么构造 | 入口的**魔数/长度/版本校验**（只硬编了 ICC/IT8 两种） | 怎么拼字节过 front-gate 进深层 | T10 |
| 3 | 某参数绑定失败 | **失败原因**（不透明 / 需初始化链 / 有 producer 没接上）——只写进遥测没人读 | 这参数到底传啥、要不要先调别的 API | T5 |
| 4 | 只会生成 happy-path 骨架 | （根本没把错误形态告诉 LLM） | —（错误分支从构造上不可达） | T11 |
| 5 | 跑出来的可用取值丢了 | 某次 trial **真进了深层分支的那个取值** | 下一轮又从头猜（`coverage_memory.json` 只写不读） | T12 |

**统一修法 = B3 的 CALLSPEC**：在符号放弃的每个点，把"已知半截信息"作为 `value_intent` 结构化塞进去，让 LLM **有据补全而非凭空猜**。其中 1/3 已有数据（T2 已做、T5 只需接线），2/4/5 需新技术（T10/T11/T12，要你批）。

---

# 三、附：fse26_tlr（TLR）参考价值分析（冷静版）

**结论：借鉴价值有限，而且恰恰不在"那个秀的自动机 formalism"上。不强行借鉴是对的。**

**TLR 是什么**：用 LLM 修 C 内存错误（UAF/DF/leak）。(a) ASan/Valgrind + PoC 复现；(b) 一张手写的**内存错误有限 typestate 自动机（FTA）** + GDB 单步，**只在 typestate 跳变点**抽上下文，拼成精简 context trace；(c) 结构化 prompting 喂 LLM。

**那个"秀"的自动机本体，对我们不转移——两条硬理由**：
1. **领域不同**：它建的是**"内存错误 typestate"**（uninit→live→dead→error）。我们要的是**"API 协议 typestate"**（句柄生命周期），而这个**我们已经有了**（`usedef.py` 的 `Typestate` 解释器 + project-adaptive automaton）。它的 formalism 套不到我们的对象上。
2. **阶段更要命**：TLR 是**事后**——有 PoC、bug 已知，拿 GDB **replay 一条具体执行轨迹**，自动机只是**在这条已知轨迹上做"留哪些快照"的过滤器**。我们是**前向合成**，没有执行、没有轨迹可走；它的 error-propagation-path 抽取在生成阶段**没有对应物**。
   → 自动机本体、replay 管线、传播路径推断规则，**都不搬**。硬搬即"强行借鉴"。

**唯一过硬、且我们已独立拥有的一条原则**：它的 ablation（Fig 10）证明**"用 typestate 选择性投喂" > "全量倒"**——把 backtrace 全函数倒进去的 TLR-M=11，远不如完整选择性系统 TLR=22，且比 SWE-agent **省 97% token**。但这条原则**正是我们 B3/T4 已经在走的方向**。所以 TLR 对我们的价值是：

> **一篇同行评审 + ablation，帮我们背书了一个我们本来就在做的判断。** 是"related-work 里的一个引用 / 设计 sanity-check"，**不是可以挖的机制**；对"正确 + 高 coverage"是**零代码增量**。（formalism 写论文时能让表述更严谨，但与 coverage 目标正交。）

**唯一"如果……才"的例外**：**如果**将来上 T12（轻量动态运行做取值反馈），它那个**"只在 typestate 跳变点快照、不逐行记录"的工程小技巧可直接复用**，让运行时 trace 保持精简。条件性、未来式，且只是工程模式。

**一句话**：继续自己的路线。把 TLR 降格为"佐证 B3 方向的一个引用"即可。**但它点醒了一件我们自己的事**——见下节：我们其实**已有 typestate 建模**，却**没把它（和 SVF）紧密喂给那个"裁决 sequence 合法性"的 LLM**。这才是 TLR 这面镜子照出的、我们能立刻改的真问题。

---

# 四、由 TLR 反观自身：typestate / SVF / LLM 三者**没紧密结合**（可立即用奥卡姆修）

## 现状：我们**已经**有精确的 typestate 建模
- `liberator_adapter/analysis/usedef.py`：`APIEffect`（每个 API 的 USE/DEF/KILL 摘要）、`UseDefGraph`、`Typestate.check(sequence)` → 精确的 `ViolationRecord`（USE_BEFORE_INIT / DESTROY_BEFORE_INIT / DOUBLE_DESTROY / USE_AFTER_DESTROY / REINIT_WITHOUT_DESTROY），逐句、逐句柄。
- L2/L3 过滤器（lifecycle / state_machine）**已经在调它**做"留/弃"。project-adaptive automaton 也是 typestate（句柄状态向量）。
→ **typestate 我们不缺，缺的是把它的"诊断输出"喂给 LLM。**

## 问题：LLM 裁决 sequence 合法性时，几乎看不到符号证据（松耦合）
`Comprehender-B`（`comprehender.py:comprehend_sequences`）让 LLM 判某条 API 序列语义是否 VALID/SUBOPTIMAL/INVALID，**喂进 prompt 的只有**：
- 序列（**只有函数名** `A -> B -> C`）、每 API 的 usage 文本、`allowed_apis`；
- `static_facts`（`comprehender.py:_build_static_facts`）= **只有聚合计数**（"3 init / 5 source / 2 sink"）+ 最多 8 条 init/destroy 对。

**它看不到**：① 这条序列的 **typestate 裁决结果**（`Typestate.check(seq)` 的 violations——我们算了，当过滤器用完就丢）；② 序列里这几个 API 的 **per-API USE/DEF/KILL**（SVF 已算，`automaton.graph.all_effects()` 就有）。
→ **LLM 只能从"名字 + 散文"里重新猜句柄生命周期结构**——既浪费、又容易幻觉，而且**真正能让它精确裁决的符号证据被我们扣下了**。这正是你说的"没紧密结合 SVF + typestate + LLM"。
（讽刺的是：prefilter 注释已经写明"acc<1.0 → 交给 LLM，因为没见过≠非法"——可一旦交给 LLM，我们却几乎不给它符号证据，等于**让它空手裁决**。）

## 奥卡姆修法（不引入任何新分析，只接线 + 剪裁）
把 `static_facts`（聚合计数）换成**"针对当前这条序列"的选择性符号证据块**：
1. **typestate 裁决**：对该序列跑 `Typestate.check(seq)`，把 violations 渲染成精确事实——"位置 2：USE 句柄 `sqlite3_stmt*`，但本序列中无任何 API DEF 它 → USE_BEFORE_INIT"。
2. **per-API USE/DEF/KILL**：**只渲染本序列涉及的那几个 API**（选择性——正是 TLR 那条有用的"上下文剪裁"：只给与本次决策相关的最小事实，不倒全量、不给聚合计数）。
3. **LLM 干它本职**：裁决这个 violation 是**真问题**（真 UAF/缺 creator → INVALID）还是**误报**（被 USE 的句柄其实是直接 fuzz 入口、不需要项目内 producer → VALID）。这恰好就是 prefilter 担心的"没见过≠非法"那个软判断——**但现在 LLM 是带着符号证据裁决，而不是空手猜**。

**为什么是奥卡姆**：`Typestate.check` 和 `all_effects()` **都已存在**；改动集中在 `_build_static_facts`（升级成 per-sequence）+ 在调用点把 effects/typestate 传进去。**零新分析、零新依赖**，只是把已算出的符号输出**选择性**接进 LLM 的 prompt。
**分工更干净**：符号层陈述**事实**（句柄 H 在位置 2 被 USE、全程未被 DEF），LLM 只做**软裁决**（这是致命还是合法入口模式）。
**注意主线**：这不是新功能，是**把现有三者拧紧**，且与 B3/T4 的 CALLSPEC 同源（CALLSPEC 给 Prototyper，本项给 Comprehender-B 裁决器）——**不偏离主线**。

### ✅ 已落地（commit「紧密结合 SVF⊕typestate⊕LLM」）
按你拍板的 a/b/c 实现：
- **(a) 带句柄类型 + 位置**：`comprehender._build_sequence_facts(seq, graph)` 渲染 `⚠ position N, <api>: handle <T> → <violation_kind>`。
- **(b) 同时给正向证据**：每个本序列 API 的 `USE/DEF/KILL {句柄类型}`（**只本序列涉及的 API**，选择性剪裁）。
- **(c) 改 prompt + 测试**：user 模板加 `{SEQUENCE_FACTS}` 块；system 加规则「违例是证据、非自动 INVALID；被 USE 的句柄若无 in-sequence producer 常是合法直接入口」（**防过度误杀的回归护栏**）。+5 单测、175 全绿。
- **回归护栏**：① 门控——无 automaton → `use_def_graph=None` → 行为不变；② 杀手锏——`LOGICFUZZ_DISABLE_SEQFACTS=1` 即时回退做 A/B。
- **✅ 冒烟 A/B 已跑**（c-ares，离线复用缓存 + 真 LLM gpt-4o-mini，temp=0，12 条 facts-bearing 序列）：
  - **噪声地板** A1 vs A2（同 prompt 复跑）= **0/12**（facts-bearing 序列上 temp=0 确定）。
  - **facts 信号** A1 vs B = **1/12 翻转，且是 rescue**（`INVALID→SUBOPTIMAL`：`ares_dns_parse→…→destroy` 的 DEF→USE→destroy 证据让 LLM 看出"可插消费者修复"而非死序列）；**新增误杀 = 0**。
  - 早前混合子集里"`ares_strerror` 被误杀"经查是**空 facts 序列上的 LLM 采样噪声**（A/B prompt 相同 → 非本特性）。
  - **结论：净正向、无回归**（救回假 INVALID，零新误杀）。注意：小样本/单项目/harness 强制全过 LLM（无 prefilter、project static_facts 为空）使绝对 INVALID 率比线上严，但 A vs B 隔离有效。
- **仍可做**：更大样本 + 多项目 + 线上完整 prepare() 的端到端覆盖对照（接 docker）。

---

# 五、审查：喂给 LLM 的数据能否 formalize？是否合理？

**问题**：把喂进 LLM 的数据抽象成字段 = schema 吗？这些数据能 formalize 吗？合理吗？
**一句话结论**：**能 formalize；但当前不合理**——Prototyper 提示词是 ~18 个临时拼起来的块，约 1/3 是**重复 / 死代码 / 原文倒灌**。我这几轮加的 value-intents 是其中**唯一一块成体系的 typed schema**；其余是历史堆积。合理化 = 把"该留的"收敛成一张 CALLSPEC、把"重复/原文"砍掉（即 T4）。

## 5.1 完整清单：Prototyper 实际喂了什么（按组装顺序，`prototyper.py:460-560`）

| 块 | 内容 | 来源 | 形态 | 评判 |
|---|---|---|---|---|
| `skeleton_code` | 空串 | `_retrieve_skeleton`（stub `return ""`）| 死 | ❌ **CUT**（死桩）|
| `srs_specification` | 函数分析摘要 | function_analysis | 散文 | ◐ 审视（低信号？）|
| `api_understanding` | 7-role **名称启发式**分类 | `classify_project_apis` | 散文表 | ❌ **CUT**（与 reconciled role 重复；G1 已降级名称启发式）|
| `library_purpose` | 一句话用途 | comprehender | 文本 | ✅ KEEP |
| `api_usages` | per-API 用法散文 | comprehender | 散文 | ◐ MERGE→CALLSPEC |
| `api_sequences` | 候选序列(名字) ×8 | api_sequences | 名字列表 | ◐ MERGE→skeleton |
| `sequence_signatures` | 序列 API 的签名+用法 | project_apis+usages | 半结构 | ✅ KEEP→**CALLSPEC 核心** |
| `sequence_invariants` | Comprehender-B 不变式 | sequence_semantics | 文本 | ✅ KEEP |
| `protocol_templates` | 自动机接受路径 | automaton | 序列 | ✅ KEEP |
| `project_apis` | top-20 签名 | project_apis | 签名表 | ❌ **CUT**（sequence_signatures 的低保真重复）|
| `dep_graph` | per-API 依赖 ×12 | dependency_graph | 图 | ◐ MERGE（与 handle_provenance/wiring 重叠）|
| `condition_info` | **聚合** role 计数 | condition_info | 聚合数 | ❌ CUT/RETYPE（per-sequence facts 已超越）|
| `skeleton_template`+`holes` | 骨架代码 + 洞 + **value_intents + library_constants** | CBFactory + hole_semantics | **typed schema** | ✅ **KEEP（核心）** |
| `include_path_context` | 头文件/包含路径 | headers | 结构 | ✅ KEEP |
| `driver_knowledge` | **3 份完整驱动源码** | existing drivers | 原文倒灌 | ❌ **CUT→压缩**（最大 token sink；与 idioms 重复）|
| `baseline_recovery` | §10B 回归恢复提示 | baseline_diff | 文本 | ◐ 条件保留 |
| `synthesis_base` | **同一** active_skeleton 的"refine-this"视图 | active_skeleton | 代码 | ❌ **CUT**（skeleton_template 的重复视图，已取证两者同吃 `active_skeleton`）|
| `extern_c_note` | `extern "C"` 样板 | 静态 | 样板 | ◐ 移到 system prompt |

**Comprehender-B**（序列合法性裁决，`comprehender.py`）：`sequence`(名字) + `api_usages`(散文) + `static_facts`(聚合计数, RETYPE) + **`sequence_facts`(per-API USE/DEF/KILL + typestate 裁决, ✅ typed)** + `allowed_apis`(名字)。

## 5.2 合理性判决（量化）
~18 个 Prototyper 块里：
- **✅ 该留、且已/可 typed**：~6（skeleton+holes 的 value_intents/library_constants、sequence_signatures、sequence_invariants、protocol_templates、library_purpose、include_path）。
- **❌ 重复/死/原文倒灌**：~6（skeleton_code 死桩、api_understanding 第二套 role、project_apis 重复、synthesis_base 重复骨架、condition_info 聚合、driver_knowledge 3 份原文）。
- **◐ 可并入或迁移**：~5（api_usages/api_sequences/dep_graph 并入 CALLSPEC；baseline_recovery 条件；extern_c 进 system）。

→ **三套"API 视图"**（api_understanding / sequence_signatures / project_apis / dep_graph 各说一遍同一批 API）+ **两套骨架视图** + **两套 role 分类** + **3 份原文驱动**：这就是"不合理"的实证。**不是 schema 的问题，是没把它们收成一个 schema。**

## 5.3 formalize 的目标：一张 CALLSPEC（T4）
把上面 ✅+◐ 收敛成**每个调用一行的 typed 元组** + 少量项目级 slot：

```
CALLSPEC（每调用一行）:
  step | api | role(APIRole) | signature | ret_contract(nullable?/sentinel) |
  args[ (i, type, argrole(ArgRole), value_intent, pairs_with, populated_from) ] |
  needs[handle←producer | orphan] | produces[handle] | precond | cleanup
项目级 slot（各一次、token-bounded）:
  library_purpose · library_constants · idioms · protocol_templates · 1 个压缩范例
```
每个字段都已有权威来源（见第三/四节 + ②′ 表）。这张表**替掉** api_understanding / api_sequences / sequence_signatures / project_apis / dep_graph / condition_info / synthesis_base / driver_knowledge 八个块。

## 5.4 诚实的自我批评（即便已 typed 的部分）
- **`value_intent` 仍是自然语言串**，不是真正 typed 的值（例如 `"VARY_RANGE: …"` / `"ENUM (T): one of {…}"`）。这是**符号→LLM 的交接点**，本就该软；但要更严格可把它拆成 `{kind: ENUM|RANGE|STRUCTURED_INPUT|LENGTH|HANDLE, payload: …}`，渲染时再转串。**是否值得，取决于 LLM 对结构化 vs 散文 intent 的敏感度——需 A/B。**
- **两个决策点 schema 尚未统一**：填洞用 value_intents、裁决用 sequence_facts，字段有重叠（role、USE/DEF/KILL vs handle_provenance）。可抽一个公共 `APIView` 基类，两处各取所需。
- **CALLSPEC 尚未落地**：今天是"一块成体系 + 一堆散块"，T4 才把散块收进来。**这步会改 LLM 行为，必须端到端 A/B**（旧/新提示词比覆盖+token）。

**给你拍板**：(a) CALLSPEC 字段集是否就用 5.3 这版？(b) `value_intent` 要不要拆成 typed `{kind,payload}`，还是保持串先跑 A/B？(c) 砍 driver_knowledge 3 份原文 → 换 1 个压缩范例，是否同意（这是最大 token 节省，但也动 few-shot）？

### 决定（2026-06-06，已拍板）
- (a) ✅ **CALLSPEC 就用 5.3 这版**（暂定）。
- (b) ◐ **轻拆**：给 `value_intent` 加一个 `kind` 标签（`ENUM|RANGE|STRUCTURED_INPUT|LENGTH|HANDLE|OUTPUT`）让 CALLSPEC 表可扫；payload 保持串。**不做完整 typed-value 重构**（影响小，等下游符号消费者真需要再拆——empirical-before-parametric）。
- (c) ✅ **砍原文**，但用 §5.5 的方法选范例（不是"前 3"）。

## 5.5 选择方法：不要 top-N，要 *scope + 相关性阈值*
**反模式**：`max_drivers=3` / `limit=8/20/12` 这些**固定 top-N 截断**没道理。正确做法分两种 regime：

**A. 任务范围内的数据 → 只给范围、不截断（范围内穷举）。** `api_sequences`/`project_apis`/`dep_graph` 不该是全局 top-N——真正相关的只有**当前 active skeleton 序列里的那几个 API + 它们的直接 producer**。就一小撮，穷举、确定性。CALLSPEC 本就 per-call → 这些 cap 直接消失。

**B. 大候选池（参考驱动 / 跨项目语料）→ 相关性阈值 + token 预算，不是 count-N：**
- **结构签名（主，确定性、精确）**：拿候选驱动对 *当前序列* 打分——{API 集、句柄类型目录、生命周期 n-gram、creator/parser 入口类型} 的重叠。我们有精确结构，所以比 embedding **又便宜又准**。取所有 score ≥ τ 的、按分排，直到 token 预算 B；若无人过 τ，取最佳 1 个（资料稀薄的库也有兜底）。→ "所有相关的"，不是"前 3"。
- **embedding（次，仅跨库/跨命名）**：结构签名在**同领域、不同 API 命名**的兄弟库上会失配（T7 高天花板那种"另一个 JSON parser"）——这正是语义 embedding 该上的地方。**先结构、量化它漏了什么、只为跨命名残差补 embedding**（别一上来就建向量库）。

**落点**：
- `driver_knowledge`（**同项目**驱动，1-15 个）：用结构签名对当前序列选最相关的（压缩版），token 预算封顶——同项目用结构足矣，**不需要 embedding**。
- T7（**跨项目**语料）：结构签名为主 + embedding 补跨命名残差，阈值而非 top-k。

---

# 六、为什么 coverage 落后 baseline 这么多？方法论差距分析（2026-06-06）

对照 PromeFuzz Table 2（24h，PromeFuzz/PromptFuzz/CKGFuzzer）。**一句话：差距主要是 API 广度差距，根因是我们 correct-by-construction 把"连不上的孤岛 API"整个排除在序列之外。**

## 6.1 数据
| | lcms | c-ares | zlib |
|---|---|---|---|
| public API | 1032 | 781 | 158 |
| **我们候选序列覆盖的 API** | **166** | **60** | **67** |
| **PromeFuzz #API（可运行 harness）** | **358** | **113** | **89** |
| 我们 APIs/序列 均值 | 7.0 | 3.7 | 3.6 |

外加 T9 实测：**302/452 个 gap API 从不出现在任何候选序列里**。

## 6.2 三个叠加的成因
1. **构造排除"孤岛 API"（主因）**。correct-by-construction 只把**符号上能连起来**的 API 串成序列；opaque/void* 参数、无项目内 producer 的深层 API 连不进任何链 → 从不进序列 → 从不成 driver。候选广度因此只有 PromeFuzz 的 ~46%(lcms)/53%(c-ares)。这正是文档里"lcms portfolio 被单一子系统主导、saturate 在 27-29%"的根。baseline 没这限制——LLM 想调哪个 API 就调，连不上就乱写/崩了再修。
2. **漏斗只丢不修**。候选 166 → 可运行 driver ≪ 166（Z3 可行性 + 绑定 + 编译各丢一层），而我们**没有结构修复**（Phase A 已删）。PromeFuzz 的看家本领恰是 **repair loop**——harness 编译/运行失败就修，所以它的 358 是**可运行**的。我们为了 valid-by-construction 把失败直接丢——这就是广度的代价。
3. **每 driver 太薄（c-ares/zlib）**。均值 3.6-3.7 个 API/序列 = 最小生命周期链（create→use→destroy）。高覆盖要的是**稠密 harness**（PromeFuzz lcms ~24 API/harness）。我们优化的是"每个调用都对"，不是"每个 driver 多调几个"。

## 6.3 诚实的元判断
**我们这一季的工作（CALLSPEC、schema、correctness）优化的是"精度"；baseline 赢在"广度 + 恢复力"。对原始 branch coverage，`广度 × 稠密度 × fuzz 时间`才是主项，而我们一直在拿广度/稠密度换 validity。** 三大创新（reconcile / 构造 / gap-direction）让我们**更准**，但没让我们**更广**。

## 6.4 方法论修法（按杠杆排序；24h 跑之前要做的）
1. **别再丢孤岛 API（最高杠杆，=binding 层 #14 的重构）**。把"绑定失败 → 丢 API"改成"绑定失败 → 把那几个参数当洞、连同 T5 来路 + ret_contract + CALLSPEC 签名一起交给 LLM 填"。**binding 从二元（bind-or-drop）改成优雅降级（bind-or-hint-and-defer）。** 我们这一季造的 hint（T5/CALLSPEC）正是 LLM 填这些洞需要的料——铺垫已就位。
2. **让 LLM 加密 driver**。给它"骨架 + 这个子系统的 gap-API 清单"，让它顺手多织几个相关调用（提高 API/driver），尤其 c-ares/zlib。
3. **漏斗变得能容错**。靠 LangGraph fixer 把编译失败救回来（别丢），缩小 候选→可运行 的衰减——像 PromeFuzz 那样 loss-tolerant。
4. **按子系统多生成 driver**（gap API 按子系统聚类：lcms postscript/tag/optimizer）。
5. **修测量**：coverage-build clobber（sancov 被覆盖→盲跑）+ 退化的 eval build（zlib 重测 baseline）会**放大**表观差距，跑 24h 前先修，免得白跑。

## 6.5 张力（要你拍板）
修法 1/2/3 本质是**为了广度，放松一点"correctness-first"**——让 LLM 去试那些符号搞不定的硬 API（可能失败、要修）。这跟我们"correct-by-construction、无 repair"的主线**有张力**。但可以两全：**符号保证它能保证的（可连核心），孤岛 API 给最大 hint 让 LLM best-effort**（失败交 fixer）——优雅降级，而非硬丢。这样既保创新、又拿广度。**是否走这条优雅降级路线，要你定。**

## 6.6 实现状态（2026-06-07）：breadth + low-FP 组合拳已落地（走了优雅降级路线）

§6.4 修法 1/2 + §6.5 的优雅降级**已实现并实测**。详细机制写在 `docs/contributions_and_related_work.md`（设计/对标）+ `CLAUDE.md`（flags/组件）；这里只留状态 + 数据。

**落地的杠杆**（都带 kill-switch，符合"符号定结构、LLM 填软值"）：
| 杠杆 | 边界 | flag | 一句话 |
|---|---|---|---|
| **B 优雅降级** | 6.4-#1 | `LOGICFUZZ_STRICT_ORDERING` off | 孤岛 API（USE_BEFORE_INIT on orphan handle）不再被 ordering 过滤器丢，进候选→unchecked render 留洞→LLM 填 |
| **density** | 6.4-#2 | `LOGICFUZZ_DENSE_CONSTRUCT` | 在生命周期链后附加 USE 已开句柄的 extender（mutator*→consumer*→getter*），稠密化薄 driver |
| **hard-guard** | 低-FP | 由 density 蕴含 | ret_contract 升级 `MUST-GUARD if(!x)return0` + opaque 句柄工厂链提示；**density 必须配它**（消融证明 density-only 有害） |
| **keep-best + 文件回写** | 低-FP | 默认 | 绝不 ship 比本 trial 峰值差的 driver；回退时把恢复源码**写回磁盘**（否则 merge ship 差驱动） |
| **dead-filter 修复 + pre-ship 隔离** | 低-FP | 默认 | preflight 崩溃 drop 的死代码 bug 修复；merge 前用 trial 自身判定丢"立即崩溃0覆盖"假阳性（毒化融合 harness） |
| **crash-frame classifier** | 低-FP | 复用核心 | 确定性 ASan 帧归因 driver-bug vs library-bug（符号事实，不交 LLM 裁） |

**实测（30s A/B，best driver；非 24h，不可直接对标 PromeFuzz Table 2）：**
| 项目 | baseline | combo(density+guard) | Δ覆盖 | baseline FP | combo FP |
|---|---|---|---|---|---|
| lcms | 66 | **206** | **+212%** | 1 | 0 |
| c-ares | 1410 | 1412 | +0%（best 中性） | 4 | 4 |
| zlib | 515 | **545**（trial01 85→399） | +6% | 0 | 3（pre-ship 隔离会在 merge 丢掉）|

**消融结论**：density 与 guard **协同**——单独都不行（lcms density-only=0 全 SEGV、guard-only=54≈66），combo 才 206。**c-ares "回退"经子代理根因 = LLM n=1 采样方差**（density 对无句柄的纯 parser 是构造级 no-op，没接任何 extender；136→14 是 LLM 那次采样把 `abuf` 绑到 buffer 末尾→立即 ARES_EBADNAME），**非 density 系统性伤害**；且其中一部分是 keep-best 文件回写 bug 污染（已修）。

**待办**：24h `--merge` union 跑（后台进行中）才能对标 PromeFuzz（their lcms ~13k / c-ares 6,106，24h 数十 driver union）。<br>
**未走的修法**：§6.4-#3（漏斗容错/fixer 救回）、#4（按子系统多生成）、§6.5 的"放松 correctness 让 LLM 试硬 API"——目前优雅降级已在不牺牲主线的前提下拿到广度，这几条留作后续。


TODO: 本文档需要更新，你要移除掉我们确认完成的任务和实现好的技术细节内容；只保留不确定的、需要你拍板的部分。 已完成的优化任务和新组件（包括schema定义、callspec设计、typestate快照等）可以简洁地更新到仓库的README或设计文档中，保持这个文档专注于待决策的事项和未来的计划。