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
- **现成驱动的调用序列 + 实参来源被丢掉了。** 只有 3 份原文 + 10 条正则惯用法（`idiom_distiller.py`）留了下来；最权威的 API n-gram 序列、以及「哪个返回值喂给哪个实参」的来源图，从没被重建过。自动机（automaton）从 tests/examples 里学序列，却*偏偏不从驱动源码里学*——而驱动恰恰是「合法 fuzz 入口序列」最权威的范例。
- **文档先验默认关闭**（`--use-doxygen-priors` / `--use-readme-purpose`）。默认跑法下，库的用途是从项目名硬编出来的，从不读 `@param` 的所有权语义、也不读 `@return`/`@retval` 的 NULL 契约——而这恰恰是「生成的驱动漏掉对 creator 返回值的 NULL 检查」那条记忆所需要的信号。
- README 里的 **Quick-Start 代码块**（一个免费的可运行示例）被显式剥掉了；**种子语料**（真实输入格式 / 魔数）只在 fuzz 阶段用，对生成阶段不可见；**build.sh/.dict/.options**（必需的 `-D` 宏、格式字典、`max_len`）也没被挖。

### B2. 静态分析 → 模型（维度二）——丰富的 SVF 数据在边界处被销毁
- **整个 per-param `access_type_set` 被压成了一个布尔值。** `usedef.py:363` 把每参数约 969 处字段级 struct 访问 + create/delete 来源 + 逐字段写掩码（lcms 数据）统统压成 `_svf_writes` 一个 bool，其余全扔。
- **`set_by`（参数→参数 的初始化依赖图，lcms 上约 75 条边）** 没被提升进 `APISemanticModel` / 序列构造器——模型的 requires/produces 纯按句柄类型建键，根本表达不了「arg0 这个 struct 是由 param_2/param_3 填充的」。
- **没有抽取错误返回 / NULL 后置条件**（IR 里的 `if (p==NULL) return; if (rc<0) goto err`）——这些从 extractor 已经加载的 bitcode 里完全恢复得出来。这*就是*那个 NULL 检查 bug 的根。
- **没有真正的 CFG 可达性。** L4 所谓「可达性优先」其实是自动机*接受度*（协议顺序匹配），不是对未覆盖基本块的静态可达性；gap 信号只是函数级的有/无。
- **没有 CONFIG 标量参数的枚举/取值域**（switch 表、enum 定义、相等性守卫，本可界定哪些取值能进到有意思的代码）。

### B3. 模型 → LLM（维度三）——喂得太多、重复、过时
- **两套冗余的 role 分类**同时塞进提示词（被降级的命名启发式 `classify_project_apis`，以及已经协调过的 `APISemanticModel` roles）。
- **3 份完整的现成驱动源码**被原样倒进提示词（单项最大的 token 消耗），还跟已经提炼好的 `<library_idioms>` / `<code_patterns>` 大量重叠。
- **系统提示词还在宣传一个已删除的工具**：`fuzz_introspector_query` 加 4 处「去查源码」/「去查用法示例」的指令，可 `get_tools()==[]` → 诱发幻觉工具调用、白白消耗注意力。
- 多个重叠的 API 视图（`<api_sequences>` / `<sequence_api_signatures>` / `<project_apis>` / `<dependency_graph>`）、重复的 skeleton 渲染、「多调几个 API」这条规则重复说了 3–4 遍，而且没有全局 token 预算。

### B4. 符号方法在它放弃的地方，把锅甩给 LLM 去猜（维度四）
- **CONFIG/枚举参数**只拿到 `VARY_RANGE：覆盖合法与非法取值`（`hole_semantics.py:96`）；LLM 只能*猜*合法值（lcms `TYPE_RGB_8`、intent 0–3；zlib level 0–9）。其实按参数 typedef 去扫一下头文件的 enum/#define，就能确定性地给出这些值。
- **格式入口（front-gate）只硬编了 2 种格式**（ICC `acsp@36`、IT8）；其余一律给一句含糊的 header/body 提示 → 解析器只能浅尝辄止（即「已覆盖函数内部仍有未覆盖分支」那条教训）。
- **绑定失败的原因沦为只写不读的遥测。** `try_to_get_var` 抛 `ConditionUnsat`（incomplete_opaque / struct_needs_init / has_source）时，原因——现在由新加的 `_record_binding_rejection` 记下来了——却从没流到 `create_skeleton_unchecked` 路径上的洞标注里，于是 LLM 永远不知道「这个参数需要一条初始化链 / 是不透明类型」。
- **只走 happy-path 的骨架**（create→use(合法)→destroy）——错误处理 / UAF / 把 NULL 当句柄 / 乱序销毁这些分支，从构造上就*不可能*被覆盖到。
- **没有动态取值反馈。** Phase C 的 `coverage_memory.json` 只写不读；某次 trial 好不容易让一个取值进到了深层分支，这个事实却丢了。

### B5. 人类专家对照（统一版）
一个专家给 lcms `cmsDoTransform` / zlib deflate 链写高覆盖驱动时会做五件事：(1) 读头文件**枚举**拿合法常量；(2) 读解析器**源码/IR**拿入口字节谓词（魔数 / 长度前缀 / 版本）；(3) 读 **@return** 拿 NULL 契约；(4) **照抄**本项目或同类项目现成驱动的调用序列 + 输入分发；(5) 从**调用图**判断哪个 API 把守着最多未覆盖代码。工具在（生命周期 + 句柄接线）上很强，但 (1)–(5) 基本都跳过了。

---

## 优先级方案

### 第一梯队——确定性、低风险、高杠杆（不需要新技术；先做）
每一条都用工具已有的、或能廉价拿到的数据，去堵一道边界泄漏：

| # | 改动 | 边界 | 杠杆/工作量 | 状态 |
|---|------|------|------------|------|
| T1 | **别再把 SVF 压成一个 bit。** 把 per-arg 字段写掩码 + `set_by` 初始化依赖边 + `len_depends_on`/`is_array` 从 conditions.json 提升进 `APISemanticModel` 和 G4 洞的取值意图。 | B2 | 高/中 | 待做 |
| T2 | **为 CONFIG 参数做符号化 enum/#define 抽取。** 扫头文件拿到参数 typedef 的合法枚举/常量集，用真实取值集替换泛泛的 `VARY_RANGE`。 | B4 | 高/中 | ✅ 已完成（`named_constants.py`；lcms 11 个枚举、zlib `Z_*` 已端到端验证） |
| T3 | **逐 API 抽取错误返回 / NULL 后置条件**，作为强制的洞/守卫约束（修掉 creator NULL 检查 bug）。 | B2 | 高/中 | 待做 |
| T4 | **LLM 瘦身 → 一张 typed CALLSPEC DSL 表。** 砍掉 3 份原文驱动 + 一套 role 分类 + 过时的 fuzz_introspector 指令；把重叠的 API/skeleton 视图收成「每个调用一行」的元组 `step │ api │ role │ ret │ args=[(i,type,argrole,pairs_with)] │ needs │ precond/cleanup │ value_intent`；加一个全局 token 预算仲裁。 | B3 | 高/小 | 🚧 部分（已删过时工具指令；CALLSPEC 重构待做，且需端到端 A/B 验证） |
| T5 | **把绑定失败原因 + 分析器找到的 producer**，标到 unchecked-skeleton 路径的洞上（数据已由新遥测 + `find_producer_apis` 算出）。 | B4 | 高/小 | 待做 |
| T6 | **文档先验默认开**；把 `@return`/`@retval` 解析成结构化的错误/所有权契约；把 README 第一个用法**代码块**当 few-shot。 | B1 | 高/小 | 待做 |

### 第二梯队——更大，或需要新技术（先报你批准）

| # | 改动 | 为什么需要你拍板 |
|---|------|------------------|
| T7 | **跨项目驱动检索**：给 `extracted_fuzz_drivers/`（外加拉取更大的 OSS-Fuzz 语料）建索引，按 API 形态签名（creator/parser 入口类型、不透明句柄目录、出错返回模式）取 k-NN 同类驱动注入到资料稀薄的库。 | 最大的一块输入信号，但要建语料 + 一个检索/嵌入组件。 |
| T8 | **从本项目自己的驱动里挖调用序列 + 实参来源**喂进自动机/构造器（把 `static_trace.extract_project_traces` 也用在驱动 `.c` 上，而不只是 tests）。 | 中等工作量；会改变自动机学习的来源。 |
| T9 | **给 gap API 加静态 CFG 可达性权重**进 L4（从 bitcode 数它能传递可达的未覆盖块数）。 | 需要对 bitcode 做一遍调用图分析。 |
| T10 | **泛化格式入口解码器**：用符号常量传播去推解析器入口的校验（替掉硬编的 2 种格式）。 | **新技术：轻量符号执行 / 取值约束分析。** |
| T11 | **符号化的形态变体骨架**（NULL_INJECT / double-free / 乱序销毁），让错误路径分支变得可达（LLM 仍只填叶子取值）。 | 中等；改动骨架发射器结构（generation.md F5）。 |
| T12 | **动态取值反馈闭环**：编译并跑一个微探针（或从某次 trial 里挖出存活的取值），把可用的叶子取值/初始化链钉进下一个骨架的洞（Phase C 的「读」侧）。 | **新技术：轻量动态运行。** |

### 建议的起步顺序
**T2 + T4 + T5 是最好的第一刀**——杠杆最高、风险低，而且互相成全：T2 把真实合法值给 LLM，T5 告诉它哪些参数难、难在哪，T4 把淹没这两个信号的冗余文本清掉。T1/T3/T6 紧随其后（都是确定性的）。T7（跨项目）是第二梯队里天花板最高的一项。T10/T12 是两处「新技术（符号执行 / 动态运行）」明显能回本的地方——是提议，不是擅自决定。

> 说明：T4 里的 CALLSPEC 重构会**以单测无法捕捉的方式改变 LLM 行为**，要确认它真能提覆盖、且不致退化，需要一次端到端 A/B（用旧/新提示词在 cjson/zlib/lcms 上各跑一遍、比覆盖率）。
