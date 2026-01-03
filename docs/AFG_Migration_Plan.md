# Developement Plan

## Overview

1. 复用liberator里的AFG。

2. 对AFG进行剪枝：
(1) 使用额外的上下文信息，进行语义校验。

包括：使用long-term memory里的跨项目知识，剪枝掉语义上无意义的调用序列（这依赖于对目标项目里状态机的建模）；
注意：目前long-term memory还没实现好！需要两边联动设计。

(2)优先选择高分支点部分的检查，fan-out大。不确定：是否可以根据API调用序列长度来排序，优先选择调用序列最长的一条path。

(3)已知的同项目里的fuzz driver，代码注释用于进一步检查API调用序列是否合理（因为信息量不大，这部分作为补充使用）

3. Long-term memory的建立：

利用extracted_fuzz_drivers文件夹下的已有driver 代码，提取：

（1）API生命周期和资源语义；
（2）API调用顺序的协议语义； （一般是来源于文档）
（3）API角色和用途语义；
（4）参数层面的语义约束（这里特指类型之外的语义约束，因为AFG使用了类型信息）；

（5）回调语义（function pointer）的处理；
（6）Fuzzer输入与API的语义对齐（TLV）
（7）多API组合的高阶语义学习和提取；

## AFG (API Flow / Dependency Graph) 集成与迁移计划

> 目标：在 `logicfuzz` 中引入 AFG 驱动的 API 序列选择策略，把 `liberator` 中与 AFG/依赖图相关的实现迁移到现有 `liberator_adapter`，并以可配置的方式在 generator 中启用该策略。

---

## 一、高层目标与约束
- **非破坏性**：初期采用“复制 + shim”策略，保持现有 `liberator` 代码可回退。  
- **可配置性**：AFG 指导为可选策略（配置开关），便于对比与回滚。  
- **最小入侵**：通过适配层提供统一接口，尽量少改动 `logicfuzz` 现有生成器调用点。

---

## 二、需要提供的 adapter 公共接口（建议）
- `DependencyGraph`（图数据结构与基本操作）  
- `TypeDependencyGraphGenerator` / `UndefDependencyGraphGenerator`（生成依赖图的工厂/生成器）  
- `GrammarGenerator`（把依赖图转为文法用于 driver/序列生成）  
- `Bias` 接口及实现：`IBias`、`WBias`、`SBias`（为候选 API 加权/选择提供策略）  
- 工具/兼容模块：必要的 `Api`、`Utils`（如 `calc_api_seq_str`）  
- 包装/工厂方法：例如 `create_dependency_graph(config)`、`create_bias(config)` 以便在 `Configuration` 中调用

注：这些接口应保持简单、类型清晰，便于在 `logicfuzz` generator 中按需替换或组合现有 bias。

---

## 三、迁移策略（步骤）
1. Inventory（清点）：列出所有与 AFG/依赖/bias/grammar 有关的文件与依赖关系。  
2. 设计 adapter 公共 API（接口、导出函数、预期输入/输出）。  
3. 在现有 `liberator_adapter/` 内组织统一命名空间，创建 `__init__.py` 并实现导出接口。  
4. 复制核心实现文件到 `liberator_adapter/`（保留原始实现作为回退）。  
5. 在原路径放置轻量 shim（例如在 `liberator/framework/dependency/DependencyGraph.py` 保持小文件，转发到 `liberator_adapter.dependency`）。  
6. 更新 `logicfuzz` 的 `Configuration` / generator 配置以支持 `afg_adapter` 开关与 `afg_policy` 参数。  
7. 在 generator 的候选 API 选择路径中引入 adapter 的 `Bias`，并实现平滑回退。  
8. 编写单元/集成测试并运行 lint，修复所有导入/类型错误。  

---

## 四、集成点（在哪改）
- `liberator/framework/generator/Configuration.py`：在 `dependency_graph` / `factory` 创建逻辑中加入 `liberator_adapter` 的工厂调用或配置开关。  
- `liberator/framework/bias/`：把 bias 的实现抽象为可由 adapter 提供的实现，或在 adapter 中复用现有实现并导出兼容对象。  
- `driver.factory` 及相关 `CBFactory`/`CBGFactory`：若这些工厂依赖于依赖图或 grammar，改为从 adapter 接收图/grammar。

---

## 五、测试与验证
- 单元测试：对 adapter 中的 `DependencyGraph`、生成器和 `Bias.get_random_candidate` 做快速导入与行为测试（不需要完整生成 driver）。  
- 集成测试（可选）：在一个小 target 上运行 driver 生成比较开启/关闭 AFG 的差异（覆盖/driver 多样性）。  
- Lint/静态检查：每次迁移后跑 `flake8`/`pylint` 或仓库主用 linter，停留并修复问题。

---
## 六、开放问题
1. 命名一致性：仓库已有 `liberator_adapter`,采用已有名字。
2. 把 AFG 默认启用，他是我们driver生成的基础。
3. 先生成完整 inventory 并与我核对后一次性迁移。


