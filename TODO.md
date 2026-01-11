2025/01/09

0. DONE: 我们已经全面移除了支持针对特定函数fuzz的功能，目前是scope是面向指定项目来自行寻找api sequence来写fuzz driver。

1. clang 的安装;

2. 实现在给定项目之后，自动拉取项目源代码到本地，然后用liberator进行静态分析，得到类型依赖图和对应的一些路径约束、头文件信息等等。后续我们再对图上的所有API调用序列路径先一一展开，然后过滤语义上无用的序列。

注意，当前的type dependency graph 里存在“过度依赖”问题 (类型匹配 != 调用依赖)
  - 算法将"类型匹配"等同于"依赖关系"
  - 例如,所有返回 cJSON * 的函数都被认为是所有接受 cJSON * 参数的函数的依赖
  - 这导致依赖数量虚高(最多79个依赖


3. 梳理liberator里的局限性，尤其是针对API chain的生成的误报
已知问题：
（1）var-len这里，他们是启发式设计：hard-code 他们两个的关系。
（2）对于包含loop的chain，没有处理？
（3）对于回调节点（function pointer），他们默认用stub function来处理；


( final TODO: public headers 信息可以用fuzz introspector，或者用我们的逆拓扑排序手动去获取。)