2025/12/21

0. 梳理liberator里的局限性，尤其是针对API chain的生成的误报
已知问题：
（1）var-len这里，他们是启发式设计：hard-code 他们两个的关系。
（2）对于包含loop的chain，没有处理？
（3）对于回调节点（function pointer），他们默认用stub function来处理；