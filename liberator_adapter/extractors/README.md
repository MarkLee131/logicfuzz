# Liberator API 提取器

本模块提供了使用 Clang 和 LLVM 直接提取 Liberator API 信息的功能。

## 概述

提取器封装了 Liberator 仓库中的工具：
- **ClangAPIExtractor**: 使用 `extract_included_functions.py` 从头文件提取 `apis_clang.json`
- **LLVMAPIExtractor**: 使用 `condition_extractor/bin/extractor` 从 bitcode 提取 `apis_llvm.json`
- **HybridAPIExtractor**: 整合两者，提供完整的提取流程

## 使用方法

### 基本用法

```python
from experiment.benchmark import Benchmark
from liberator_adapter.extractors import HybridAPIExtractor

# 创建基准对象
benchmark = Benchmark(project='zlib', ...)

# 创建混合提取器
extractor = HybridAPIExtractor(benchmark)

# 提取所有 API
apis = extractor.extract()

# 获取特定函数
api = extractor.get_api('adler32')
```

### 在适配器中使用

```python
from experiment.benchmark import Benchmark
from liberator_adapter.adapter import LiberatorAPIAdapter

# 创建基准对象
benchmark = Benchmark(project='zlib', ...)

# 使用 Clang/LLVM 模式创建适配器
adapter = LiberatorAPIAdapter(
    project_name='zlib',
    use_clang_llvm=True,
    benchmark=benchmark
)

# 提取单个函数
api = adapter.convert_to_liberator_api('int adler32(unsigned int adler, const unsigned char *buf, unsigned int len)')

# 或提取所有 API
all_apis = adapter.extract_all_apis()
```

## 工作流程

1. **Clang 提取** (`extract_apis_clang`)
   - 从头文件目录提取函数声明
   - 生成 `apis_clang.json`（包含 `type_clang` 和 `const` 信息）

2. **编译到 Bitcode** (`compile_to_bitcode`)
   - 使用 `wllvm` 编译项目
   - 提取 bitcode 文件（`.bc`）

3. **LLVM 提取** (`extract_apis_llvm`)
   - 从 bitcode 分析函数参数
   - 生成 `apis_llvm.json`（包含 `flag` 和 `size` 信息）

4. **合并数据** (`_merge_apis`)
   - 使用 `Utils.get_api_list()` 合并 Clang 和 LLVM 数据
   - 生成最终的 `Api` 对象

## 配置要求

### 容器环境

提取器需要在 OSS-Fuzz Docker 容器中运行，容器需要：

1. **Clang Python bindings**
   ```bash
   pip install clang
   ```

2. **wllvm** (Whole Program LLVM)
   ```bash
   pip install wllvm
   ```

3. **Liberator 工具**
   - `extract_included_functions.py` 需要可访问
   - `condition_extractor/bin/extractor` 需要已编译

### 文件路径

提取器会自动处理以下情况：
- 如果 Liberator 目录已挂载到容器内的 `/liberator`，直接使用
- 否则，自动复制必要的脚本/二进制文件到容器内的 `/tmp`

## 注意事项

1. **性能**: 首次提取可能需要较长时间（编译项目、分析 bitcode）
2. **缓存**: 提取结果会缓存在 `api_cache` 中
3. **清理**: 使用完毕后调用 `cleanup()` 清理临时文件和容器

## 示例

完整示例请参考 `test_liberator_extractors.py`（如果存在）。

