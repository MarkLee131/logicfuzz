# 新项目集成指南：OSS-Fuzz + FuzzIntrospector + LogicFuzz

本文档详细介绍如何将一个新的C/C++项目集成到OSS-Fuzz，生成FuzzIntrospector数据库，并运行LogicFuzz进行自动化fuzz target生成。

## 目录

1. [前提条件](#1-前提条件)
2. [创建OSS-Fuzz项目](#2-创建oss-fuzz项目)
3. [构建项目并生成FI数据](#3-构建项目并生成fi数据)
4. [导入FI数据库](#4-导入fi数据库)
5. [创建Benchmark配置](#5-创建benchmark配置)
6. [运行LogicFuzz](#6-运行logicfuzz)
7. [常见问题](#7-常见问题)

---

## 1. 前提条件

### 1.1 环境要求

- Docker 已安装并运行
- Python 3.10+
- LogicFuzz 仓库已克隆
- FuzzIntrospector 本地服务已启动（端口8080）

### 1.2 目录结构

```
logicfuzz/
├── oss-fuzz/
│   └── projects/
│       └── your-project/    # 新项目放这里
├── conti-benchmark/
│   └── your-project.yaml    # benchmark配置
└── fuzz-introspector/
    └── tools/web-fuzzing-introspection/app/static/assets/db/
        └── all-functions-db-your-project.json  # FI数据库
```

---

## 2. 创建OSS-Fuzz项目

### 2.1 创建项目目录

```bash
mkdir -p oss-fuzz/projects/my-project
cd oss-fuzz/projects/my-project
```

### 2.2 创建源代码文件

以一个简单的字符串解析库为例：

**strparser.h**
```c
#ifndef STRPARSER_H
#define STRPARSER_H

#include <stdint.h>
#include <stddef.h>

// 函数声明
int strparser_hex_decode(const char *input, size_t input_len,
                         uint8_t *output, size_t output_size,
                         size_t *output_len);

#endif
```

**strparser.c**
```c
#include "strparser.h"
#include <stdlib.h>
#include <string.h>

int is_hex_digit(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

int hex_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int strparser_hex_decode(const char *input, size_t input_len,
                         uint8_t *output, size_t output_size,
                         size_t *output_len) {
    if (!input || !output || !output_len) return -1;
    *output_len = 0;
    if (input_len % 2 != 0) return -1;

    size_t expected_output_len = input_len / 2;
    if (expected_output_len > output_size) return -1;

    for (size_t i = 0; i < input_len; i += 2) {
        if (!is_hex_digit(input[i]) || !is_hex_digit(input[i + 1])) {
            return -1;
        }
        int high = hex_to_int(input[i]);
        int low = hex_to_int(input[i + 1]);
        output[*output_len] = (uint8_t)((high << 4) | low);
        (*output_len)++;
    }
    return 0;
}
```

### 2.3 创建Dockerfile

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder

# 安装依赖（根据项目需要调整）
RUN apt-get update && apt-get install -y \
    make \
    gcc

# 复制源代码
COPY strparser.h strparser.c $SRC/my-project/
WORKDIR $SRC/my-project
COPY build.sh $SRC/
```

### 2.4 创建build.sh

**重要**：build.sh必须创建一个调用库函数的fuzzer，否则FuzzIntrospector无法捕获函数信息。

```bash
#!/bin/bash -eu

cd $SRC/my-project

# 编译库
$CC $CFLAGS -c strparser.c -o strparser.o
ar rcs libstrparser.a strparser.o

# 创建一个调用库函数的fuzzer（这是关键！）
cat > $SRC/fuzzer.c << 'EOF'
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "strparser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    char *input = (char *)malloc(size + 1);
    if (!input) return 0;
    memcpy(input, data, size);
    input[size] = '\0';

    // 调用要测试的函数
    uint8_t output[256];
    size_t decoded_len;
    strparser_hex_decode(input, size, output, sizeof(output), &decoded_len);

    free(input);
    return 0;
}
EOF

# 编译fuzzer
$CC $CFLAGS -I$SRC/my-project -c $SRC/fuzzer.c -o $WORK/fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $WORK/fuzzer.o \
    $SRC/my-project/libstrparser.a -o $OUT/my_project_fuzzer

# 复制源文件用于覆盖率分析
cp $SRC/my-project/strparser.h $OUT/
cp $SRC/my-project/strparser.c $OUT/
```

### 2.5 创建project.yaml

```yaml
homepage: "https://github.com/example/my-project"
language: c
primary_contact: "your-email@example.com"
main_repo: "https://github.com/example/my-project"
fuzzing_engines:
  - libfuzzer
sanitizers:
  - address
  - undefined
```

---

## 3. 构建项目并生成FI数据

### 3.1 使用introspector sanitizer构建

```bash
cd /path/to/logicfuzz/oss-fuzz

# 构建Docker镜像
python infra/helper.py build_image my-project

# 使用introspector sanitizer构建（生成FI数据）
python infra/helper.py build_fuzzers --sanitizer introspector my-project
```

### 3.2 验证构建结果

```bash
# 检查生成的fuzzer
ls -la build/out/my-project/

# 应该看到类似文件：
# my_project_fuzzer
# fuzzerLogFile-my_project_fuzzer.data
# fuzzerLogFile-my_project_fuzzer.data.yaml
```

### 3.3 生成FI数据库

introspector构建会在 `build/out/my-project/inspector/` 目录下生成完整的FI数据，包括：
- `all-fuzz-introspector-functions.json` - 所有函数的元数据
- `source-code/` - 源代码文件副本

使用以下Python脚本将数据转换为FI webapp格式：

```bash
cd /path/to/logicfuzz/fuzz-introspector/tools/web-fuzzing-introspection/app/static/assets/db

python3 << 'EOF'
import json
import os

PROJECT = "my-project"  # 修改为你的项目名
OSS_FUZZ_DIR = "/path/to/logicfuzz/oss-fuzz"  # 修改为实际路径

# 读取introspector生成的函数数据
inspector_dir = os.path.join(OSS_FUZZ_DIR, "build", "out", PROJECT, "inspector")
functions_file = os.path.join(inspector_dir, "all-fuzz-introspector-functions.json")

with open(functions_file, 'r') as f:
    functions_data = json.load(f)

# 转换为FI webapp格式
converted = []
for func in functions_data:
    converted.append({
        "name": func.get("function_name", ""),
        "file": func.get("function_filename", ""),
        "sig": func.get("function_signature", ""),
        "cov": func.get("runtime_coverage_percent", 0.0),
        "fuzzers": func.get("reached_by_fuzzers", []),
        "cov_fuzzers": func.get("cov_fuzzers", []),
        "comb_fuzzers": func.get("comb_fuzzers", []),
        "cov_url": "",
        "icount": func.get("llvm_instruction_count", 0),
        "acc_cc": func.get("accummulated_complexity", 0),
        "u-cc": func.get("undiscovered_complexity", 0),
        "args": func.get("function_arguments", []),
        "args-names": func.get("function_argument_names", []),
        "rtn": func.get("return_type", ""),
        "raw-name": func.get("raw_function_name", ""),
        "src_begin": func.get("source_line_begin", -1),
        "src_end": func.get("source_line_end", -1),
        "debug": func.get("debug_summary", {}),
        "access": True,
        "asserts": func.get("assert_stmts", [])
    })

# 写入数据库文件
with open(f"all-functions-db-{PROJECT}.json", "w") as f:
    json.dump(converted, f, indent=2)

# 创建空的constructors数据库
with open(f"all-constructors-db-{PROJECT}.json", "w") as f:
    json.dump([], f)

print(f"Created all-functions-db-{PROJECT}.json with {len(converted)} functions")
EOF
```

---

## 4. 导入FI数据库

### 4.1 确认数据库文件

确保以下文件存在：

```
fuzz-introspector/tools/web-fuzzing-introspection/app/static/assets/db/
├── all-functions-db-my-project.json
└── all-constructors-db-my-project.json
```

### 4.2 注册项目到FI数据库

**重要**：新项目必须添加到FI的项目配置文件中，否则FI无法识别该项目。

```bash
cd /path/to/logicfuzz/fuzz-introspector/tools/web-fuzzing-introspection/app/static/assets/db

# 运行以下Python脚本添加项目
python3 << 'EOF'
import json
from datetime import date

PROJECT_NAME = "my-project"  # 修改为你的项目名

# 添加到 all-project-current.json
with open('all-project-current.json', 'r') as f:
    projects = json.load(f)

if not any(p.get('project_name') == PROJECT_NAME for p in projects):
    projects.append({
        "project_name": PROJECT_NAME,
        "date": str(date.today()),
        "language": "c",
        "coverage-data": {"coverage_url": "", "line_coverage": {"count": 0, "covered": 0, "percent": 0.0}},
        "per-fuzzer-coverage-data": {},
        "introspector-data": {
            "introspector_report_url": "",
            "coverage_lines": 0.0,
            "static_reachability": 0.0,
            "fuzzer_count": 1,
            "function_count": 0,
            "functions_covered_estimate": 0.0,
            "annotated_cfg": [],
            "optimal_targets": [],
            "project_name": PROJECT_NAME,
            "typedef_list": [],
            "macro_block": []
        },
        "fuzzer-count": 1,
        "project_repository": f"https://github.com/example/{PROJECT_NAME}",
        "light-introspector": {"test-files": [], "all-files": [], "all-pairs": []},
        "recent_results": {}
    })
    with open('all-project-current.json', 'w') as f:
        json.dump(projects, f, indent=2)
    print(f"Added {PROJECT_NAME} to all-project-current.json")

# 添加到 all-project-timestamps.json
with open('all-project-timestamps.json', 'r') as f:
    timestamps = json.load(f)

if not any(p.get('project_name') == PROJECT_NAME for p in timestamps):
    timestamps.append({
        "date": str(date.today()),
        "project_name": PROJECT_NAME,
        "language": "c",
        "coverage-data": True,
        "introspector-data": True,
        "fuzzer-count": 1,
        "introspector_url": "",
        "project_url": "",
        "project_repository": f"https://github.com/example/{PROJECT_NAME}"
    })
    with open('all-project-timestamps.json', 'w') as f:
        json.dump(timestamps, f, indent=2)
    print(f"Added {PROJECT_NAME} to all-project-timestamps.json")
EOF
```

### 4.3 启动FI本地服务（Local模式）

**关键**：必须设置 `FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ` 环境变量，指向OSS-Fuzz目录，这样FI才能读取本地构建的源代码。

```bash
cd /path/to/logicfuzz/fuzz-introspector/tools/web-fuzzing-introspection

# 如果使用虚拟环境
source .venv/bin/activate

# 设置本地模式环境变量（重要！）
export FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ=/path/to/logicfuzz/oss-fuzz

# 启动Flask应用
python3 ./app/main.py
```

服务启动后应该显示：
```
Local webapp is set
* Running on http://0.0.0.0:8080
```

**注意**：如果没有看到 "Local webapp is set"，说明环境变量没有正确设置，源代码查找功能将无法工作。

### 4.4 验证API

```bash
# 获取项目的所有函数
curl "http://localhost:8080/api/all-functions?project=my-project"

# 获取特定函数签名
curl "http://localhost:8080/api/function-signature?project=my-project&function=strparser_hex_decode"

# 测试源代码获取（关键测试）
curl "http://localhost:8080/api/function-source-code?project=my-project&function_signature=int%20strparser_hex_decode(const%20char%20*,%20size_t,%20uint8_t%20*,%20size_t,%20size_t%20*)"
```

如果服务正常运行，会返回JSON数据。如果返回 `{"msg":"No source code","result":"error"}`，说明：
1. 环境变量 `FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ` 没有正确设置
2. 或者项目没有添加到 `all-project-current.json`

---

## 5. 创建Benchmark配置

在 `conti-benchmark/` 目录下创建 `my-project.yaml`：

```yaml
"functions":
- "name": "strparser_hex_decode"
  "params":
  - "name": "input"
    "type": "const char*"
  - "name": "input_len"
    "type": "size_t"
  - "name": "output"
    "type": "uint8_t*"
  - "name": "output_size"
    "type": "size_t"
  - "name": "output_len"
    "type": "size_t*"
  "return_type": "int"
  "signature": "int strparser_hex_decode(const char*, size_t, uint8_t*, size_t, size_t*)"

"language": "c"
"project": "my-project"
"target_name": "my_project_fuzzer"
"target_path": "/src/my-project/fuzzer.c"
```

---

## 6. 运行LogicFuzz

### 6.1 设置环境变量

```bash
# 禁用OSS-Fuzz清理（防止自定义项目被删除）
export OFG_CLEAN_UP_OSS_FUZZ=0

# 设置LLM API密钥（根据使用的模型选择）
export DEEPSEEK_API_KEY=your-api-key
# 或
export OPENAI_API_KEY=your-api-key
```

### 6.2 运行LogicFuzz

```bash
cd /path/to/logicfuzz

python run_logicfuzz.py \
  -y conti-benchmark/my-project.yaml \
  --model deepseek-chat \
  -n 1 \
  --run-timeout 60 \
  -e http://localhost:8080/api \
  -of oss-fuzz
```

### 6.3 参数说明

| 参数 | 说明 |
|------|------|
| `-y` | benchmark YAML配置文件路径 |
| `--model` | LLM模型（deepseek-chat, gpt-4, claude-3等） |
| `-n` | 试验次数 |
| `--run-timeout` | fuzzer运行超时时间（秒） |
| `-e` | FuzzIntrospector API端点 |
| `-of` | OSS-Fuzz目录路径 |

### 6.4 查看结果

```bash
# 生成的fuzz target
cat results/output-my-project-strparser_hex_decode/fuzz_targets/01.fuzz_target

# 覆盖率报告
ls results/output-my-project-strparser_hex_decode/code-coverage-reports/

# 日志文件
ls results/output-my-project-strparser_hex_decode/logs/
```

---

## 7. 常见问题

### 7.1 FI API返回"No source code"

**原因**：FI无法找到源代码文件。

**解决方案**：
1. 确保启动FI时设置了 `FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ` 环境变量
2. 确保项目已添加到 `all-project-current.json` 和 `all-project-timestamps.json`
3. 重启FI服务后验证输出中显示 "Local webapp is set"
4. 检查源代码是否存在于 `oss-fuzz/build/out/my-project/inspector/source-code/` 目录

### 7.2 FI API返回"Unable to find function"

**原因**：函数没有被捕获到FI数据库中。

**解决方案**：
1. 确保build.sh中的fuzzer调用了目标函数
2. 使用introspector sanitizer重新构建
3. 检查 `all-functions-db-my-project.json` 是否正确生成

### 7.3 Docker构建失败："path not found"

**原因**：路径解析问题。

**解决方案**：
确保使用绝对路径或正确设置工作目录：
```bash
export OFG_CLEAN_UP_OSS_FUZZ=0
```

### 7.4 项目目录被删除

**原因**：OSS-Fuzz的git clean命令删除了未跟踪的文件。

**解决方案**：
```bash
export OFG_CLEAN_UP_OSS_FUZZ=0
```

### 7.5 函数签名不匹配

**原因**：YAML中的签名与FI数据库中的签名格式不同（如空格差异，例如 `char*` vs `char *`）。

**解决方案**：
LogicFuzz会自动尝试解析函数名并查询完整签名。如果仍失败，使用FI API查询正确的签名格式：
```bash
curl "http://localhost:8080/api/function-signature?project=my-project&function=strparser_hex_decode"
```

### 7.6 构建成功但覆盖率为0

**原因**：生成的fuzz target可能有问题。

**解决方案**：
1. 检查生成的fuzz target代码
2. 手动编译测试
3. 查看日志文件中的错误信息

---

## 附录：完整示例命令

```bash
# 1. 创建项目
mkdir -p oss-fuzz/projects/my-project
# ... 创建源文件、Dockerfile、build.sh、project.yaml

# 2. 构建并生成FI数据
cd oss-fuzz
python infra/helper.py build_image my-project
python infra/helper.py build_fuzzers --sanitizer introspector my-project

# 3. 注册项目到FI数据库（参见4.2节的Python脚本）
cd fuzz-introspector/tools/web-fuzzing-introspection/app/static/assets/db
# 运行添加项目的Python脚本...

# 4. 启动FI服务（另一个终端，使用Local模式）
cd fuzz-introspector/tools/web-fuzzing-introspection
export FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ=/path/to/logicfuzz/oss-fuzz
python3 ./app/main.py
# 确认输出中显示 "Local webapp is set"

# 5. 验证FI API（可选但推荐）
curl "http://localhost:8080/api/all-functions?project=my-project"

# 6. 运行LogicFuzz
cd /path/to/logicfuzz
export OFG_CLEAN_UP_OSS_FUZZ=0
export DEEPSEEK_API_KEY=your-key

python run_logicfuzz.py \
  -y conti-benchmark/my-project.yaml \
  --model deepseek-chat \
  -n 1 \
  --run-timeout 60 \
  -e http://localhost:8080/api \
  -of oss-fuzz

# 7. 查看结果
cat results/output-my-project-strparser_hex_decode/fuzz_targets/01.fuzz_target
```
