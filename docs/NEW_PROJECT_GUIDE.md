# 新项目集成指南：OSS-Fuzz + FuzzIntrospector + LogicFuzz

本文档详细介绍如何将一个新的C/C++项目集成到OSS-Fuzz，生成FuzzIntrospector数据库，并运行LogicFuzz进行自动化fuzz target生成。

> **实测验证**：本指南已通过 `gejingquan-project` 项目完整验证，成功生成5个fuzz targets，构建成功率100%，最大覆盖率68.8%。

## 目录

1. [前提条件](#1-前提条件)
2. [创建OSS-Fuzz项目](#2-创建oss-fuzz项目)
3. [构建项目并生成FI数据](#3-构建项目并生成fi数据)
4. [导入FI数据库](#4-导入fi数据库)
5. [创建Benchmark配置](#5-创建benchmark配置)
6. [运行LogicFuzz](#6-运行logicfuzz)
7. [常见问题](#7-常见问题)
8. [完整实战案例](#8-完整实战案例)

---

## 1. 前提条件

### 1.1 环境要求

- Docker 已安装并运行
- Python 3.10+
- LogicFuzz 仓库已克隆
- Git
- LLM API 密钥（DeepSeek、OpenAI 或 Claude）

### 1.2 目录结构

```
logicfuzz/
├── oss-fuzz/                # 需要克隆完整的 OSS-Fuzz 仓库
│   ├── infra/               # OSS-Fuzz 构建基础设施（必需）
│   ├── projects/
│   │   └── your-project/    # 新项目放这里
│   └── build/out/           # 构建输出目录
├── conti-benchmark/
│   └── your-project.yaml    # benchmark配置
└── fuzz-introspector/       # 需要单独克隆
    └── tools/web-fuzzing-introspection/app/static/assets/db/
        ├── all-functions-db-your-project.json
        ├── all-constructors-db-your-project.json
        ├── all-project-current.json
        ├── all-project-timestamps.json
        └── db-timestamps.json
```

### 1.3 克隆 OSS-Fuzz（首次使用，必需）

**重要**：必须克隆完整的 OSS-Fuzz 仓库，因为需要 `infra/helper.py` 等构建工具。

```bash
cd /path/to/logicfuzz

# 如果 oss-fuzz 目录为空或只有 projects 子目录，需要重新克隆
rm -rf oss-fuzz
git clone --depth 1 https://github.com/google/oss-fuzz.git oss-fuzz

# 验证克隆成功
ls oss-fuzz/infra/helper.py  # 应该存在此文件
```

### 1.4 克隆 FuzzIntrospector（首次使用）

如果 `fuzz-introspector/` 目录为空或不存在，需要先克隆：

```bash
cd /path/to/logicfuzz
git clone https://github.com/ossf/fuzz-introspector fuzz-introspector

# 安装依赖
cd fuzz-introspector/tools/web-fuzzing-introspection
pip install -r requirements.txt
```

---

## 2. 创建OSS-Fuzz项目

本节以实际的 `gejingquan-project` 项目为例，展示如何创建一个完整的OSS-Fuzz项目。

### 2.1 创建项目目录

```bash
cd /path/to/logicfuzz
mkdir -p oss-fuzz/projects/gejingquan-project
cd oss-fuzz/projects/gejingquan-project
```

### 2.2 创建源代码文件

以 `gejingquan-project` 字符串解析库为例，该库提供了多种字符串解析功能：hex解码、URL解码、整数列表解析、字符串分割、键值对解析等。

**strparser.h**
```c
#ifndef STRPARSER_H
#define STRPARSER_H

#include <stdint.h>
#include <stddef.h>

// Token structure for split operations
typedef struct {
    const char *start;
    size_t length;
} strparser_token_t;

// Key-value pair structure
typedef struct {
    const char *key_start;
    size_t key_length;
    const char *value_start;
    size_t value_length;
} strparser_kv_t;

// Integer list structure
typedef struct {
    int *values;
    size_t count;
    size_t capacity;
} strparser_int_list_t;

// Function declarations

// Check if character is a hex digit
int is_hex_digit(char c);

// Convert hex character to integer value
int hex_to_int(char c);

// Parse a comma-separated list of integers
// Returns 0 on success, -1 on error
int strparser_parse_int_list(const char *input, size_t input_len, strparser_int_list_t *result);

// Free memory allocated for integer list
void strparser_free_int_list(strparser_int_list_t *list);

// Split string by delimiter
// Returns number of tokens found, or -1 on error
int strparser_split(const char *input, size_t input_len, char delimiter,
                    strparser_token_t *tokens, size_t max_tokens, size_t *token_count);

// Parse a single key=value pair
// Returns 0 on success, -1 on error
int strparser_parse_kv(const char *input, size_t input_len, strparser_kv_t *result);

// Parse a list of key=value pairs separated by delimiter
// Returns 0 on success, -1 on error
int strparser_parse_kv_list(const char *input, size_t input_len, char delimiter,
                            strparser_kv_t *kvs, size_t max_kvs, size_t *kv_count);

// URL decode a string
// Returns 0 on success, -1 on error
int strparser_url_decode(const char *input, size_t input_len,
                         char *output, size_t output_size, size_t *output_len);

// Hex decode a string
// Returns 0 on success, -1 on error
int strparser_hex_decode(const char *input, size_t input_len,
                         uint8_t *output, size_t output_size, size_t *output_len);

#endif // STRPARSER_H
```

**strparser.c**
```c
#include "strparser.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Check if character is a hex digit
int is_hex_digit(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

// Convert hex character to integer value
int hex_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Parse a comma-separated list of integers
int strparser_parse_int_list(const char *input, size_t input_len, strparser_int_list_t *result) {
    if (!input || !result) return -1;

    result->values = NULL;
    result->count = 0;
    result->capacity = 0;

    if (input_len == 0) return 0;

    size_t i = 0;
    while (i < input_len) {
        // Skip whitespace
        while (i < input_len && isspace((unsigned char)input[i])) i++;
        if (i >= input_len) break;

        // Check for negative sign
        int negative = 0;
        if (input[i] == '-') {
            negative = 1;
            i++;
        }

        // Parse number
        if (i >= input_len || !isdigit((unsigned char)input[i])) {
            // Invalid format
            free(result->values);
            result->values = NULL;
            result->count = 0;
            return -1;
        }

        int value = 0;
        while (i < input_len && isdigit((unsigned char)input[i])) {
            value = value * 10 + (input[i] - '0');
            i++;
        }
        if (negative) value = -value;

        // Add to result
        if (result->count >= result->capacity) {
            size_t new_capacity = result->capacity == 0 ? 8 : result->capacity * 2;
            int *new_values = realloc(result->values, new_capacity * sizeof(int));
            if (!new_values) {
                free(result->values);
                result->values = NULL;
                result->count = 0;
                return -1;
            }
            result->values = new_values;
            result->capacity = new_capacity;
        }
        result->values[result->count++] = value;

        // Skip whitespace
        while (i < input_len && isspace((unsigned char)input[i])) i++;

        // Expect comma or end
        if (i < input_len) {
            if (input[i] == ',') {
                i++;
            } else {
                // Invalid character
                free(result->values);
                result->values = NULL;
                result->count = 0;
                return -1;
            }
        }
    }

    return 0;
}

// Free memory allocated for integer list
void strparser_free_int_list(strparser_int_list_t *list) {
    if (list && list->values) {
        free(list->values);
        list->values = NULL;
        list->count = 0;
        list->capacity = 0;
    }
}

// Split string by delimiter
int strparser_split(const char *input, size_t input_len, char delimiter,
                    strparser_token_t *tokens, size_t max_tokens, size_t *token_count) {
    if (!input || !tokens || !token_count || max_tokens == 0) return -1;

    *token_count = 0;

    if (input_len == 0) {
        return 0;
    }

    size_t start = 0;
    for (size_t i = 0; i <= input_len; i++) {
        if (i == input_len || input[i] == delimiter) {
            if (*token_count >= max_tokens) {
                return -1; // Buffer too small
            }
            tokens[*token_count].start = input + start;
            tokens[*token_count].length = i - start;
            (*token_count)++;
            start = i + 1;
        }
    }

    return 0;
}

// Parse a single key=value pair
int strparser_parse_kv(const char *input, size_t input_len, strparser_kv_t *result) {
    if (!input || !result) return -1;

    result->key_start = NULL;
    result->key_length = 0;
    result->value_start = NULL;
    result->value_length = 0;

    if (input_len == 0) return -1;

    // Find the '=' character
    size_t eq_pos = 0;
    int found = 0;
    for (size_t i = 0; i < input_len; i++) {
        if (input[i] == '=') {
            eq_pos = i;
            found = 1;
            break;
        }
    }

    if (!found) return -1;

    // Extract key (trim whitespace)
    size_t key_start = 0;
    size_t key_end = eq_pos;
    while (key_start < key_end && isspace((unsigned char)input[key_start])) key_start++;
    while (key_end > key_start && isspace((unsigned char)input[key_end - 1])) key_end--;

    // Extract value (trim whitespace)
    size_t value_start = eq_pos + 1;
    size_t value_end = input_len;
    while (value_start < value_end && isspace((unsigned char)input[value_start])) value_start++;
    while (value_end > value_start && isspace((unsigned char)input[value_end - 1])) value_end--;

    result->key_start = input + key_start;
    result->key_length = key_end - key_start;
    result->value_start = input + value_start;
    result->value_length = value_end - value_start;

    return 0;
}

// Parse a list of key=value pairs separated by delimiter
int strparser_parse_kv_list(const char *input, size_t input_len, char delimiter,
                            strparser_kv_t *kvs, size_t max_kvs, size_t *kv_count) {
    if (!input || !kvs || !kv_count || max_kvs == 0) return -1;

    *kv_count = 0;

    if (input_len == 0) return 0;

    // First split by delimiter
    strparser_token_t *tokens = malloc(max_kvs * sizeof(strparser_token_t));
    if (!tokens) return -1;

    size_t token_count;
    if (strparser_split(input, input_len, delimiter, tokens, max_kvs, &token_count) != 0) {
        free(tokens);
        return -1;
    }

    // Parse each token as key=value
    for (size_t i = 0; i < token_count; i++) {
        if (*kv_count >= max_kvs) {
            free(tokens);
            return -1;
        }
        if (strparser_parse_kv(tokens[i].start, tokens[i].length, &kvs[*kv_count]) == 0) {
            (*kv_count)++;
        }
    }

    free(tokens);
    return 0;
}

// URL decode a string
int strparser_url_decode(const char *input, size_t input_len,
                         char *output, size_t output_size, size_t *output_len) {
    if (!input || !output || !output_len || output_size == 0) return -1;

    *output_len = 0;

    for (size_t i = 0; i < input_len; i++) {
        if (*output_len >= output_size - 1) return -1; // Buffer too small

        if (input[i] == '%' && i + 2 < input_len &&
            is_hex_digit(input[i + 1]) && is_hex_digit(input[i + 2])) {
            // Decode hex sequence
            int high = hex_to_int(input[i + 1]);
            int low = hex_to_int(input[i + 2]);
            output[*output_len] = (char)((high << 4) | low);
            (*output_len)++;
            i += 2;
        } else if (input[i] == '+') {
            // '+' represents space
            output[*output_len] = ' ';
            (*output_len)++;
        } else {
            output[*output_len] = input[i];
            (*output_len)++;
        }
    }

    output[*output_len] = '\0';
    return 0;
}

// Hex decode a string
int strparser_hex_decode(const char *input, size_t input_len,
                         uint8_t *output, size_t output_size, size_t *output_len) {
    if (!input || !output || !output_len) return -1;

    *output_len = 0;

    // Input length must be even for valid hex
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

RUN apt-get update && apt-get install -y \
    make \
    gcc \
    libjpeg-dev \
    zlib1g-dev \
    libyaml-dev

COPY strparser.h strparser.c $SRC/gejingquan-project/
WORKDIR $SRC/gejingquan-project
COPY build.sh $SRC/
```

### 2.4 创建build.sh

**重要**：build.sh必须创建一个调用库函数的fuzzer，否则FuzzIntrospector无法捕获函数信息。

```bash
#!/bin/bash -eu

cd $SRC/gejingquan-project

# Compile the library
$CC $CFLAGS -c strparser.c -o strparser.o
ar rcs libstrparser.a strparser.o

# Create fuzzer source that calls library functions
cat > $SRC/fuzzer.c << 'EOF'
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "strparser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    // Create null-terminated string
    char *input = (char *)malloc(size + 1);
    if (!input) return 0;
    memcpy(input, data, size);
    input[size] = '\0';

    // Test hex decode
    uint8_t hex_output[256];
    size_t hex_decoded_len;
    strparser_hex_decode(input, size, hex_output, sizeof(hex_output), &hex_decoded_len);

    // Test URL decode
    char url_output[512];
    size_t url_decoded_len;
    strparser_url_decode(input, size, url_output, sizeof(url_output), &url_decoded_len);

    // Test integer list parsing
    strparser_int_list_t int_list;
    if (strparser_parse_int_list(input, size, &int_list) == 0) {
        strparser_free_int_list(&int_list);
    }

    // Test split
    strparser_token_t tokens[32];
    size_t token_count;
    strparser_split(input, size, ',', tokens, 32, &token_count);

    // Test key-value parsing
    strparser_kv_t kv;
    strparser_parse_kv(input, size, &kv);

    // Test key-value list parsing
    strparser_kv_t kvs[16];
    size_t kv_count;
    strparser_parse_kv_list(input, size, '&', kvs, 16, &kv_count);

    free(input);
    return 0;
}
EOF

# Compile fuzzer
$CC $CFLAGS -I$SRC/gejingquan-project -c $SRC/fuzzer.c -o $WORK/fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $WORK/fuzzer.o \
    $SRC/gejingquan-project/libstrparser.a -o $OUT/gejingquan_project_fuzzer

# Copy source files for coverage
cp $SRC/gejingquan-project/strparser.h $OUT/
cp $SRC/gejingquan-project/strparser.c $OUT/
```

**注意**：创建后需要添加执行权限：
```bash
chmod +x build.sh
```

#### 2.4.1 理解桩 Fuzzer（fuzzer.c）的作用

build.sh 中创建的 `fuzzer.c` 是一个**桩 Fuzzer（Stub Fuzzer）**，它有两个关键作用：

**1. 让 FuzzIntrospector 捕获函数信息（必需）**

FuzzIntrospector 通过分析 fuzzer 的调用关系来发现库中的函数。如果没有一个 fuzzer 调用库函数，FuzzIntrospector 就**无法捕获**这些函数的信息。

桩 fuzzer 必须调用所有需要被 LogicFuzz 分析的目标函数，如上例中：
```c
// 在 fuzzer.c 中调用所有目标函数
strparser_hex_decode(...);
strparser_url_decode(...);
strparser_parse_int_list(...);
strparser_split(...);
strparser_parse_kv(...);
strparser_parse_kv_list(...);
```

这样 FuzzIntrospector 在使用 `--sanitizer introspector` 构建时，就能捕获到这些函数的签名、参数类型、源代码位置等信息，并生成 `all-fuzz-introspector-functions.json` 数据库。

**2. 提供基础的 fuzzing 能力**

这个 fuzzer 也是一个可以实际运行的 libFuzzer target，它会：
- 接收随机输入数据 (`data`, `size`)
- 将数据传递给各个库函数进行测试
- 可以发现库中的崩溃和漏洞

**桩 Fuzzer vs LogicFuzz 生成的 Fuzz Target**

| 特性 | fuzzer.c (桩 Fuzzer) | LogicFuzz 生成的 Fuzz Target |
|------|---------------------|------------------------------|
| **目的** | 让 FI 捕获函数信息 | 针对特定函数深度测试 |
| **输入构造** | 简单（直接传递原始数据） | 智能（使用 FuzzedDataProvider） |
| **参数处理** | 固定缓冲区大小 | 动态分配，边界检查 |
| **覆盖函数** | 一个 fuzzer 覆盖所有函数 | 每个函数一个专门的 fuzzer |
| **代码质量** | 手写，较简单 | LLM 生成，考虑前置条件 |

> **重要**：`fuzzer.c` 是 FuzzIntrospector 数据收集的**必要条件**，没有它就无法生成函数数据库，LogicFuzz 也就无法工作。

### 2.5 创建project.yaml

```yaml
homepage: "https://github.com/gejingquan/gejingquan-project"
language: c
primary_contact: "gejingquan@example.com"
main_repo: "https://github.com/gejingquan/gejingquan-project"
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

# 构建Docker镜像（输入 'n' 跳过拉取基础镜像）
echo "n" | python infra/helper.py build_image gejingquan-project

# 使用introspector sanitizer构建（生成FI数据）
python infra/helper.py build_fuzzers --sanitizer introspector gejingquan-project
```

### 3.2 验证构建结果

```bash
# 检查生成的fuzzer和inspector数据
ls -la build/out/gejingquan-project/
ls -la build/out/gejingquan-project/inspector/

# 应该看到类似文件：
# build/out/gejingquan-project/
#   gejingquan_project_fuzzer
#   strparser.c
#   strparser.h
# build/out/gejingquan-project/inspector/
#   all-fuzz-introspector-functions.json
#   source-code/
```

### 3.3 验证捕获的函数

```bash
# 查看捕获的函数
cat build/out/gejingquan-project/inspector/all-fuzz-introspector-functions.json | python3 -m json.tool | head -50
```

---

## 4. 导入FI数据库

### 4.1 创建数据库目录

```bash
mkdir -p fuzz-introspector/tools/web-fuzzing-introspection/app/static/assets/db
cd fuzz-introspector/tools/web-fuzzing-introspection/app/static/assets/db
```

### 4.2 转换FI数据为webapp格式

```bash
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

# 转换为FI webapp格式（注意：字段名与原始数据不同）
converted = []
for func in functions_data:
    converted.append({
        "name": func.get("Func name", ""),
        "file": func.get("Functions filename", ""),
        "sig": func.get("function_signature", ""),
        "cov": 0.0,
        "fuzzers": func.get("Reached by Fuzzers", []),
        "cov_fuzzers": func.get("Runtime reached by Fuzzers", []),
        "comb_fuzzers": func.get("Combined reached by Fuzzers", []),
        "cov_url": "",
        "icount": func.get("I Count", 0),
        "acc_cc": func.get("Accumulated cyclomatic complexity", 0),
        "u-cc": func.get("Undiscovered complexity", 0),
        "args": func.get("Args", []),
        "args-names": func.get("ArgNames", []),
        "rtn": func.get("return_type", ""),
        "raw-name": func.get("raw-function-name", ""),
        "src_begin": func.get("source_line_begin", -1),
        "src_end": func.get("source_line_end", -1),
        "debug": func.get("debug_function_info", {}),
        "access": func.get("is_accessible", True),
        "asserts": func.get("asserts", [])
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

### 4.3 注册项目到FI数据库

**重要**：新项目必须添加到FI的项目配置文件中，否则FI无法识别该项目。

```bash
python3 << 'EOF'
import json
import os
from datetime import date

PROJECT_NAME = "my-project"  # 修改为你的项目名
FUNCTION_COUNT = 3  # 修改为实际函数数量

def load_or_create(filename, default_content):
    """加载文件或创建新文件"""
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)
    return default_content

# 添加到 all-project-current.json
projects = load_or_create('all-project-current.json', [])

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
            "function_count": FUNCTION_COUNT,
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
else:
    print(f"{PROJECT_NAME} already exists in all-project-current.json")

# 添加到 all-project-timestamps.json
timestamps = load_or_create('all-project-timestamps.json', [])

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
else:
    print(f"{PROJECT_NAME} already exists in all-project-timestamps.json")

print("Done!")
EOF
```

### 4.4 创建db-timestamps.json（必需）

**重要**：FI webapp 需要此文件才能启动。

```bash
cat > db-timestamps.json << 'EOF'
[
  {
    "date": "2026-01-27",
    "project_count": 1,
    "fuzzer_count": 1,
    "function_count": 3,
    "function_coverage_estimate": 0.0,
    "accummulated_lines_total": 100,
    "accummulated_lines_covered": 0
  }
]
EOF
```

### 4.5 启动FI本地服务

**关键**：必须设置 `FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ` 环境变量，指向OSS-Fuzz目录，这样FI才能读取本地构建的源代码。

```bash
cd /path/to/logicfuzz/fuzz-introspector/tools/web-fuzzing-introspection/app

# 设置本地模式环境变量（重要！）
export FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ=/path/to/logicfuzz/oss-fuzz

# 启动Flask应用（前台运行）
python3 main.py

# 或者后台运行
nohup python3 main.py > /tmp/fi_server.log 2>&1 &
```

服务启动后应该显示：
```
Local webapp is set
Loading db
 * Running on http://0.0.0.0:8080
```

**注意**：如果没有看到 "Local webapp is set"，说明环境变量没有正确设置，源代码查找功能将无法工作。

### 4.6 验证API

```bash
# 获取项目的所有函数
curl -s "http://localhost:8080/api/all-functions?project=my-project" | python3 -m json.tool | head -30

# 获取特定函数签名
curl -s "http://localhost:8080/api/function-signature?project=my-project&function=strparser_hex_decode" | python3 -m json.tool

# 测试源代码获取（关键测试）
curl -s "http://localhost:8080/api/function-source-code?project=my-project&function_signature=int%20strparser_hex_decode(const%20char%20*,%20size_t,%20uint8_t%20*,%20size_t,%20size_t%20*)" | python3 -m json.tool
```

如果服务正常运行，会返回JSON数据。如果返回 `{"msg":"No source code","result":"error"}`，说明：
1. 环境变量 `FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ` 没有正确设置
2. 或者项目没有添加到 `all-project-current.json`

---

## 5. 创建Benchmark配置

在 `conti-benchmark/` 目录下创建 `my-project.yaml`：

**重要**：`signature` 字段中的类型必须使用空格分隔（如 `const char *` 而不是 `const char*`），需要与FI API返回的签名格式一致。

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
  "signature": "int strparser_hex_decode(const char *, size_t, uint8_t *, size_t, size_t *)"

"language": "c"
"project": "my-project"
"target_name": "my_project_fuzzer"
"target_path": "/src/my-project/fuzzer.c"
```

**提示**：可以通过FI API获取正确的签名格式：
```bash
curl -s "http://localhost:8080/api/function-signature?project=my-project&function=strparser_hex_decode" | python3 -c "import sys,json; print(json.load(sys.stdin)['signature'])"
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
| `--model` | LLM模型（deepseek-chat, gpt-4o, claude-3-5-sonnet等） |
| `-n` | 试验次数 |
| `--run-timeout` | fuzzer运行超时时间（秒） |
| `-e` | FuzzIntrospector API端点 |
| `-of` | OSS-Fuzz目录路径 |
| `--enable-source-filter` | 启用源代码过滤 |
| `--source-filter-min-lines` | 源代码最小行数过滤阈值 |

### 6.4 运行示例

```bash
# 带源代码过滤的完整命令
python run_logicfuzz.py \
  -y conti-benchmark/my-project.yaml \
  --model deepseek-chat \
  -n 1 \
  --run-timeout 60 \
  -e http://localhost:8080/api \
  -of oss-fuzz \
  --enable-source-filter \
  --source-filter-min-lines 50
```

### 6.5 查看结果

```bash
# 生成的fuzz target
cat results/output-my-project-strparser_hex_decode/fuzz_targets/01.fuzz_target

# 覆盖率报告
ls results/output-my-project-strparser_hex_decode/code-coverage-reports/

# 日志文件
ls results/output-my-project-strparser_hex_decode/logs/

# benchmark配置
cat results/output-my-project-strparser_hex_decode/benchmark.yaml
```

### 6.6 预期输出

成功运行后，日志末尾应显示类似：
```
**** FINAL RESULTS: ****

================================================================================
*my-project, int strparser_hex_decode(const char *, size_t, uint8_t *, size_t, size_t *)*
build success rate: 1.0, crash rate: 0.0, found bug: 0, max coverage: 0.6880733944954128, max line coverage diff: 0.9086021505376344

**** TOTAL COVERAGE GAIN: ****
*my-project: 0.9941176470588236
```

**关键指标说明**：
| 指标 | 说明 | 理想值 |
|------|------|--------|
| build success rate | 构建成功率 | 1.0 (100%) |
| crash rate | 崩溃率 | 0.0 (0%) |
| max coverage | 最大代码覆盖率 | > 0.5 |
| max line coverage diff | 最大行覆盖率增量 | > 0.8 |
| TOTAL COVERAGE GAIN | 总覆盖率增益 | > 0.9 |

---

## 7. 常见问题

### 7.1 FI服务启动失败：FileNotFoundError db-timestamps.json

**原因**：缺少 `db-timestamps.json` 文件。

**解决方案**：
创建 `db-timestamps.json` 文件（参见4.4节）。

### 7.2 FI API返回"No source code"

**原因**：FI无法找到源代码文件。

**解决方案**：
1. 确保启动FI时设置了 `FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ` 环境变量
2. 确保项目已添加到 `all-project-current.json` 和 `all-project-timestamps.json`
3. 重启FI服务后验证输出中显示 "Local webapp is set"
4. 检查源代码是否存在于 `oss-fuzz/build/out/my-project/inspector/source-code/` 目录

### 7.3 FI API返回"Unable to find function"

**原因**：函数没有被捕获到FI数据库中。

**解决方案**：
1. 确保build.sh中的fuzzer调用了目标函数
2. 使用introspector sanitizer重新构建
3. 检查 `all-functions-db-my-project.json` 是否正确生成

### 7.4 Docker构建时提示输入

**原因**：`build_image` 命令会询问是否拉取最新基础镜像。

**解决方案**：
```bash
echo "n" | python infra/helper.py build_image my-project
```

### 7.5 项目目录被删除

**原因**：OSS-Fuzz的git clean命令删除了未跟踪的文件。

**解决方案**：
```bash
export OFG_CLEAN_UP_OSS_FUZZ=0
```

### 7.6 函数签名不匹配

**原因**：YAML中的签名与FI数据库中的签名格式不同（如空格差异，例如 `char*` vs `char *`）。

**解决方案**：
LogicFuzz会自动尝试解析函数名并查询完整签名。如果仍失败，使用FI API查询正确的签名格式：
```bash
curl "http://localhost:8080/api/function-signature?project=my-project&function=strparser_hex_decode"
```

### 7.7 构建成功但覆盖率为0

**原因**：生成的fuzz target可能有问题。

**解决方案**：
1. 检查生成的fuzz target代码
2. 手动编译测试
3. 查看日志文件中的错误信息

### 7.8 OSS-Fuzz 缺少 infra/helper.py

**原因**：`oss-fuzz` 目录不完整，只有 `projects` 子目录。

**解决方案**：
```bash
cd /path/to/logicfuzz
rm -rf oss-fuzz
git clone --depth 1 https://github.com/google/oss-fuzz.git oss-fuzz
```

### 7.9 LLM API 认证失败

**原因**：API 密钥无效或未设置。

**解决方案**：
```bash
# 检查环境变量
echo $DEEPSEEK_API_KEY

# 重新设置（确保密钥正确）
export DEEPSEEK_API_KEY=sk-your-valid-api-key

# 或使用 OpenAI
export OPENAI_API_KEY=sk-your-openai-key
```

### 7.10 FI 服务连接被拒绝

**原因**：FI 服务未启动或已停止。

**解决方案**：
```bash
# 检查服务是否运行
curl -s "http://localhost:8080/api/all-functions?project=my-project"

# 如果连接被拒绝，重新启动服务
cd /path/to/logicfuzz/fuzz-introspector/tools/web-fuzzing-introspection/app
export FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ=/path/to/logicfuzz/oss-fuzz
nohup python3 main.py > /tmp/fi_server.log 2>&1 &

# 等待服务启动
sleep 5
```

---

## 8. 完整实战案例

以下是 `gejingquan-project` 项目从0到1的完整实战记录。

### 8.1 项目概述

- **项目名称**：gejingquan-project
- **语言**：C
- **功能**：字符串解析库（hex解码、URL解码、整数列表解析、字符串分割、键值对解析）
- **目标函数**：5个

### 8.2 执行步骤

```bash
# ============================================================
# 步骤1：克隆 OSS-Fuzz（如果目录不完整）
# ============================================================
cd /path/to/logicfuzz
git clone --depth 1 https://github.com/google/oss-fuzz.git oss-fuzz

# ============================================================
# 步骤2：创建项目目录和源文件
# ============================================================
mkdir -p oss-fuzz/projects/gejingquan-project

# 创建源文件：strparser.h, strparser.c, Dockerfile, build.sh, project.yaml
# （参考第2节的内容）

chmod +x oss-fuzz/projects/gejingquan-project/build.sh

# ============================================================
# 步骤3：构建 Docker 镜像
# ============================================================
cd oss-fuzz
echo "n" | python3 infra/helper.py build_image gejingquan-project

# ============================================================
# 步骤4：使用 introspector sanitizer 构建
# ============================================================
python3 infra/helper.py build_fuzzers --sanitizer introspector gejingquan-project

# 验证构建结果
ls build/out/gejingquan-project/inspector/all-fuzz-introspector-functions.json

# ============================================================
# 步骤5：设置 FI 数据库
# ============================================================
cd /path/to/logicfuzz/fuzz-introspector/tools/web-fuzzing-introspection/app/static/assets/db

# 转换 FI 数据（使用4.2节的脚本，PROJECT="gejingquan-project"）
# 注册项目（使用4.3节的脚本）
# 创建 db-timestamps.json（使用4.4节的命令）

# ============================================================
# 步骤6：启动 FI 服务
# ============================================================
cd /path/to/logicfuzz/fuzz-introspector/tools/web-fuzzing-introspection/app
export FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ=/path/to/logicfuzz/oss-fuzz
nohup python3 main.py > /tmp/fi_server.log 2>&1 &

# 验证服务启动
sleep 5
curl -s "http://localhost:8080/api/all-functions?project=gejingquan-project" | head -c 200

# ============================================================
# 步骤7：创建 Benchmark 配置
# ============================================================
# 创建 conti-benchmark/gejingquan-project.yaml（参考第5节）

# ============================================================
# 步骤8：运行 LogicFuzz
# ============================================================
cd /path/to/logicfuzz
export OFG_CLEAN_UP_OSS_FUZZ=0
export DEEPSEEK_API_KEY=sk-your-api-key

python run_logicfuzz.py \
  -y conti-benchmark/gejingquan-project.yaml \
  --model deepseek-chat \
  -n 1 \
  --run-timeout 60 \
  -e http://localhost:8080/api \
  -of oss-fuzz
```

### 8.3 实际运行结果

```
**** FINAL RESULTS: ****

================================================================================
*gejingquan-project, int strparser_hex_decode(...)*
build success rate: 1.0, crash rate: 0.0, found bug: 0, max coverage: 0.6880733944954128

================================================================================
*gejingquan-project, int strparser_url_decode(...)*
build success rate: 1.0, crash rate: 0.0, found bug: 0, max coverage: 0.6880733944954128

================================================================================
*gejingquan-project, int strparser_parse_int_list(...)*
build success rate: 1.0, crash rate: 0.0, found bug: 0, max coverage: 0.6880733944954128

================================================================================
*gejingquan-project, int strparser_split(...)*
build success rate: 1.0, crash rate: 0.0, found bug: 0, max coverage: 0.6880733944954128

================================================================================
*gejingquan-project, int strparser_parse_kv(...)*
build success rate: 1.0, crash rate: 0.0, found bug: 0, max coverage: 0.6880733944954128

**** TOTAL COVERAGE GAIN: ****
*gejingquan-project: 0.9941176470588236
```

### 8.4 生成的文件

```
results/
├── output-gejingquan-project-strparser_hex_decode/
│   ├── fuzz_targets/
│   │   └── 01.fuzz_target          # 生成的 fuzz target
│   ├── code-coverage-reports/
│   │   └── 01.fuzz_target          # 覆盖率报告
│   ├── logs/                        # 日志文件
│   └── benchmark.yaml               # benchmark 配置
├── output-gejingquan-project-strparser_url_decode/
├── output-gejingquan-project-strparser_parse_int_list/
├── output-gejingquan-project-strparser_split/
├── output-gejingquan-project-strparser_parse_kv/
└── report.json                      # 汇总报告
```

---

## 附录A：完整示例命令

```bash
# ============================================================
# 1. 创建项目
# ============================================================
mkdir -p oss-fuzz/projects/my-project
cd oss-fuzz/projects/my-project
# 创建 strparser.h, strparser.c, Dockerfile, build.sh, project.yaml
chmod +x build.sh

# ============================================================
# 2. 构建并生成FI数据
# ============================================================
cd /path/to/logicfuzz/oss-fuzz
echo "n" | python infra/helper.py build_image my-project
python infra/helper.py build_fuzzers --sanitizer introspector my-project

# 验证构建结果
ls build/out/my-project/inspector/all-fuzz-introspector-functions.json

# ============================================================
# 3. 设置FI数据库（如果fuzz-introspector目录为空，先克隆）
# ============================================================
cd /path/to/logicfuzz
# git clone https://github.com/ossf/fuzz-introspector fuzz-introspector
# pip install -r fuzz-introspector/tools/web-fuzzing-introspection/requirements.txt

cd fuzz-introspector/tools/web-fuzzing-introspection/app/static/assets/db
# 运行4.2节的Python脚本转换数据
# 运行4.3节的Python脚本注册项目
# 运行4.4节的命令创建db-timestamps.json

# ============================================================
# 4. 启动FI服务（新终端）
# ============================================================
cd /path/to/logicfuzz/fuzz-introspector/tools/web-fuzzing-introspection/app
export FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ=/path/to/logicfuzz/oss-fuzz
python3 main.py
# 确认输出中显示 "Local webapp is set"

# ============================================================
# 5. 验证FI API
# ============================================================
curl -s "http://localhost:8080/api/all-functions?project=my-project" | python3 -m json.tool | head -20

# ============================================================
# 6. 创建Benchmark配置
# ============================================================
cd /path/to/logicfuzz
# 创建 conti-benchmark/my-project.yaml

# ============================================================
# 7. 运行LogicFuzz
# ============================================================
export OFG_CLEAN_UP_OSS_FUZZ=0
export DEEPSEEK_API_KEY=your-key

python run_logicfuzz.py \
  -y conti-benchmark/my-project.yaml \
  --model deepseek-chat \
  -n 1 \
  --run-timeout 60 \
  -e http://localhost:8080/api \
  -of oss-fuzz

# ============================================================
# 8. 查看结果
# ============================================================
cat results/output-my-project-strparser_hex_decode/fuzz_targets/01.fuzz_target
```

---

## 附录B：生成的Fuzz Target示例

以下是 LogicFuzz 为 `gejingquan-project` 实际生成的 fuzz target 示例：

### strparser_hex_decode

```cpp
#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "strparser.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Construct input string - hex decode expects hex characters
  std::string input_str = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());
  size_t input_len = input_str.length();

  // PRE-1: Input pointer must be valid or NULL
  const char* input_ptr = input_str.c_str();
  if (input_len == 0) {
    input_ptr = NULL;
  }

  // Allocate output buffer - capacity should be at least half input length
  size_t output_capacity = (input_len / 2) + 1;
  uint8_t* output_buf = NULL;

  // PRE-2: Output buffer pointer must be valid if capacity > 0
  if (output_capacity > 0) {
    output_buf = (uint8_t*)malloc(output_capacity);
    if (!output_buf) {
      return 0;
    }
  }

  size_t bytes_written = 0;

  // Call the target function
  int result = strparser_hex_decode(input_ptr, input_len, output_buf, output_capacity, &bytes_written);

  // Cleanup
  if (output_buf) {
    free(output_buf);
  }

  return 0;
}
```

### strparser_parse_kv

```cpp
#include <stddef.h>
#include <stdint.h>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "strparser.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) return 0;

  FuzzedDataProvider fdp(data, size);

  // Split input: first half for string, second half for potential other fuzzing
  size_t str_len = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
  std::string input_str = fdp.ConsumeBytesAsString(str_len);

  // Initialize the key-value struct
  strparser_kv_t kv = {0};

  // Call the target function
  int ret = strparser_parse_kv(input_str.c_str(), input_str.length(), &kv);

  return 0;
}
```

### strparser_split

```cpp
#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <vector>

extern "C" {
#include "strparser.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);

  // Construct input string
  std::string input_str = fdp.ConsumeRandomLengthString(4096);
  const char* input = input_str.c_str();
  size_t input_len = input_str.length();

  // Construct delimiter
  char delimiter = fdp.ConsumeIntegral<char>();

  // Construct max_tokens with reasonable bounds
  size_t max_tokens = fdp.ConsumeIntegralInRange<size_t>(0, 1024);

  // Allocate tokens array if max_tokens > 0
  std::vector<strparser_token_t> tokens_vec;
  strparser_token_t* tokens = nullptr;

  if (max_tokens > 0) {
    tokens_vec.resize(max_tokens);
    tokens = tokens_vec.data();
  }

  // Output parameter
  size_t tokens_written = 0;
  size_t* tokens_written_ptr = &tokens_written;

  // Call the target function
  int result = strparser_split(input, input_len, delimiter, tokens,
                               max_tokens, tokens_written_ptr);

  return 0;
}
```

---

## 附录C：Benchmark YAML 配置示例

以下是 `gejingquan-project` 的完整 benchmark 配置：

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
  "signature": "int strparser_hex_decode(const char *, size_t, uint8_t *, size_t, size_t *)"

- "name": "strparser_url_decode"
  "params":
  - "name": "input"
    "type": "const char*"
  - "name": "input_len"
    "type": "size_t"
  - "name": "output"
    "type": "char*"
  - "name": "output_size"
    "type": "size_t"
  - "name": "output_len"
    "type": "size_t*"
  "return_type": "int"
  "signature": "int strparser_url_decode(const char *, size_t, char *, size_t, size_t *)"

- "name": "strparser_parse_int_list"
  "params":
  - "name": "input"
    "type": "const char*"
  - "name": "input_len"
    "type": "size_t"
  - "name": "result"
    "type": "strparser_int_list_t*"
  "return_type": "int"
  "signature": "int strparser_parse_int_list(const char *, size_t, strparser_int_list_t *)"

- "name": "strparser_split"
  "params":
  - "name": "input"
    "type": "const char*"
  - "name": "input_len"
    "type": "size_t"
  - "name": "delimiter"
    "type": "char"
  - "name": "tokens"
    "type": "strparser_token_t*"
  - "name": "max_tokens"
    "type": "size_t"
  - "name": "token_count"
    "type": "size_t*"
  "return_type": "int"
  "signature": "int strparser_split(const char *, size_t, char, strparser_token_t *, size_t, size_t *)"

- "name": "strparser_parse_kv"
  "params":
  - "name": "input"
    "type": "const char*"
  - "name": "input_len"
    "type": "size_t"
  - "name": "result"
    "type": "strparser_kv_t*"
  "return_type": "int"
  "signature": "int strparser_parse_kv(const char *, size_t, strparser_kv_t *)"

"language": "c"
"project": "gejingquan-project"
"target_name": "gejingquan_project_fuzzer"
"target_path": "/src/gejingquan-project/fuzzer.c"
```
