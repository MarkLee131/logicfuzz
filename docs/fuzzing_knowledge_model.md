# Fuzzing Knowledge Model

## 目标

让LLM能够"简单地写对写好"fuzzing driver，通过系统化的知识建模，而不是依赖迭代优化。

## 核心洞察

从cJSON实验中，我们发现覆盖率提升的关键知识是：

1. **Parser函数需要结构化输入** - 随机字符串导致早期parse失败
2. **查找API需要命中双分支** - 空容器只能命中not-found
3. **错误路径需要malformed输入** - 只有valid输入漏掉50%代码

这些知识是**可泛化的**，但需要**项目特定的实例化**。

---

## 知识维度定义

### Dimension 1: API Semantic Role (API语义角色)

```yaml
api_roles:
  parser:
    description: "消费原始外部输入的函数"
    indicators:
      - name_patterns: [parse, read, load, decode, deserialize, from_, import]
      - param_patterns: [(const char*, size_t), (const uint8_t*, size_t), (FILE*)]
    fuzz_strategy: "直接喂fuzzer输入，需要结构化生成"
    examples: [cJSON_Parse, xml_parse, json_decode, fread]

  creator:
    description: "从参数构造新对象的函数"
    indicators:
      - name_patterns: [create, new, alloc, make, init]
      - return_type: "pointer to struct"
    fuzz_strategy: "程序化构建，参数可用fuzzer控制"
    examples: [cJSON_CreateObject, malloc, BN_new]

  accessor:
    description: "读取已有对象数据的函数"
    indicators:
      - name_patterns: [get, has, is_, find, lookup, search, query]
      - param_patterns: [(object*, key)]
    fuzz_strategy: "在已有对象上调用，需要准备多种状态"
    examples: [cJSON_GetObjectItem, cJSON_HasObjectItem, dict_get]

  mutator:
    description: "修改已有对象的函数"
    indicators:
      - name_patterns: [set, add, insert, remove, replace, update, delete]
      - param_patterns: [(object*, ...)]
    fuzz_strategy: "在已有对象上调用，可连续调用多次"
    examples: [cJSON_AddItemToObject, cJSON_ReplaceItem]

  destructor:
    description: "释放资源的函数"
    indicators:
      - name_patterns: [free, delete, destroy, release, close, cleanup]
      - return_type: void
    fuzz_strategy: "最后调用，保证资源清理"
    examples: [cJSON_Delete, free, fclose]
```

### Dimension 2: Input Format (输入格式)

```yaml
input_formats:
  structured_text:
    subtypes:
      - json: {delimiters: '{}[]:,"', escapes: '\\', nesting: true}
      - xml: {delimiters: '<>/=', escapes: '&', nesting: true}
      - yaml: {delimiters: ':-', indentation: true}
      - ini: {delimiters: '[]=', sections: true}
    generation_strategy: "构造有效结构 + 偶尔注入corruption"

  binary:
    subtypes:
      - image: {magic_bytes: required, chunks: true}
      - archive: {header: required, checksums: maybe}
      - protocol: {length_prefix: maybe, type_tags: maybe}
    generation_strategy: "种子突变 + 结构感知变异"

  free_text:
    subtypes:
      - path: {separators: '/', special: '.'}
      - url: {scheme: true, host: true, path: true, query: maybe}
      - command: {args: true, flags: true}
    generation_strategy: "模板化生成 + 随机变异"
```

### Dimension 3: Branch Coverage Patterns (分支覆盖模式)

```yaml
branch_patterns:
  lookup_branches:
    description: "查找操作有found/not-found两个分支"
    apis: [HasObjectItem, GetObjectItem, find, lookup, search]
    coverage_requirement:
      - prepare_state: "容器中预置已知key"
      - call_with: ["已知存在的key", "已知不存在的key"]
    code_pattern: |
      // 预置known key
      container["probe"] = value;
      // 命中found分支
      lookup(container, "probe");
      // 命中not-found分支
      lookup(container, "missing");

  type_check_branches:
    description: "类型检查有多个分支(每种类型一个)"
    apis: [IsArray, IsObject, IsString, IsNumber, GetType]
    coverage_requirement:
      - prepare_inputs: "准备多种类型的对象"
      - call_on_each: true
    code_pattern: |
      // 准备不同类型
      obj = CreateObject();
      arr = CreateArray();
      str = CreateString("x");
      // 分别检查
      IsArray(obj);  // false branch
      IsArray(arr);  // true branch

  error_exit_branches:
    description: "错误处理分支需要无效输入触发"
    apis: [parse_*, validate_*, check_*]
    coverage_requirement:
      - generate: "intentionally malformed input"
      - types: [truncated, missing_delimiter, invalid_encoding, overflow]
    code_pattern: |
      // 有效输入
      parse(valid_json);
      // 各种无效输入
      parse("{incomplete");  // 缺少闭合
      parse("\\u12G4");      // 无效unicode
      parse("[1 2]");        // 缺少逗号
```

### Dimension 4: Library Type Templates (库类型模板)

```yaml
library_templates:
  parser_library:
    description: "解析外部格式的库(JSON, XML, Protocol Buffers)"
    canonical_flow: "Parse → Transform → Serialize"
    api_priority:
      - 1st: "Find Parser API (Parse/Load/Read)"
      - 2nd: "Accessor APIs for traversal"
      - 3rd: "Mutator APIs for modification"
      - last: "Destructor for cleanup"
    input_strategy: "structured generation with corruption"

  compression_library:
    description: "压缩/解压库(zlib, lz4, zstd)"
    canonical_flow: "Compress → Decompress → Verify"
    api_priority:
      - 1st: "Compress/Decompress functions"
      - 2nd: "Configuration/level setters"
      - last: "Stream cleanup"
    input_strategy: "raw bytes with varied sizes"

  crypto_library:
    description: "加密/哈希库(OpenSSL, libsodium)"
    canonical_flow: "Init → Update → Finalize"
    api_priority:
      - 1st: "Hash/Encrypt/Decrypt functions"
      - 2nd: "Key generation"
      - last: "Context cleanup"
    input_strategy: "raw bytes with boundary sizes"

  image_library:
    description: "图像处理库(libpng, libjpeg, stb_image)"
    canonical_flow: "Decode → Transform → Encode"
    api_priority:
      - 1st: "Decode/Read functions"
      - 2nd: "Transformation functions"
      - 3rd: "Encode/Write functions"
    input_strategy: "seed mutation with magic bytes"
```

---

## 知识提取流程

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Project Info   │────▶│ Knowledge       │────▶│ Generation      │
│                 │     │ Extraction      │     │ Strategy        │
│ - API list      │     │                 │     │                 │
│ - Headers       │     │ 1. Classify     │     │ - Input format  │
│ - Types         │     │    API roles    │     │ - Call sequence │
│ - Docs          │     │ 2. Identify     │     │ - State setup   │
│                 │     │    input format │     │ - Error paths   │
└─────────────────┘     │ 3. Match library│     └─────────────────┘
                        │    template     │
                        │ 4. Extract      │
                        │    branch needs │
                        └─────────────────┘
```

### Step 1: API Role Classification

**输入**: API函数签名列表
**输出**: 每个API的语义角色

```python
def classify_api_role(api: APIInfo) -> str:
    # 1. 名称模式匹配
    name = api.name.lower()
    if any(p in name for p in ['parse', 'read', 'load', 'decode']):
        return 'parser'
    if any(p in name for p in ['create', 'new', 'alloc', 'make']):
        return 'creator'
    if any(p in name for p in ['get', 'has', 'is_', 'find', 'lookup']):
        return 'accessor'
    if any(p in name for p in ['set', 'add', 'insert', 'remove', 'replace']):
        return 'mutator'
    if any(p in name for p in ['free', 'delete', 'destroy', 'close']):
        return 'destructor'

    # 2. 参数模式匹配
    if has_raw_input_params(api):  # (const char*, size_t) or (const uint8_t*, size_t)
        return 'parser'

    # 3. 返回值匹配
    if api.return_type == 'void' and len(api.params) == 1:
        return 'destructor'

    # 4. LLM fallback
    return llm_classify_api(api)
```

### Step 2: Input Format Identification

**输入**: Parser API签名 + 项目描述
**输出**: 输入格式类型

```python
def identify_input_format(project: ProjectInfo, parser_apis: List[APIInfo]) -> str:
    # 1. 项目名/描述启发式
    name = project.name.lower()
    if any(x in name for x in ['json', 'cjson', 'jansson', 'rapidjson']):
        return 'json'
    if any(x in name for x in ['xml', 'expat', 'libxml']):
        return 'xml'
    if any(x in name for x in ['png', 'jpeg', 'gif', 'image']):
        return 'image'
    if any(x in name for x in ['zip', 'zlib', 'lz4', 'compress']):
        return 'binary_compressed'

    # 2. Parser API签名分析
    for api in parser_apis:
        if 'json' in api.name.lower():
            return 'json'
        if has_text_input_signature(api):  # const char*
            return 'structured_text'
        if has_binary_input_signature(api):  # const uint8_t*, size_t
            return 'binary'

    # 3. LLM fallback
    return llm_identify_format(project, parser_apis)
```

### Step 3: Branch Coverage Requirement Extraction

**输入**: Accessor/Mutator API列表
**输出**: 需要准备的状态和调用模式

```python
def extract_branch_requirements(apis: List[APIInfo]) -> List[BranchRequirement]:
    requirements = []

    for api in apis:
        name = api.name.lower()

        # Lookup APIs需要found/not-found两种状态
        if any(p in name for p in ['has', 'find', 'get', 'lookup', 'search']):
            requirements.append(BranchRequirement(
                api=api,
                type='lookup',
                states_needed=['container_with_known_key', 'key_exists', 'key_not_exists'],
                code_pattern='''
                // Pre-populate container with known key
                add_to_container(container, "probe", value);
                // Hit FOUND branch
                {api_name}(container, "probe");
                // Hit NOT-FOUND branch
                {api_name}(container, "definitely_missing");
                '''.format(api_name=api.name)
            ))

        # Type check APIs需要多种类型
        if any(p in name for p in ['is_', 'isarray', 'isobject', 'isstring']):
            requirements.append(BranchRequirement(
                api=api,
                type='type_check',
                states_needed=['object_of_each_type'],
                code_pattern='''
                // Prepare objects of different types
                // Call on each to hit all type branches
                '''
            ))

    return requirements
```

---

## 生成策略决策树

```
                        ┌─────────────────┐
                        │ Has Parser API? │
                        └────────┬────────┘
                                 │
                    ┌────────────┴────────────┐
                    │ YES                     │ NO
                    ▼                         ▼
          ┌─────────────────┐      ┌─────────────────┐
          │ What format?    │      │ Use Creator +   │
          └────────┬────────┘      │ Mutator sequence│
                   │               └─────────────────┘
      ┌────────────┼────────────┐
      │            │            │
   JSON/XML    Binary        Text
      │            │            │
      ▼            ▼            ▼
┌──────────┐ ┌──────────┐ ┌──────────┐
│Structured│ │ Seed     │ │ Template │
│Generator │ │ Mutation │ │ + Random │
└──────────┘ └──────────┘ └──────────┘
      │            │            │
      ▼            ▼            ▼
┌─────────────────────────────────────┐
│ Add corruption for error paths      │
│ Pre-populate for lookup branches    │
│ Vary types for type-check branches  │
└─────────────────────────────────────┘
```

---

## 实现路径

### Phase 1: 静态知识提取 (无LLM)

```python
class StaticKnowledgeExtractor:
    """从项目信息中提取fuzzing知识，不使用LLM"""

    def extract(self, project: ProjectInfo) -> FuzzingKnowledge:
        knowledge = FuzzingKnowledge()

        # 1. API角色分类 (启发式)
        for api in project.apis:
            knowledge.api_roles[api.name] = self._classify_role(api)

        # 2. 识别Parser APIs
        knowledge.parser_apis = [
            api for api, role in knowledge.api_roles.items()
            if role == 'parser'
        ]

        # 3. 识别输入格式 (从项目名和API名)
        knowledge.input_format = self._identify_format(project)

        # 4. 匹配库模板
        knowledge.library_template = self._match_template(project)

        # 5. 提取分支覆盖需求
        knowledge.branch_requirements = self._extract_branch_reqs(
            [api for api, role in knowledge.api_roles.items()
             if role in ['accessor', 'mutator']]
        )

        return knowledge
```

### Phase 2: LLM增强 (可选)

```python
class LLMKnowledgeEnhancer:
    """使用LLM增强和验证提取的知识"""

    def enhance(self, knowledge: FuzzingKnowledge, project: ProjectInfo) -> FuzzingKnowledge:
        # 1. 验证/修正API角色分类
        uncertain_apis = [api for api, role in knowledge.api_roles.items()
                         if role == 'unknown']
        if uncertain_apis:
            knowledge.api_roles.update(
                self._llm_classify_apis(uncertain_apis, project)
            )

        # 2. 确认输入格式
        if knowledge.input_format == 'unknown':
            knowledge.input_format = self._llm_identify_format(project)

        # 3. 生成格式特定的生成器代码
        if knowledge.input_format in ['json', 'xml', 'yaml']:
            knowledge.input_generator_code = self._llm_generate_structured_generator(
                knowledge.input_format, project
            )

        return knowledge
```

### Phase 3: 知识到策略的转换

```python
class StrategyGenerator:
    """将知识转换为具体的生成策略"""

    def generate_strategy(self, knowledge: FuzzingKnowledge) -> FuzzingStrategy:
        strategy = FuzzingStrategy()

        # 1. 输入生成策略
        if knowledge.input_format in STRUCTURED_FORMATS:
            strategy.input_generation = 'structured_generator'
            strategy.input_generator_code = knowledge.input_generator_code
        elif knowledge.input_format in BINARY_FORMATS:
            strategy.input_generation = 'seed_mutation'
        else:
            strategy.input_generation = 'random_bytes'

        # 2. API调用顺序
        strategy.call_sequence = self._determine_sequence(knowledge)

        # 3. 状态准备代码
        strategy.state_setup_code = self._generate_state_setup(
            knowledge.branch_requirements
        )

        # 4. 错误路径测试
        strategy.error_injection = self._generate_error_injection(
            knowledge.input_format
        )

        return strategy
```

---

## Prompt Template 改进

基于知识模型，新的prototyper prompt应该包含：

```
# Fuzzing Knowledge for {PROJECT_NAME}

## API Semantic Roles
{API_ROLES_TABLE}

## Input Format: {INPUT_FORMAT}
Generation Strategy: {GENERATION_STRATEGY}
{INPUT_GENERATOR_EXAMPLE}

## Branch Coverage Requirements
{BRANCH_REQUIREMENTS}

## Library Template: {LIBRARY_TYPE}
Canonical Flow: {CANONICAL_FLOW}

## Generation Checklist
- [ ] Parser APIs receive structured input (not random strings)
- [ ] Lookup APIs hit both found and not-found branches
- [ ] Type-check APIs called on multiple types
- [ ] Error paths tested with malformed input
- [ ] Resources cleaned up in reverse order
```

---

## 验证与度量

### 知识提取质量度量

```python
def evaluate_knowledge_extraction(
    extracted: FuzzingKnowledge,
    ground_truth: FuzzingKnowledge
) -> Dict[str, float]:
    return {
        'api_role_accuracy': accuracy(extracted.api_roles, ground_truth.api_roles),
        'format_accuracy': 1.0 if extracted.input_format == ground_truth.input_format else 0.0,
        'branch_coverage': coverage(extracted.branch_requirements, ground_truth.branch_requirements),
    }
```

### 生成质量度量

```python
def evaluate_generation_quality(
    generated_driver: str,
    project: ProjectInfo
) -> Dict[str, float]:
    # 编译并运行10秒
    coverage_metrics = run_fuzzer(generated_driver, timeout=10)

    return {
        'initial_coverage': coverage_metrics.line_coverage,
        'branch_coverage': coverage_metrics.branch_coverage,
        'parse_success_rate': coverage_metrics.parse_success_rate,  # 如果有parser
        'improvement_potential': estimate_improvement_potential(coverage_metrics),
    }
```

---

## 总结

**核心思想**：将"覆盖率优化迭代中学到的知识"**前置**到初始生成阶段。

**关键创新点**：
1. 定义了4个知识维度：API角色、输入格式、分支覆盖、库模板
2. 提出了静态+LLM混合的知识提取流程
3. 设计了知识到策略的转换机制

**预期效果**：
- 初始driver覆盖率从~5%提升到~30%+
- 减少优化迭代次数（从5次→1-2次）
- 提高生成driver的通用质量
