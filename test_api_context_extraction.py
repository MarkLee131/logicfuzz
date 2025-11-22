#!/usr/bin/env python3
"""
测试 API Context 提取功能

从正常的 workflow 输入（yaml 文件）开始，测试是否能正确提取 target API 需要的 context。

测试用例：conti-benchmark/conti-cmp/curl.yaml
"""

import sys
import json
import logging
from pathlib import Path
from typing import Dict, List

# 添加项目根目录到路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from experiment.benchmark import Benchmark
from agent_graph.api_context_extractor import APIContextExtractor

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def print_section(title: str, char: str = "="):
    """打印分节标题"""
    print(f"\n{char * 80}")
    print(f"{title}")
    print(f"{char * 80}")


def print_dict(data: Dict, indent: int = 0):
    """格式化打印字典"""
    prefix = "  " * indent
    for key, value in data.items():
        if isinstance(value, dict):
            print(f"{prefix}{key}:")
            print_dict(value, indent + 1)
        elif isinstance(value, list):
            print(f"{prefix}{key}: [{len(value)} items]")
            if value and isinstance(value[0], dict):
                for i, item in enumerate(value[:3]):  # 只显示前3个
                    print(f"{prefix}  [{i}]:")
                    print_dict(item, indent + 2)
                if len(value) > 3:
                    print(f"{prefix}  ... ({len(value) - 3} more items)")
            elif value:
                for i, item in enumerate(value[:5]):  # 只显示前5个
                    print(f"{prefix}  - {item}")
                if len(value) > 5:
                    print(f"{prefix}  ... ({len(value) - 5} more items)")
        else:
            # 截断过长的字符串
            str_value = str(value)
            if len(str_value) > 100:
                str_value = str_value[:100] + "..."
            print(f"{prefix}{key}: {str_value}")


def test_api_context_extraction(yaml_path: str):
    """
    测试 API context 提取功能
    
    Args:
        yaml_path: YAML 配置文件路径
    """
    print_section("API Context Extraction Test")
    print(f"YAML file: {yaml_path}")
    
    # Step 1: 加载 Benchmark
    print_section("Step 1: Loading Benchmark from YAML", "-")
    try:
        benchmarks = Benchmark.from_yaml(yaml_path)
        if not benchmarks:
            logger.error("No benchmarks loaded from YAML file")
            return False
        
        benchmark = benchmarks[0]
        logger.info(f"✅ Loaded benchmark: {benchmark.id}")
        logger.info(f"   Project: {benchmark.project}")
        logger.info(f"   Function: {benchmark.function_name}")
        logger.info(f"   Signature: {benchmark.function_signature}")
        logger.info(f"   Language: {benchmark.language}")
        
        print(f"\nBenchmark details:")
        print(f"  ID: {benchmark.id}")
        print(f"  Project: {benchmark.project}")
        print(f"  Function Name: {benchmark.function_name}")
        print(f"  Function Signature: {benchmark.function_signature}")
        print(f"  Return Type: {benchmark.return_type}")
        print(f"  Parameters: {len(benchmark.params)}")
        for i, param in enumerate(benchmark.params):
            print(f"    [{i}] {param.get('name', 'unknown')}: {param.get('type', 'unknown')}")
        
    except Exception as e:
        logger.error(f"❌ Failed to load benchmark: {e}", exc_info=True)
        return False
    
    # Step 2: 提取 API Context
    print_section("Step 2: Extracting API Context", "-")
    try:
        extractor = APIContextExtractor(benchmark.project)
        logger.info(f"✅ Created APIContextExtractor for project: {benchmark.project}")
        
        # 提取 context
        logger.info(f"Extracting context for: {benchmark.function_signature}")
        api_context = extractor.extract(benchmark.function_signature)
        
        if not api_context:
            logger.error("❌ API context extraction returned None or empty")
            return False
        
        logger.info("✅ API context extracted successfully")
        
    except Exception as e:
        logger.error(f"❌ Failed to extract API context: {e}", exc_info=True)
        return False
    
    # Step 3: 验证和显示 Context 内容
    print_section("Step 3: API Context Content", "-")
    
    # 检查关键字段
    required_fields = [
        'parameters',
        'return_type',
        'type_definitions',
        'usage_examples',
        'initialization_patterns',
        'related_functions'
    ]
    
    print("\n📊 Context Summary:")
    for field in required_fields:
        value = api_context.get(field)
        if isinstance(value, list):
            count = len(value)
            status = "✅" if count > 0 else "⚠️"
            print(f"  {status} {field}: {count} items")
        elif isinstance(value, dict):
            count = len(value)
            status = "✅" if count > 0 else "⚠️"
            print(f"  {status} {field}: {count} entries")
        else:
            status = "✅" if value else "⚠️"
            print(f"  {status} {field}: {value}")
    
    # 详细显示各个部分
    print_section("Detailed Context Information", "-")
    
    # Parameters
    print("\n📋 Parameters:")
    params = api_context.get('parameters', [])
    if params:
        for i, param in enumerate(params):
            print(f"  [{i}] {param.get('name', 'unknown')}: {param.get('type', 'unknown')}")
            if 'description' in param:
                print(f"      Description: {param['description']}")
    else:
        print("  ⚠️  No parameters extracted")
    
    # Return Type
    print(f"\n📤 Return Type: {api_context.get('return_type', 'unknown')}")
    
    # Type Definitions
    print(f"\n📚 Type Definitions: {len(api_context.get('type_definitions', {}))} types")
    type_defs = api_context.get('type_definitions', {})
    if type_defs:
        for i, (type_name, type_info) in enumerate(list(type_defs.items())[:5]):
            print(f"  [{i}] {type_name}")
            if isinstance(type_info, dict):
                if 'definition' in type_info:
                    def_str = str(type_info['definition'])
                    if len(def_str) > 80:
                        def_str = def_str[:80] + "..."
                    print(f"      Definition: {def_str}")
        if len(type_defs) > 5:
            print(f"  ... ({len(type_defs) - 5} more types)")
    
    # Usage Examples
    print(f"\n💡 Usage Examples: {len(api_context.get('usage_examples', []))} examples")
    examples = api_context.get('usage_examples', [])
    if examples:
        for i, example in enumerate(examples[:3]):
            print(f"  [{i}]")
            example_str = str(example)
            if len(example_str) > 200:
                example_str = example_str[:200] + "..."
            # 按行显示，每行缩进
            for line in example_str.split('\n'):
                print(f"      {line}")
        if len(examples) > 3:
            print(f"  ... ({len(examples) - 3} more examples)")
    else:
        print("  ⚠️  No usage examples found")
    
    # Initialization Patterns
    print(f"\n🔧 Initialization Patterns: {len(api_context.get('initialization_patterns', []))} patterns")
    init_patterns = api_context.get('initialization_patterns', [])
    if init_patterns:
        for i, pattern in enumerate(init_patterns[:3]):
            print(f"  [{i}] {pattern}")
        if len(init_patterns) > 3:
            print(f"  ... ({len(init_patterns) - 3} more patterns)")
    else:
        print("  ⚠️  No initialization patterns found")
    
    # Related Functions
    print(f"\n🔗 Related Functions: {len(api_context.get('related_functions', []))} functions")
    related_funcs = api_context.get('related_functions', [])
    if related_funcs:
        for i, func in enumerate(related_funcs[:5]):
            func_name = func.get('name', 'unknown') if isinstance(func, dict) else str(func)
            print(f"  [{i}] {func_name}")
        if len(related_funcs) > 5:
            print(f"  ... ({len(related_funcs) - 5} more functions)")
    else:
        print("  ⚠️  No related functions found")
    
    # Side Effects (if available)
    side_effects = api_context.get('side_effects', {})
    if side_effects:
        print(f"\n⚡ Side Effects: {len(side_effects)} identified")
        for key, value in list(side_effects.items())[:3]:
            print(f"  - {key}: {value}")
    
    # Step 4: 验证 Context 有效性
    print_section("Step 4: Context Validation", "-")
    
    # 必需字段（关键信息）
    required_fields = {
        'has_parameters': len(api_context.get('parameters', [])) > 0,
        'has_return_type': bool(api_context.get('return_type')),
    }
    
    # 可选字段（增强信息，但不是必需的）
    optional_fields = {
        'has_type_definitions': len(api_context.get('type_definitions', {})) > 0,
        'has_usage_examples': len(api_context.get('usage_examples', [])) > 0,
        'has_initialization_patterns': len(api_context.get('initialization_patterns', [])) > 0,
        'has_related_functions': len(api_context.get('related_functions', [])) > 0,
    }
    
    print("\n✅ Required Fields (Critical):")
    all_required_passed = True
    for check, passed in required_fields.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {status}: {check}")
        if not passed:
            all_required_passed = False
    
    print("\n📊 Optional Fields (Enhancement):")
    for check, passed in optional_fields.items():
        status = "✅ YES" if passed else "⚠️  NO"
        print(f"  {status}: {check}")
    
    # 关键检查：至少要有参数或返回类型
    all_passed = all_required_passed
    if not all_passed:
        logger.error("❌ CRITICAL: Required fields are missing!")
    
    # Step 5: 保存完整 Context 到 JSON（可选）
    print_section("Step 5: Saving Context to JSON", "-")
    output_file = f"api_context_{benchmark.project}_{benchmark.function_name}.json"
    try:
        with open(output_file, 'w') as f:
            json.dump(api_context, f, indent=2, default=str)
        logger.info(f"✅ Saved full context to: {output_file}")
        print(f"  Output file: {output_file}")
    except Exception as e:
        logger.warning(f"⚠️  Failed to save context to JSON: {e}")
    
    # 最终总结
    print_section("Test Summary", "=")
    if all_passed:
        print("✅ API Context extraction test PASSED")
        print(f"\n   Successfully extracted context for: {benchmark.function_signature}")
        print(f"   Context contains:")
        print(f"     - {len(api_context.get('parameters', []))} parameters")
        print(f"     - {len(api_context.get('type_definitions', {}))} type definitions")
        print(f"     - {len(api_context.get('usage_examples', []))} usage examples")
        print(f"     - {len(api_context.get('initialization_patterns', []))} initialization patterns")
        print(f"     - {len(api_context.get('related_functions', []))} related functions")
        print(f"\n   ✅ All required fields are present")
        print(f"   📊 Optional fields: {sum(optional_fields.values())}/{len(optional_fields)} available")
        return True
    else:
        print("❌ API Context extraction test FAILED")
        print("   Some required fields are missing or empty")
        print("   Required fields:")
        for check, passed in required_fields.items():
            status = "✅" if passed else "❌"
            print(f"     {status} {check}")
        return False


def main():
    """主函数"""
    # 默认使用 curl.yaml
    yaml_path = "conti-benchmark/conti-cmp/curl.yaml"
    
    if len(sys.argv) > 1:
        yaml_path = sys.argv[1]
    
    # 检查文件是否存在
    if not Path(yaml_path).exists():
        logger.error(f"YAML file not found: {yaml_path}")
        logger.info("Usage: python test_api_context_extraction.py [yaml_path]")
        sys.exit(1)
    
    # 运行测试
    success = test_api_context_extraction(yaml_path)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

