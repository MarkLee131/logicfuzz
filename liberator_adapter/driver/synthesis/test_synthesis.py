"""
Test cases for Synthesis Module

Usage:
    python -m pytest liberator_adapter/driver/synthesis/test_synthesis.py -v
    or
    python liberator_adapter/driver/synthesis/test_synthesis.py
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
))))

from liberator_adapter.common.api import Api, Arg
from liberator_adapter.driver.synthesis.hole import (
    Hole, HoleKind, HolePriority, HoleSet,
    BufferSizeHole, ArrayLengthHole, InitValueHole, LoopBoundHole,
    CallbackImplHole, LoopConditionHole,
    create_buffer_size_hole, create_callback_hole,
)
from liberator_adapter.driver.synthesis.skeleton_generator import (
    SkeletonGenerator, SkeletonRenderer, DriverSkeleton,
    generate_skeleton_for_sequence, render_skeleton,
)
from liberator_adapter.driver.synthesis.constraint_collector import (
    ConstraintCollector, ConstraintSolver, collect_and_solve,
)
from liberator_adapter.driver.synthesis.hole_filler import (
    HoleFiller, RuleFillStrategy, TemplateFillStrategy,
    CallbackStubLibrary, fill_skeleton_holes,
)


# =============================================================================
# Test helpers
# =============================================================================

def make_arg(name: str, type_str: str, is_const: list = None) -> Arg:
    """Helper to create Arg objects"""
    return Arg(name=name, flag="", size=0, type=type_str, is_const=is_const or [])


def make_api(name: str, return_type: str, args: list) -> Api:
    """Helper to create Api objects"""
    return_arg = make_arg("", return_type)
    arg_objs = [make_arg(a[0], a[1]) for a in args]
    return Api(
        function_name=name,
        is_vararg=False,
        return_info=return_arg,
        arguments_info=arg_objs,
        namespace=[]
    )


# =============================================================================
# Test Hole definitions
# =============================================================================

class TestHoleDefinitions:
    """Test Hole classes"""

    def test_buffer_size_hole(self):
        """Test BufferSizeHole creation"""
        hole = create_buffer_size_hole(
            name="buf_size_1",
            buffer_idx=0,
            length_idx=1,
            relationship=">="
        )

        assert hole.kind == HoleKind.BUFFER_SIZE
        assert hole.buffer_arg_idx == 0
        assert hole.length_arg_idx == 1
        assert hole.relationship == ">="
        assert hole.is_simple
        assert not hole.is_filled

    def test_callback_hole(self):
        """Test CallbackImplHole creation"""
        hole = create_callback_hole(
            name="callback_1",
            signature="int (*)(const void*, const void*)",
            callback_type="comparator"
        )

        assert hole.kind == HoleKind.CALLBACK_IMPL
        assert hole.callback_type == "comparator"
        assert not hole.is_simple
        assert not hole.is_filled

    def test_hole_set(self):
        """Test HoleSet management"""
        hole_set = HoleSet()

        # Add holes
        hole1 = BufferSizeHole(name="buf1", buffer_arg_idx=0, length_arg_idx=1)
        hole2 = ArrayLengthHole(name="arr1")
        hole3 = CallbackImplHole(name="cb1", callback_signature="void (*)()")

        hole_set.add(hole1)
        hole_set.add(hole2)
        hole_set.add(hole3)

        assert len(hole_set) == 3
        assert len(hole_set.get_simple_holes()) == 2
        assert len(hole_set.get_complex_holes()) == 1

    def test_hole_filling(self):
        """Test filling holes"""
        hole_set = HoleSet()
        hole = ArrayLengthHole(name="arr1", max_length=1024)
        hole_set.add(hole)

        # Fill with valid value
        assert hole_set.fill("arr1", 256, "test reason")
        assert hole.is_filled
        assert hole.filled_value == 256
        assert hole.fill_reason == "test reason"

        # Check all_filled
        assert hole_set.all_filled()


# =============================================================================
# Test Skeleton Generator
# =============================================================================

class TestSkeletonGenerator:
    """Test SkeletonGenerator"""

    def setup_method(self):
        self.generator = SkeletonGenerator()

    def test_simple_api_sequence(self):
        """Test skeleton generation for simple API sequence"""
        api1 = make_api("init_context", "Context *", [])
        api2 = make_api("process", "int", [
            ("ctx", "Context *"),
            ("data", "const char *"),
            ("len", "size_t"),
        ])
        api3 = make_api("cleanup", "void", [("ctx", "Context *")])

        skeleton = self.generator.generate(
            api_sequence=[api1, api2, api3],
            driver_name="test_driver"
        )

        assert skeleton.name == "test_driver"
        assert len(skeleton.target_apis) == 3
        assert len(skeleton.statements) > 0

        print(f"Variables: {list(skeleton.variables.keys())}")
        print(f"Statements: {len(skeleton.statements)}")
        print(f"Holes: {len(skeleton.holes)}")

    def test_with_varlen_relations(self):
        """Test skeleton generation with var-len relations"""
        api = make_api("process_data", "int", [
            ("data", "const char *"),
            ("size", "size_t"),
        ])

        varlen_relations = {
            "process_data": [(0, 1, ">=")]  # data length >= size
        }

        skeleton = self.generator.generate(
            api_sequence=[api],
            varlen_relations=varlen_relations,
            driver_name="varlen_test"
        )

        # Should have a BufferSizeHole
        buffer_holes = skeleton.holes.get_by_kind(HoleKind.BUFFER_SIZE)
        print(f"Buffer size holes: {len(buffer_holes)}")

    def test_with_callback(self):
        """Test skeleton generation with callback parameter"""
        api = make_api("sort", "void", [
            ("arr", "void *"),
            ("n", "size_t"),
            ("cmp", "int (*)(const void*, const void*)"),
        ])

        skeleton = self.generator.generate(
            api_sequence=[api],
            driver_name="callback_test"
        )

        # Should have a CallbackImplHole
        callback_holes = skeleton.holes.get_by_kind(HoleKind.CALLBACK_IMPL)
        print(f"Callback holes: {len(callback_holes)}")


# =============================================================================
# Test Skeleton Renderer
# =============================================================================

class TestSkeletonRenderer:
    """Test SkeletonRenderer"""

    def test_render_simple(self):
        """Test rendering simple skeleton"""
        api = make_api("simple_func", "int", [
            ("value", "int"),
        ])

        generator = SkeletonGenerator()
        skeleton = generator.generate([api], driver_name="simple")

        renderer = SkeletonRenderer()
        code = renderer.render(skeleton)

        assert "LLVMFuzzerTestOneInput" in code
        assert "simple_func" in code

        print("Generated code:")
        print(code)

    def test_render_with_holes_marked(self):
        """Test rendering with hole markers"""
        api = make_api("callback_func", "void", [
            ("cb", "void (*)(void)"),
        ])

        generator = SkeletonGenerator()
        skeleton = generator.generate([api], driver_name="marked")

        renderer = SkeletonRenderer()
        code = renderer.render_with_holes_marked(skeleton)

        # Should contain HOLE markers
        assert "HOLE" in code or "__" in code

        print("Code with markers:")
        print(code)


# =============================================================================
# Test Constraint Collector
# =============================================================================

class TestConstraintCollector:
    """Test ConstraintCollector"""

    def test_collect_from_skeleton(self):
        """Test collecting constraints from skeleton"""
        api = make_api("process", "int", [
            ("data", "const char *"),
            ("size", "size_t"),
        ])

        generator = SkeletonGenerator()
        skeleton = generator.generate(
            [api],
            varlen_relations={"process": [(0, 1, ">=")]}
        )

        collector = ConstraintCollector()
        constraints = collector.collect_from_skeleton(skeleton)

        print(f"Collected {len(constraints.constraints)} constraints")
        for c in constraints.constraints:
            print(f"  - {c.kind.name}: {c.description}")


# =============================================================================
# Test Hole Filler
# =============================================================================

class TestHoleFiller:
    """Test HoleFiller"""

    def test_rule_fill_strategy(self):
        """Test rule-based filling"""
        strategy = RuleFillStrategy()

        # Test array length hole
        hole = ArrayLengthHole(name="arr1", max_length=1024)
        assert strategy.can_fill(hole)

        result = strategy.fill(hole, {})
        assert result.success
        assert result.method == "rule"
        assert isinstance(result.value, int)

        print(f"Filled array length: {result.value}")

    def test_template_fill_strategy(self):
        """Test template-based filling for callbacks"""
        strategy = TemplateFillStrategy()

        # Test comparator callback
        hole = CallbackImplHole(
            name="cmp1",
            callback_signature="int (*)(const void*, const void*)",
            callback_type="comparator"
        )
        assert strategy.can_fill(hole)

        result = strategy.fill(hole, {})
        assert result.success
        assert result.method == "template"
        assert "memcmp" in result.value

        print(f"Generated stub:\n{result.value}")

    def test_callback_stub_library(self):
        """Test callback stub templates"""
        # Comparator
        stub = CallbackStubLibrary.get_stub("comparator", "my_cmp")
        assert stub is not None
        assert "my_cmp" in stub
        assert "memcmp" in stub

        # Reader
        stub = CallbackStubLibrary.get_stub("reader", "my_reader")
        assert stub is not None
        assert "my_reader" in stub
        assert "memcpy" in stub

        # Allocator
        stub = CallbackStubLibrary.get_stub("allocator", "my_alloc")
        assert stub is not None
        assert "malloc" in stub

    def test_fill_all_holes(self):
        """Test filling all holes in a skeleton"""
        api = make_api("process", "int", [
            ("data", "const char *"),
            ("size", "size_t"),
        ])

        generator = SkeletonGenerator()
        skeleton = generator.generate([api])

        filler = HoleFiller()
        report = filler.fill_all(skeleton)

        print(f"Fill report:")
        print(f"  Total holes: {report.total_holes}")
        print(f"  Filled: {report.filled_count}")
        print(f"  Failed: {report.failed_count}")

        for result in report.results:
            status = "✓" if result.success else "✗"
            print(f"  {status} {result.hole_name}: {result.method} - {result.reason}")


# =============================================================================
# Integration Test
# =============================================================================

class TestIntegration:
    """Integration tests for the complete synthesis pipeline"""

    def test_full_pipeline(self):
        """Test complete pipeline: generate skeleton -> fill holes -> render"""
        # Create API sequence
        api1 = make_api("ctx_create", "Context *", [])
        api2 = make_api("ctx_process", "int", [
            ("ctx", "Context *"),
            ("data", "const uint8_t *"),
            ("len", "size_t"),
        ])
        api3 = make_api("ctx_destroy", "void", [("ctx", "Context *")])

        # Generate skeleton
        skeleton = generate_skeleton_for_sequence(
            api_sequence=[api1, api2, api3],
            varlen_relations={"ctx_process": [(1, 2, ">=")]},
            driver_name="integration_test"
        )

        print(f"Generated skeleton with {len(skeleton.holes)} holes")

        # Fill holes
        report = fill_skeleton_holes(skeleton)
        print(f"Filled {report.filled_count}/{report.total_holes} holes")

        # Render code
        code = render_skeleton(skeleton)
        print("\n=== Generated Driver Code ===")
        print(code)
        print("=== End Driver Code ===\n")

        # Verify code structure
        assert "LLVMFuzzerTestOneInput" in code
        assert "ctx_create" in code
        assert "ctx_process" in code
        assert "ctx_destroy" in code

    def test_callback_api_pipeline(self):
        """Test pipeline with callback API"""
        api = make_api("set_callback", "void", [
            ("ctx", "Context *"),
            ("handler", "error_handler"),  # typedef callback
            ("user_data", "void *"),
        ])

        skeleton = generate_skeleton_for_sequence(
            api_sequence=[api],
            callback_infos={
                "set_callback": [{
                    "arg_idx": 1,
                    "callback_type": "handler",
                    "stub_code": None,
                }]
            },
            driver_name="callback_test"
        )

        report = fill_skeleton_holes(skeleton)
        code = render_skeleton(skeleton)

        print("\n=== Callback Driver Code ===")
        print(code)
        print("=== End ===\n")


# =============================================================================
# Run tests
# =============================================================================

def run_all_tests():
    """Run all tests manually"""
    test_classes = [
        TestHoleDefinitions,
        TestSkeletonGenerator,
        TestSkeletonRenderer,
        TestConstraintCollector,
        TestHoleFiller,
        TestIntegration,
    ]

    for test_class in test_classes:
        print(f"\n{'='*60}")
        print(f"Running {test_class.__name__}")
        print('='*60)

        instance = test_class()

        for method_name in dir(instance):
            if method_name.startswith('test_'):
                print(f"\n--- {method_name} ---")
                if hasattr(instance, 'setup_method'):
                    instance.setup_method()
                try:
                    getattr(instance, method_name)()
                    print("PASSED")
                except AssertionError as e:
                    print(f"FAILED: {e}")
                except Exception as e:
                    print(f"ERROR: {e}")


if __name__ == "__main__":
    run_all_tests()
