"""
Test cases for Special Pattern Analyzers

Usage:
    python -m pytest liberator_adapter/constraints/test_special_patterns.py -v
    or
    python liberator_adapter/constraints/test_special_patterns.py
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from liberator_adapter.common.api import Api, Arg
from liberator_adapter.constraints.special_patterns import (
    VarLenAnalyzer,
    LoopPatternAnalyzer,
    CallbackAnalyzer,
    TLVAnalyzer,
    SpecialPatternAnalyzer,
    LoopType,
    CallbackType,
    StructuredFormat,
)


def make_arg(name: str, type_str: str) -> Arg:
    """Helper to create Arg objects"""
    return Arg(name=name, flag="", size=0, type=type_str, is_const=[])


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


class TestVarLenAnalyzer:
    """Test S1: Var-len parameter analysis"""

    def setup_method(self):
        self.analyzer = VarLenAnalyzer()

    def test_basic_buffer_length_pair(self):
        """Test detection of basic (buffer, length) pair"""
        api = make_api("process", "void", [
            ("data", "char *"),
            ("len", "size_t"),
        ])

        result = self.analyzer.analyze(api)

        assert len(result.phase1_candidates) > 0
        assert len(result.relations) > 0
        assert result.relations[0].buffer_arg_idx == 0
        assert result.relations[0].length_arg_idx == 1

    def test_multiple_buffer_pairs(self):
        """Test detection of multiple (buffer, length) pairs"""
        api = make_api("copy", "void", [
            ("src", "const char *"),
            ("src_len", "size_t"),
            ("dst", "char *"),
            ("dst_len", "size_t"),
        ])

        result = self.analyzer.analyze(api)

        assert len(result.phase1_candidates) >= 2
        print(f"Candidates: {result.phase1_candidates}")
        print(f"Relations: {result.relations}")

    def test_no_varlen(self):
        """Test API with no var-len relationship"""
        api = make_api("get_value", "int", [
            ("ctx", "Context *"),
        ])

        result = self.analyzer.analyze(api)

        assert len(result.phase1_candidates) == 0
        assert len(result.relations) == 0

    def test_adjacent_params(self):
        """Test detection based on adjacent parameters"""
        api = make_api("write", "ssize_t", [
            ("fd", "int"),
            ("buf", "const void *"),
            ("count", "size_t"),
        ])

        result = self.analyzer.analyze(api)

        # Should detect (buf, count) pair
        assert len(result.phase1_candidates) > 0
        print(f"Candidates: {result.phase1_candidates}")


class TestLoopPatternAnalyzer:
    """Test S3: Loop pattern analysis"""

    def setup_method(self):
        self.analyzer = LoopPatternAnalyzer()

    def test_iterator_pattern(self):
        """Test detection of iterator pattern"""
        api = make_api("get_next_item", "Item *", [
            ("iter", "Iterator *"),
        ])

        result = self.analyzer.analyze(api)

        assert result.needs_loop
        assert result.loop_type == LoopType.ITERATOR
        print(f"Termination: {result.termination_condition}")

    def test_incremental_read_pattern(self):
        """Test detection of incremental read pattern"""
        api = make_api("read_chunk", "ssize_t", [
            ("ctx", "Context *"),
            ("buf", "void *"),
            ("size", "size_t"),
        ])

        result = self.analyzer.analyze(api)

        assert result.needs_loop
        assert result.loop_type == LoopType.INCREMENTAL
        print(f"Termination: {result.termination_condition}")

    def test_no_loop_needed(self):
        """Test API that doesn't need loop"""
        api = make_api("init", "int", [
            ("ctx", "Context *"),
        ])

        result = self.analyzer.analyze(api)

        assert not result.needs_loop
        assert result.loop_type == LoopType.NONE

    def test_state_machine_pattern(self):
        """Test detection of state machine pattern"""
        api = make_api("process_next", "int", [
            ("ctx", "ProcessContext *"),
        ])

        result = self.analyzer.analyze(api)

        # May or may not be detected based on heuristics
        print(f"Needs loop: {result.needs_loop}, Type: {result.loop_type}")


class TestCallbackAnalyzer:
    """Test S4: Callback analysis"""

    def setup_method(self):
        self.analyzer = CallbackAnalyzer()

    def test_comparator_callback(self):
        """Test detection of comparator callback"""
        api = make_api("sort", "void", [
            ("arr", "void *"),
            ("n", "size_t"),
            ("size", "size_t"),
            ("cmp", "int (*)(const void*, const void*)"),
        ])

        result = self.analyzer.analyze(api)

        assert len(result.callbacks) == 1
        assert result.callbacks[0].callback_type == CallbackType.COMPARATOR
        assert result.callbacks[0].stub_code != ""
        print(f"Stub code:\n{result.callbacks[0].stub_code}")

    def test_handler_callback(self):
        """Test detection of handler callback"""
        api = make_api("set_error_handler", "void", [
            ("ctx", "Context *"),
            ("handler", "error_handler_t"),
            ("user_data", "void *"),
        ])

        result = self.analyzer.analyze(api)

        assert len(result.callbacks) == 1
        assert result.callbacks[0].callback_type == CallbackType.HANDLER
        print(f"Callback type: {result.callbacks[0].callback_type}")

    def test_reader_callback(self):
        """Test detection of reader callback"""
        api = make_api("parse_with_reader", "int", [
            ("read_func", "read_callback_t"),
            ("stream", "void *"),
        ])

        result = self.analyzer.analyze(api)

        assert len(result.callbacks) == 1
        assert result.callbacks[0].callback_type == CallbackType.READER
        print(f"Stub code:\n{result.callbacks[0].stub_code}")

    def test_no_callback(self):
        """Test API with no callback"""
        api = make_api("process", "int", [
            ("data", "const char *"),
            ("len", "size_t"),
        ])

        result = self.analyzer.analyze(api)

        assert len(result.callbacks) == 0


class TestTLVAnalyzer:
    """Test S2: TLV/structured data analysis"""

    def setup_method(self):
        self.analyzer = TLVAnalyzer()

    def test_parse_function(self):
        """Test detection of parse function"""
        api = make_api("parse_message", "int", [
            ("data", "const uint8_t *"),
            ("len", "size_t"),
            ("msg", "Message *"),
        ])

        result = self.analyzer.analyze(api)

        assert result.is_structured
        print(f"Format: {result.format_type}")

    def test_decode_function(self):
        """Test detection of decode function"""
        api = make_api("decode_packet", "int", [
            ("packet", "const void *"),
            ("packet_size", "size_t"),
        ])

        result = self.analyzer.analyze(api)

        assert result.is_structured
        print(f"Format: {result.format_type}")

    def test_non_parser(self):
        """Test non-parser function"""
        api = make_api("compute_hash", "uint32_t", [
            ("data", "const void *"),
            ("len", "size_t"),
        ])

        result = self.analyzer.analyze(api)

        # May or may not be detected based on name
        print(f"Is structured: {result.is_structured}")


class TestSpecialPatternAnalyzer:
    """Test unified analyzer"""

    def setup_method(self):
        self.analyzer = SpecialPatternAnalyzer()

    def test_comprehensive_analysis(self):
        """Test comprehensive analysis of a complex API"""
        api = make_api("parse_with_callback", "int", [
            ("data", "const uint8_t *"),
            ("len", "size_t"),
            ("handler", "parse_handler_t"),
            ("user_data", "void *"),
        ])

        result = self.analyzer.analyze(api)

        print(f"API: {result.api_name}")
        print(f"Var-len relations: {result.varlen.relations if result.varlen else 'N/A'}")
        print(f"Needs loop: {result.loop.needs_loop if result.loop else 'N/A'}")
        print(f"Callbacks: {len(result.callbacks.callbacks) if result.callbacks else 0}")
        print(f"Is structured: {result.tlv.is_structured if result.tlv else 'N/A'}")

    def test_helper_methods(self):
        """Test helper methods"""
        api = make_api("read_next", "Item *", [
            ("iter", "Iterator *"),
            ("buf", "char *"),
            ("size", "size_t"),
        ])

        assert self.analyzer.needs_loop(api)
        assert len(self.analyzer.get_varlen_relations(api)) > 0

        print(f"Needs loop: {self.analyzer.needs_loop(api)}")
        print(f"Var-len relations: {self.analyzer.get_varlen_relations(api)}")


def run_all_tests():
    """Run all tests manually"""
    test_classes = [
        TestVarLenAnalyzer,
        TestLoopPatternAnalyzer,
        TestCallbackAnalyzer,
        TestTLVAnalyzer,
        TestSpecialPatternAnalyzer,
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
