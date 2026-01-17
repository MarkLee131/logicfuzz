"""
Source code filter based on PGFilter's parameter-based filtering approach.

This module provides a unified interface for filtering source code to reduce
token usage while maintaining code structure integrity.

The filtering approach:
1. Extract parameters from a target line (e.g., crash line, function call)
2. Expand parameter set through data flow analysis
3. Filter code to keep only lines related to these parameters
"""
import os
import re
import logging
from typing import List, Tuple, Optional, Dict, Any

# Try to import tree-sitter
try:
    from tree_sitter_languages import get_parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

logger = logging.getLogger(__name__)


class SourceCodeFilter:
    """
    Filter source code to keep only parameter-related code.
    
    Based on PGFilter's approach:
    1. Extract parameters from a target line (e.g., crash line, function call)
    2. Expand parameter set through data flow analysis
    3. Filter code to keep only lines related to these parameters
    """
    
    def __init__(self, source_dir: Optional[str] = None):
        """
        Initialize the source code filter.
        
        Args:
            source_dir: Optional source code directory for file resolution
        """
        self.source_dir = source_dir
        self.parser = None
        self._init_tree_sitter()
    
    def _init_tree_sitter(self):
        """Initialize tree-sitter parser for C/C++"""
        if not TREE_SITTER_AVAILABLE:
            return
        
        try:
            # Try C parser first, fallback to C++
            try:
                self.parser = get_parser('c')
            except:
                try:
                    self.parser = get_parser('cpp')
                except:
                    self.parser = None
        except Exception as e:
            logger.debug(f"Failed to initialize tree-sitter: {e}")
            self.parser = None
    
    def filter_function_source(
        self,
        source_code: str,
        target_line: Optional[int] = None,
        target_params: Optional[List[str]] = None
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Filter function source code to keep only parameter-related code.
        
        Args:
            source_code: Complete function source code
            target_line: Optional target line number (1-based) to extract parameters from
            target_params: Optional list of target parameter names
        
        Returns:
            Tuple of (filtered_source, metadata)
            metadata contains:
            - original_line_count: Original number of lines
            - filtered_line_count: Filtered number of lines
            - reduction_ratio: Percentage of code removed
            - kept_lines: List of (line_number, reason) for kept lines
            - target_params: List of parameters used for filtering
        """
        lines = source_code.splitlines(keepends=True)
        original_count = len(lines)
        
        # Extract parameters if target_line is provided
        params = target_params or []
        if target_line and not params:
            target_idx = max(0, min(len(lines) - 1, target_line - 1))
            target_line_text = lines[target_idx].strip()
            params = self._extract_parameters_from_line(target_line_text)
        
        # Expand parameter set
        initial_params = params.copy() if params else []
        if params:
            expanded_params = self._expand_key_parameters(lines, params)
        else:
            expanded_params = []
        
        # Filter code
        target_line_relative = (target_line - 1) if target_line else len(lines) - 1
        filtered_lines_info = self._extract_relevant_code(
            lines, expanded_params, target_line_relative
        )
        
        filtered_lines = [item[0] for item in filtered_lines_info]
        filtered_source = ''.join(filtered_lines)
        
        # Calculate metadata
        filtered_count = len(filtered_lines)
        reduction_ratio = (1 - filtered_count / original_count) * 100 if original_count > 0 else 0
        
        metadata = {
            'original_line_count': original_count,
            'filtered_line_count': filtered_count,
            'reduction_ratio': reduction_ratio,
            'kept_lines': [
                (i + 1, item[2]) for i, item in enumerate(filtered_lines_info)
            ],
            'initial_params': initial_params,  # 初始提取的参数
            'expanded_params': expanded_params,  # 扩展后的参数
            'target_params': expanded_params  # 保持向后兼容
        }
        
        return filtered_source, metadata
    
    def _find_file_in_directory(self, directory: str, filename: str) -> Optional[str]:
        """Recursively search for a file in a directory"""
        if not os.path.exists(directory) or not os.path.isdir(directory):
            return None
        
        for root, dirs, files in os.walk(directory):
            if filename in files:
                return os.path.join(root, filename)
        return None
    
    def _resolve_file_path(self, file_path: str) -> Optional[str]:
        """Resolve file path using multiple strategies"""
        full_path = file_path
        
        # Try multiple path resolution strategies
        if not os.path.exists(full_path):
            if self.source_dir:
                full_path = os.path.join(self.source_dir, file_path)
            if not os.path.exists(full_path):
                full_path = os.path.join(self.source_dir, os.path.basename(file_path)) if self.source_dir else None
            if not full_path or not os.path.exists(full_path):
                full_path = self._find_file_in_directory(self.source_dir, os.path.basename(file_path)) if self.source_dir else None
        
        return full_path if (full_path and os.path.exists(full_path)) else None
    
    def filter_file_source(
        self,
        file_path: str,
        target_line: int,
        context_lines: int = 10
    ) -> Optional[Dict[str, Any]]:
        """
        Filter source code from a file at a specific line.
        
        This method mimics PGFilter's CodeAnalyzer._extract_source_context behavior.
        
        Args:
            file_path: Path to source file
            target_line: Target line number (1-based)
            context_lines: Number of context lines around target
        
        Returns:
            Dictionary with filtered source context, or None if file not found
        """
        full_path = self._resolve_file_path(file_path)
        if not full_path:
            return None
        
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
                lines = source_code.splitlines(keepends=True)
            
            target_idx = max(0, min(len(lines) - 1, target_line - 1))
            
            # Find function boundaries
            if self.parser:
                result = self._find_function_boundaries_tree_sitter(source_code, lines, target_idx)
                if result:
                    start_idx, end_idx, function_lines = result
                else:
                    start_idx, end_idx, function_lines = self._find_function_boundaries_regex(lines, target_idx)
            else:
                start_idx, end_idx, function_lines = self._find_function_boundaries_regex(lines, target_idx)
            
            # Extract parameters from target line
            target_line_text = lines[target_idx].strip()
            initial_params = self._extract_parameters_from_line(target_line_text)
            
            # Expand parameters
            if initial_params:
                expanded_params = self._expand_key_parameters(function_lines, initial_params)
            else:
                expanded_params = []
            
            # Filter code
            target_line_relative = target_idx - start_idx
            filtered_lines_info = self._extract_relevant_code(
                function_lines, expanded_params, target_line_relative
            )
            
            # Build context
            context_lines_data = []
            for i, (line, orig_idx, reason) in enumerate(filtered_lines_info):
                original_global_idx = start_idx + orig_idx
                line_num = original_global_idx + 1
                context_lines_data.append({
                    'line_number': line_num,
                    'content': line.rstrip(),
                    'is_target_line': (line_num == target_line),
                    'keep_reason': reason
                })
            
            return {
                'file': os.path.basename(file_path),
                'target_line': target_line,
                'context': context_lines_data,
                'filtered_params': expanded_params
            }
            
        except Exception as e:
            logger.debug(f"Error filtering file source {file_path}: {e}")
            return None
    
    def _find_function_boundaries_tree_sitter(
        self, source_code: str, lines: List[str], target_idx: int
    ) -> Optional[Tuple[int, int, List[str]]]:
        """Find function boundaries using tree-sitter AST parsing"""
        try:
            source_bytes = bytes(source_code, 'utf-8')
            tree = self.parser.parse(source_bytes)
            root_node = tree.root_node
            
            # Build mapping from byte offset to line number
            line_start_bytes = [0]
            current_byte = 0
            for line in lines:
                current_byte += len(line.encode('utf-8'))
                line_start_bytes.append(current_byte)
            
            crash_byte_offset = line_start_bytes[target_idx]
            
            def byte_to_line(byte_offset: int) -> int:
                left, right = 0, len(line_start_bytes) - 1
                while left < right:
                    mid = (left + right + 1) // 2
                    if line_start_bytes[mid] <= byte_offset:
                        left = mid
                    else:
                        right = mid - 1
                return left
            
            def find_containing_function(node, target_byte: int):
                if not node:
                    return None
                
                if node.start_byte <= target_byte <= node.end_byte:
                    best_match = None
                    for child in node.children:
                        result = find_containing_function(child, target_byte)
                        if result:
                            if best_match is None or (result.start_byte >= best_match.start_byte and result.end_byte <= best_match.end_byte):
                                best_match = result
                    
                    if best_match:
                        return best_match
                    
                    if node.type == 'function_definition':
                        return node
                
                return None
            
            func_node = find_containing_function(root_node, crash_byte_offset)
            
            if func_node:
                start_idx = byte_to_line(func_node.start_byte)
                end_idx = byte_to_line(func_node.end_byte - 1) if func_node.end_byte > 0 else len(lines) - 1
                
                if start_idx <= target_idx <= end_idx:
                    function_lines = lines[start_idx:end_idx + 1]
                    return (start_idx, end_idx, function_lines)
            
            return None
            
        except Exception as e:
            logger.debug(f"Tree-sitter parsing failed: {e}")
            return None
    
    def _find_function_boundaries_regex(
        self, lines: List[str], target_idx: int
    ) -> Tuple[int, int, List[str]]:
        """Find function boundaries using regex (fallback method)"""
        # Find function start
        func_decl_pattern = re.compile(r'^[\w\s\*\(\),\.]*\([\w\s\*\(\),\.]*\)\s*\{?$')
        candidates = [i for i, l in enumerate(lines[:target_idx + 1]) if func_decl_pattern.search(l)]
        start_idx = candidates[-1] if candidates else 0
        
        # Find function end using brace counting
        brace_count = 0
        found_brace = False
        end_idx = len(lines) - 1
        for i in range(start_idx, len(lines)):
            line = lines[i]
            brace_count += line.count('{')
            if line.count('{') > 0:
                found_brace = True
            brace_count -= line.count('}')
            if found_brace and brace_count == 0:
                end_idx = i
                break
        
        function_lines = lines[start_idx:end_idx + 1]
        return (start_idx, end_idx, function_lines)
    
    def _extract_parameters_from_line(self, crash_line_text: str) -> List[str]:
        """Extract key parameters from crash line"""
        def extract_params_from_call(call_str: str) -> List[str]:
            """Extract parameters from function call, handling nested parentheses"""
            open_idx = call_str.find('(')
            if open_idx == -1:
                return []
            
            depth = 0
            close_idx = -1
            for i in range(open_idx, len(call_str)):
                if call_str[i] == '(':
                    depth += 1
                elif call_str[i] == ')':
                    depth -= 1
                    if depth == 0:
                        close_idx = i
                        break
            
            if close_idx == -1:
                return []
            
            params_str = call_str[open_idx + 1:close_idx].strip()
            if not params_str:
                return []
            
            params = [p.strip() for p in params_str.split(',') if p.strip()]
            return params
        
        # Try to find function calls
        func_call_pattern = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')
        matches = func_call_pattern.finditer(crash_line_text)
        
        all_params = []
        for match in matches:
            start_pos = match.start()
            remaining = crash_line_text[start_pos:]
            params = extract_params_from_call(remaining)
            for param in params:
                vars_in_param = self._extract_variables_from_expression(param)
                all_params.extend(vars_in_param)
        
        if all_params:
            return list(set(all_params))
        
        # Try assignment pattern
        assign_pattern = re.compile(r'([\w\[\]\->\.]+)\s*([+\-*/%&|^]{0,2}=)\s*(.+);')
        m = assign_pattern.search(crash_line_text)
        if m:
            lhs = m.group(1).strip()
            rhs = m.group(3).strip()
            rhs_vars = self._extract_variables_from_expression(rhs)
            result = [lhs] + rhs_vars
            return list(set(result))
        
        # Extract variables from entire line
        all_vars = self._extract_variables_from_expression(crash_line_text)
        return all_vars
    
    def _expand_key_parameters(self, function_lines: List[str], initial_params: List[str]) -> List[str]:
        """Expand key parameters set, find other parameters related to initial parameters"""
        key_params = set(initial_params)
        expanded_once = True
        while expanded_once:
            expanded_once = False
            new_params = set()

            for line_num, line in enumerate(function_lines):
                line = line.strip()
                new_added = set()

                assign_match = re.search(r'^(.*?)\s*=\s*(.*);', line)
                if assign_match:
                    lhs_expr = assign_match.group(1).strip()
                    rhs_expr = assign_match.group(2).strip()

                    lhs_vars = self._extract_variables_from_expression(lhs_expr)
                    rhs_vars = self._extract_variables_from_expression(rhs_expr)
                    
                    if any(var in key_params for var in lhs_vars):
                        new_added.update(rhs_vars)
                    
                    if any(var in key_params for var in rhs_vars):
                        new_added.update(lhs_vars)
                
                for var in new_added:
                    if var not in key_params:
                        key_params.add(var)
                        expanded_once = True
            key_params.update(new_params)
        return list(key_params)
    
    def _extract_variables_from_expression(self, expr: str) -> List[str]:
        """Extract all variable names from expression, excluding function calls and keywords"""
        variables = []
        keywords = {'if', 'else', 'for', 'while', 'switch', 'case', 'return', 'break', 
                   'continue', 'sizeof', 'NULL', 'true', 'false', 'int', 'char', 'void',
                   'float', 'double', 'long', 'short', 'unsigned', 'signed', 'const',
                   'static', 'extern', 'inline', 'struct', 'union', 'enum', 'typedef',
                   'malloc', 'free', 'calloc', 'realloc', 'sizeof'}
        
        func_call_pattern = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')
        expr_without_funcs = func_call_pattern.sub('__FUNC_CALL__(', expr)
        
        pattern = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b')
        matches = pattern.findall(expr_without_funcs)
        
        for match in matches:
            if (match not in keywords and 
                not match.isdigit() and 
                match != '__FUNC_CALL__' and
                not match.startswith('__')):
                variables.append(match)
        
        return list(set(variables))
    
    def _extract_relevant_code(
        self, function_lines: List[str], params: List[str], crash_line_relative: int
    ) -> List[Tuple[str, int, str]]:
        """
        Extract statements directly related to key parameters and preserve minimal necessary structure.
        Only keeps code up to and including the crash line, while maintaining function structure integrity.
        
        Returns: List[tuple] Each tuple is (line_content, original_index, keep_reason)
        """
        keep_indices = set()
        keep_reasons = {}
        control_keywords = ("if", "else", "for", "while", "switch")
        
        max_line_idx = min(crash_line_relative, len(function_lines) - 1)
        
        # Find lines related to parameters (only up to crash line)
        for i in range(max_line_idx + 1):
            line = function_lines[i]
            matched_params = []
            for param in params:
                if re.search(rf'\b{re.escape(param)}\b', line):
                    matched_params.append(param)
            
            if matched_params:
                keep_indices.add(i)
                keep_reasons[i] = f"Contains parameters: {', '.join(matched_params)}"
                
                # Search upward for control structures
                j = i - 1
                while j >= 0:
                    stripped = function_lines[j].strip()
                    if any(stripped.startswith(k) for k in control_keywords):
                        if j not in keep_indices:
                            keep_indices.add(j)
                            keep_reasons[j] = "Control structure (contains parameter-related code)"
                        break
                    if "{" in stripped:
                        break
                    j -= 1
        
        # Always keep function definition line
        if 0 not in keep_indices:
            keep_indices.add(0)
            keep_reasons[0] = "Function definition line (always kept)"
        
        # Keep opening brace if needed
        func_def_line = function_lines[0].strip() if len(function_lines) > 0 else ""
        if '{' not in func_def_line and len(function_lines) > 1:
            next_line = function_lines[1].strip()
            if next_line == '{' or next_line.startswith('{'):
                if 1 not in keep_indices:
                    keep_indices.add(1)
                    keep_reasons[1] = "Function opening brace (after function definition)"
        
        # Always keep crash line if it's within function
        if crash_line_relative < len(function_lines) and crash_line_relative not in keep_indices:
            keep_indices.add(crash_line_relative)
            keep_reasons[crash_line_relative] = "Crash line (always kept)"
        
        # If no parameters, keep all lines from function start to crash line
        if not params:
            for i in range(0, max_line_idx + 1):
                if i not in keep_indices:
                    keep_indices.add(i)
                    keep_reasons[i] = "Code before crash line (no parameters)"
        
        # Handle brace balance
        sorted_indices = sorted([i for i in keep_indices if i <= max_line_idx])
        
        opened_blocks = []
        brace_depth = 0
        
        for idx in sorted_indices:
            line = function_lines[idx]
            line_braces = line.count('{') - line.count('}')
            brace_depth += line_braces
            
            if line_braces > 0:
                opened_blocks.append((idx, brace_depth - line_braces))
            
            if line_braces < 0:
                opened_blocks = [(start, depth) for start, depth in opened_blocks 
                               if brace_depth > depth]
        
        # Check each opened block
        for start_idx, start_depth in opened_blocks:
            block_brace_depth = start_depth
            found_close = False
            
            for j in range(start_idx + 1, max_line_idx + 1):
                block_brace_depth += function_lines[j].count('{') - function_lines[j].count('}')
                
                if block_brace_depth == start_depth:
                    if j not in keep_indices:
                        keep_indices.add(j)
                        keep_reasons[j] = "Maintain brace balance (close code block)"
                    found_close = True
                    break
        
        # Calculate total unclosed braces
        total_braces = 0
        for i in range(0, max_line_idx + 1):
            total_braces += function_lines[i].count('{') - function_lines[i].count('}')
        
        # Add closing braces after crash line if needed
        if total_braces > 0:
            current_brace_depth = total_braces
            closing_indices = []
            
            for j in range(max_line_idx + 1, len(function_lines)):
                line_braces = function_lines[j].count('{') - function_lines[j].count('}')
                current_brace_depth += line_braces
                
                if line_braces < 0:
                    closing_indices.append(j)
                
                if current_brace_depth == 0:
                    break
            
            for closing_idx in closing_indices[:total_braces]:
                if closing_idx not in keep_indices:
                    keep_indices.add(closing_idx)
                    keep_reasons[closing_idx] = "Maintain brace balance (close unclosed blocks)"
        
        # Construct output
        final_lines = []
        sorted_indices = sorted(keep_indices)
        
        for i in sorted_indices:
            if i <= max_line_idx:
                reason = keep_reasons.get(i, "Unknown reason")
                final_lines.append((function_lines[i], i, reason))
            elif i > max_line_idx and "Maintain brace balance" in keep_reasons.get(i, ""):
                reason = keep_reasons.get(i, "Maintain brace balance")
                if i < len(function_lines) and '}' in function_lines[i]:
                    final_lines.append((function_lines[i], i, reason))
                else:
                    final_lines.append(("}\n", i, reason))
        
        return final_lines

