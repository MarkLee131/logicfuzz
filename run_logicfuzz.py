#!/usr/bin/env python3
"""Run an experiment with all function-under-tests."""

import argparse
import json
import logging
import os
import re
import sys
import time
import traceback
from pathlib import Path

from dotenv import load_dotenv

# Load environment variables from logicfuzz.env
_env_file = Path(__file__).parent / "logicfuzz.env"
if _env_file.exists():
    load_dotenv(_env_file)
else:
    print(f"Warning: {_env_file} not found. API keys may not be configured.")
from datetime import timedelta
from multiprocessing import Pool, Process
from typing import Any

import run_single_fuzz
from data_prep import introspector
from experiment import benchmark as benchmarklib
from experiment import evaluator, oss_fuzz_checkout, textcov
from experiment.workdir import WorkDirs
from src.llm import models
from dataclasses import dataclass
from pathlib import Path
import subprocess
import tempfile
from typing import Optional, List

# Liberator-related helpers (used to perform local Clang extraction)
from liberator_adapter.extractors.clang_extractor import ClangAPIExtractor
from liberator_adapter.extractors.llvm_extractor import LLVMAPIExtractor
from liberator_adapter.dependency.type.TypeDependencyGraphGenerator import TypeDependencyGraphGenerator
from liberator_adapter.common.api import Api, Arg
from liberator_adapter.common.utils import Utils
from liberator_adapter.common.datalayout import DataLayout
from liberator_adapter.constraints.ConditionManager import ConditionManager
from liberator_adapter.common import FunctionConditionsSet
from liberator_adapter.driver.factory import Factory
from liberator_adapter.project_driver_generator import ProjectDriverGenerator
from liberator_adapter.dependency import DependencyGraph

logger = logging.getLogger(__name__)

logger.setLevel(logging.WARNING)

# WARN: Avoid large NUM_EXP for local experiments.
# NUM_EXP controls the number of experiments in parallel, while each experiment
# will evaluate {run_single_fuzz.NUM_EVA, default 3} fuzz targets in
# parallel.
NUM_EXP = int(os.getenv('LLM_NUM_EXP', '10'))

# Default LLM hyper-parameters.
MAX_TOKENS: int = run_single_fuzz.MAX_TOKENS
NUM_SAMPLES: int = run_single_fuzz.NUM_SAMPLES
RUN_TIMEOUT: int = run_single_fuzz.RUN_TIMEOUT
TEMPERATURE: float = run_single_fuzz.TEMPERATURE

RESULTS_DIR: str = run_single_fuzz.RESULTS_DIR
JSON_REPORT = 'report.json'
TIME_STAMP_FMT = '%Y-%m-%d %H:%M:%S'

WORK_DIR = ''

LOG_LEVELS = ['debug', 'info', 'error']
LOG_FMT = ('%(asctime)s.%(msecs)03d %(levelname)s '
           '%(module)s - %(funcName)s: %(message)s')

class Result:
  benchmark: benchmarklib.Benchmark
  result: run_single_fuzz.AggregatedResult | str

  def __init__(self, benchmark, result):
    self.benchmark = benchmark
    self.result = result

def generate_benchmarks(args: argparse.Namespace) -> None:
  """Generates benchmarks, write to filesystem and set args benchmark dir."""
  logger.info('Generating benchmarks.')
  benchmark_dir = introspector.get_next_generated_benchmarks_dir()
  logger.info('Setting benchmark directory to %s.', benchmark_dir)
  os.makedirs(benchmark_dir)
  args.benchmarks_directory = benchmark_dir
  benchmark_oracles = [
      heuristic.strip() for heuristic in args.generate_benchmarks.split(',')
  ]
  projects_to_target = [
      project.strip()
      for project in args.generate_benchmarks_projects.split(',')
  ]
  for project in projects_to_target:
    project_lang = oss_fuzz_checkout.get_project_language(project)
    benchmarks = introspector.populate_benchmarks_using_introspector(
        project, project_lang, args.generate_benchmarks_max, benchmark_oracles)
    if benchmarks:
      benchmarklib.Benchmark.to_yaml(benchmarks, outdir=benchmark_dir)

def prepare_experiment_targets(
    args: argparse.Namespace) -> list[benchmarklib.Benchmark]:
  """Constructs a list of experiment configs based on the |BENCHMARK_DIR| and
    |args| setting."""
  benchmark_yamls = []
  if args.benchmark_yaml:
    logger.info(
        'A benchmark yaml file %s is provided. Will use it and ignore '
        'the files in %s.', args.benchmark_yaml, args.benchmarks_directory)
    benchmark_yamls = [args.benchmark_yaml]
  else:
    if args.generate_benchmarks:
      generate_benchmarks(args)

    benchmark_yamls = [
        os.path.join(args.benchmarks_directory, file)
        for file in os.listdir(args.benchmarks_directory)
        if file.endswith('.yaml') or file.endswith('yml')
    ]
  experiment_configs = []
  for benchmark_file in benchmark_yamls:
    experiment_configs.extend(benchmarklib.Benchmark.from_yaml(benchmark_file))

  return experiment_configs


#
# Lightweight local shim to reuse the existing Clang extractor without Docker.
# This preserves extractor expectations (execute/compile/write_to_file/terminate).
#
@dataclass
class LocalProjectTool:
  benchmark: benchmarklib.Benchmark
  project_dir: str

  def __post_init__(self):
    self.container_id = 'local'
    self.project_dir = os.path.abspath(self.project_dir)

  def execute(self, command: str) -> subprocess.CompletedProcess:
    """Run |command| locally in the project directory."""
    proc = subprocess.run(command, shell=True, cwd=self.project_dir,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc

  def compile(self) -> subprocess.CompletedProcess:
    """Run the project's build.sh if present."""
    build_sh = os.path.join(self.project_dir, 'build.sh')
    if os.path.isfile(build_sh) and os.access(build_sh, os.X_OK):
      return self.execute(f'{build_sh}')
    elif os.path.isfile(build_sh):
      return self.execute(f'bash {build_sh}')
    return subprocess.CompletedProcess(args='compile', returncode=0, stdout='no build.sh', stderr='')

  def write_to_file(self, content: str, file_path: str) -> None:
    path = file_path if os.path.isabs(file_path) else os.path.join(self.project_dir, file_path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
      f.write(content)

  def terminate(self) -> None:
    return


def guess_language_from_tree(project_dir: str) -> str:
  """Heuristic: count .c vs .cpp/.cc files to infer language."""
  c_count = 0
  cpp_count = 0
  for root, _, files in os.walk(project_dir):
    for f in files:
      if f.endswith('.c'):
        c_count += 1
      if f.endswith(('.cpp', '.cc', '.cxx', '.c++', '.hpp', '.h')):
        cpp_count += 1
  return 'c' if c_count > cpp_count else 'c++'


def clone_repo(repo: str, outdir: str, commit: Optional[str] = None) -> str:
  outdir = os.path.abspath(outdir)
  if os.path.exists(outdir):
    logger.info('Using existing directory %s', outdir)
  else:
    logger.info('Cloning %s -> %s', repo, outdir)
    subprocess.run(['git', 'clone', repo, outdir], check=True)
  if commit:
    subprocess.run(['git', 'fetch'], cwd=outdir, check=True)
    subprocess.run(['git', 'checkout', commit], cwd=outdir, check=True)
  return outdir


def _infer_flag_from_type(type_str: str, is_return: bool = False) -> str:
  """Infer the flag from the type string.

  - If type contains '*' or '[]', it's a pointer -> 'ref' (or 'ret' for returns)
  - If type contains '(*)', it's a function pointer -> 'fun'
  - Otherwise -> 'val'
  """
  if '(*)' in type_str:
    return 'fun'
  elif '*' in type_str or '[' in type_str:
    return 'ret' if is_return else 'ref'
  else:
    return 'val'


def convert_apis_clang_json_to_api_list(apis_clang_path: str) -> List[Api]:
  """Read a Clang JSON lines file and convert to Api objects."""
  apis: List[Api] = []
  with open(apis_clang_path) as f:
    for line in f:
      line = line.strip()
      if not line or line.startswith('#'):
        continue
      obj = json.loads(line)
      fname = obj.get('function_name')
      is_vararg = obj.get('is_vararg', False)
      ret_json = obj.get('return_info', {'name': 'return', 'flag': 'val', 'size': 0, 'type_clang': 'void', 'const': [False]})
      # Handle const field: could be a list [bool, bool] or a single bool
      const_field = ret_json.get('const', [False])
      if isinstance(const_field, list):
        const_list = const_field
      else:
        const_list = [const_field]

      # Infer flag from type if not provided
      ret_type = ret_json.get('type_clang', ret_json.get('type', 'void'))
      ret_flag = ret_json.get('flag', _infer_flag_from_type(ret_type, is_return=True))

      return_arg = Arg(ret_json.get('name', 'return'),
                       ret_flag,
                       ret_json.get('size', 0),
                       ret_type,
                       const_list)

      args_list = []
      for a in obj.get('arguments_info', []):
        # Handle const field: could be a list [bool, bool] or a single bool
        const_field = a.get('const', [False])
        if isinstance(const_field, list):
          const_list = const_field
        else:
          const_list = [const_field]

        # Infer flag from type if not provided
        arg_type = a.get('type_clang', a.get('type', 'void'))
        arg_flag = a.get('flag', _infer_flag_from_type(arg_type, is_return=False))

        arg = Arg(a.get('name', ''), arg_flag, a.get('size', 0),
                  arg_type, const_list)
        args_list.append(arg)

      namespace = obj.get('namespace', [])
      apis.append(Api(fname, is_vararg, return_arg, args_list, namespace))
  return apis


def find_entry_points(dep_graph: dict) -> tuple[set, set]:
  """Find entry points (APIs with no dependencies) in the dependency graph.
  
  The graph format is: {api_a: [api_b1, api_b2, ...]}
  meaning api_a can use outputs from api_b1, api_b2, ... (api_a depends on them).
  
  Entry points are APIs that don't depend on any other API's output.
  
  Returns:
    tuple: (entry_points, all_apis)
      - entry_points: set of APIs that don't depend on other APIs
      - all_apis: set of all APIs in the graph
  """
  # Collect all APIs mentioned in the graph
  apis_as_keys = set(dep_graph.keys())  # APIs that have dependencies
  apis_as_values = set()  # APIs that are depended upon
  for deps in dep_graph.values():
    apis_as_values.update(deps)
  
  all_apis = apis_as_keys | apis_as_values
  
  # Entry points are APIs that are not keys (don't depend on others)
  # OR are keys but have empty dependency lists
  entry_points = set()
  for api in all_apis:
    if api not in apis_as_keys:
      # This API doesn't depend on any other API
      entry_points.add(api)
    elif len(dep_graph.get(api, [])) == 0:
      # This API is in the graph but has no dependencies
      entry_points.add(api)
  
  return entry_points, all_apis


def visualize_dependency_graph(project: str, dep_graph: dict, output_dir: str, 
                                entry_points: set = None) -> str:
  """Visualize the dependency graph using graphviz or networkx+matplotlib.
  
  Args:
    project: Project name
    dep_graph: Dependency graph {api: [dependencies]}
    output_dir: Directory to save the visualization
    entry_points: Set of entry point APIs (highlighted in green)
  
  Returns:
    Path to the generated graph image
  """
  if not dep_graph:
    logger.info('Empty graph, skipping visualization')
    return ''
  
  # Collect all APIs
  all_apis = set(dep_graph.keys())
  for deps in dep_graph.values():
    all_apis.update(deps)
  
  if entry_points is None:
    entry_points, _ = find_entry_points(dep_graph)
  
  output_path = os.path.join(output_dir, f'{project}_dependency_graph')
  
  # First try graphviz (produces nicer output)
  try:
    from graphviz import Digraph
    
    dot = Digraph(name=f'{project}_dependency_graph', format='png')
    dot.attr(rankdir='TB', size='30,30', dpi='100')
    dot.attr('node', shape='box', fontname='Helvetica', fontsize='9')
    dot.attr('edge', fontsize='7', color='#888888', arrowsize='0.5')
    
    # Add nodes with different colors
    for api in sorted(all_apis):
      if api in entry_points:
        # Entry points in green
        dot.node(api, api, style='filled', fillcolor='#90EE90', 
                 color='#228B22', penwidth='2')
      elif api in dep_graph:
        # APIs with dependencies in light blue
        dot.node(api, api, style='filled', fillcolor='#ADD8E6',
                 color='#4682B4')
      else:
        # APIs without outgoing edges in light gray
        dot.node(api, api, style='filled', fillcolor='#D3D3D3',
                 color='#696969')
    
    # Add edges (api_a -> api_b means api_a depends on api_b)
    for api_a, deps in dep_graph.items():
      for api_b in deps:
        dot.edge(api_a, api_b)
    
    # Try to render as PNG
    try:
      dot.render(output_path, cleanup=True)
      logger.info('Dependency graph visualization saved to %s.png', output_path)
      return f'{output_path}.png'
    except Exception as e:
      # Graphviz executable not found, save DOT file
      dot_path = f'{output_path}.dot'
      dot.save(dot_path)
      logger.info('Graphviz not installed. Saved graph as DOT file: %s', dot_path)
      logger.info('To render: dot -Tpng %s -o %s.png', dot_path, output_path)
      
  except ImportError:
    logger.info('graphviz package not available')
  
  # Fallback: try networkx + matplotlib
  try:
    import networkx as nx
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    
    G = nx.DiGraph()
    G.add_nodes_from(all_apis)
    for api_a, deps in dep_graph.items():
      for api_b in deps:
        G.add_edge(api_a, api_b)
    
    # Create figure
    plt.figure(figsize=(20, 16))
    
    # Use spring layout for positioning
    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)
    
    # Color nodes based on type
    node_colors = []
    for node in G.nodes():
      if node in entry_points:
        node_colors.append('#90EE90')  # Green for entry points
      elif node in dep_graph:
        node_colors.append('#ADD8E6')  # Light blue for APIs with deps
      else:
        node_colors.append('#D3D3D3')  # Gray for others
    
    # Draw the graph
    nx.draw(G, pos, 
            node_color=node_colors,
            node_size=800,
            font_size=7,
            font_weight='bold',
            with_labels=True,
            arrows=True,
            arrowsize=10,
            edge_color='#888888',
            alpha=0.9)
    
    plt.title(f'{project} Type Dependency Graph\n'
              f'Green = Entry Points ({len(entry_points)}), '
              f'Blue = APIs with deps, Gray = Others',
              fontsize=12)
    
    png_path = f'{output_path}.png'
    plt.savefig(png_path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    logger.info('Dependency graph visualization saved to %s', png_path)
    return png_path
    
  except ImportError as e:
    logger.warning('Neither graphviz nor matplotlib available for visualization: %s', e)
  except Exception as e:
    logger.warning('Failed to create visualization with matplotlib: %s', e)
  
  return ''


def setup_condition_manager(
    api_list: List[Api],
    function_conditions: FunctionConditionsSet,
    apis_clang_path: str,
    apis_llvm_path: str,
    data_layout_path: str,
    incomplete_types_path: str = None,
    enum_types_path: str = None
) -> ConditionManager:
  """
  Setup DataLayout and ConditionManager for type-aware analysis.

  Args:
    api_list: List of Api objects
    function_conditions: FunctionConditionsSet from conditions.json
    apis_clang_path: Path to apis_clang.json
    apis_llvm_path: Path to apis_llvm.json
    data_layout_path: Path to data_layout.txt
    incomplete_types_path: Path to incomplete_types.txt (optional)
    enum_types_path: Path to enum_types.txt (optional)

  Returns:
    Configured ConditionManager instance
  """
  # Setup DataLayout first (required by ConditionManager)
  data_layout = DataLayout.instance()

  # Create empty files if not provided
  if incomplete_types_path is None or not os.path.exists(incomplete_types_path):
    incomplete_types_path = os.path.join(os.path.dirname(apis_clang_path), 'incomplete_types.txt')
    if not os.path.exists(incomplete_types_path):
      with open(incomplete_types_path, 'w') as f:
        pass  # Create empty file

  if enum_types_path is None or not os.path.exists(enum_types_path):
    enum_types_path = os.path.join(os.path.dirname(apis_clang_path), 'enum_types.txt')
    if not os.path.exists(enum_types_path):
      with open(enum_types_path, 'w') as f:
        pass  # Create empty file

  try:
    data_layout.setup(
      apis_clang_p=apis_clang_path,
      apis_llvm_p=apis_llvm_path,
      incomplete_types_p=incomplete_types_path,
      data_layout_p=data_layout_path,
      enum_types_p=enum_types_path
    )
    logger.info('DataLayout setup complete')
  except Exception as e:
    logger.warning('Failed to setup DataLayout: %s', e)

  # Setup ConditionManager
  # Filter api_list to only include APIs that have conditions
  available_conditions = set(function_conditions.fun_cond_set.keys())
  api_set_filtered = {api for api in api_list if api.function_name in available_conditions}

  if len(api_set_filtered) < len(api_list):
    logger.info('Filtered %d APIs without conditions (keeping %d)',
                len(api_list) - len(api_set_filtered), len(api_set_filtered))

  condition_manager = ConditionManager.instance()
  condition_manager.setup(
    api_list=api_set_filtered,
    api_list_all=api_set_filtered,
    conditions=function_conditions
  )

  logger.info('ConditionManager setup complete:')
  logger.info('  - Source APIs: %d', len(condition_manager.get_source_api()))
  logger.info('  - Sink APIs: %d', len(condition_manager.get_sink_api()))
  logger.info('  - Init APIs: %d', len(condition_manager.get_init_api()))

  return condition_manager


def generate_type_aware_sequences(
    api_list: List[Api],
    condition_manager: ConditionManager,
    dep_graph_api: dict,  # {Api: [Api, ...]}
    max_sequences: int = 100,
    max_length: int = 5
) -> tuple[list, dict]:
  """
  Generate API sequences using type-aware source/sink classification.

  Uses ConditionManager to:
  - Find SOURCE APIs (create resources) per type
  - Find SINK APIs (destroy resources) per type
  - Find INIT/SET APIs per type
  - Generate sequences that respect type relationships

  Args:
    api_list: List of all Api objects
    condition_manager: Configured ConditionManager instance
    dep_graph_api: Dependency graph with Api objects as keys/values
    max_sequences: Maximum number of sequences to generate
    max_length: Maximum length of each sequence

  Returns:
    Tuple of (sequences, classification_stats)
  """
  if not api_list or not condition_manager:
    return ([], {})

  # Get type-aware classification from ConditionManager
  source_apis = condition_manager.get_source_api()
  sink_apis = condition_manager.get_sink_api()
  init_apis = condition_manager.get_init_api()

  # Build name -> Api mapping for easy lookup
  name_to_api = {api.function_name: api for api in api_list}

  # Get source_per_type and sink_map from ConditionManager
  source_per_type = getattr(condition_manager, 'source_per_type', {})
  sink_map = getattr(condition_manager, 'sink_map', {})

  # Classify all APIs by role (based on static analysis, no heuristics)
  classification = {
    'SOURCE': set(),      # Creates resources (return pointer to struct)
    'SINK': set(),        # Destroys resources (DELETE access)
    'INIT': set(),        # Initializes existing objects
    'OTHER': set()        # All other APIs
  }

  for api in api_list:
    if api in source_apis:
      classification['SOURCE'].add(api.function_name)
    elif api in sink_apis:
      classification['SINK'].add(api.function_name)
    elif api in init_apis:
      classification['INIT'].add(api.function_name)
    else:
      # No heuristic - all non-SOURCE/SINK/INIT APIs go to OTHER
      classification['OTHER'].add(api.function_name)

  # Build reverse dependency graph (who can come after me)
  all_apis_set = set(dep_graph_api.keys())
  for deps in dep_graph_api.values():
    all_apis_set.update(deps)

  reverse_graph = {api: [] for api in all_apis_set}
  for api, deps in dep_graph_api.items():
    for dep in deps:
      if dep in reverse_graph:
        reverse_graph[dep].append(api)

  sequences = []
  seen = set()

  def add_sequence(seq_apis: List[Api]):
    """Add sequence if unique and valid"""
    if len(seq_apis) >= 2:
      seq_names = tuple(api.function_name for api in seq_apis)
      if seq_names not in seen:
        seen.add(seq_names)
        sequences.append(list(seq_names))
        return True
    return False

  def get_type_key(api: Api) -> str:
    """Get the primary output type of an API for matching"""
    ret_type = api.return_info.type
    if ret_type and ret_type != 'void':
      return ret_type.replace('*', '').replace(' ', '')
    return None

  def find_matching_sink(source_api: Api) -> Api:
    """Find a sink that matches the source's output type"""
    source_type = get_type_key(source_api)
    if not source_type:
      return None

    # Look through sink_map for matching type
    for sink_type, sink_api in sink_map.items():
      sink_type_str = str(sink_type.token if hasattr(sink_type, 'token') else sink_type)
      sink_type_clean = sink_type_str.replace('*', '').replace(' ', '')
      if source_type == sink_type_clean:
        return sink_api

    # Fallback: look for sink with matching parameter type
    for sink_api in sink_apis:
      if sink_api.arguments_info:
        arg_type = sink_api.arguments_info[0].type
        arg_type_clean = arg_type.replace('*', '').replace(' ', '')
        if source_type == arg_type_clean:
          return sink_api

    return None

  def find_followers(api: Api, target_apis: set = None) -> List[Api]:
    """Find APIs that can follow the given API (optionally filtered)"""
    followers = reverse_graph.get(api, [])
    if target_apis:
      followers = [f for f in followers if f in target_apis]
    return followers

  # Strategy 1: SOURCE -> matched SINK (type-aware pairs)
  logger.info('Generating type-aware SOURCE -> SINK pairs...')
  for source_api in source_apis:
    if len(sequences) >= max_sequences:
      break

    sink_api = find_matching_sink(source_api)
    if sink_api:
      add_sequence([source_api, sink_api])

  # Strategy 2: SOURCE -> OTHER -> matched SINK
  logger.info('Generating SOURCE -> OTHER -> SINK sequences...')
  other_apis = {name_to_api[name] for name in classification['OTHER'] if name in name_to_api}

  for source_api in source_apis:
    if len(sequences) >= max_sequences:
      break

    sink_api = find_matching_sink(source_api)
    if not sink_api:
      continue

    # Find OTHER APIs that can follow SOURCE
    other_followers = find_followers(source_api, other_apis)

    for op_api in other_followers[:5]:
      if len(sequences) >= max_sequences:
        break

      add_sequence([source_api, op_api, sink_api])

      # Try chaining two OTHER APIs
      other_followers2 = find_followers(op_api, other_apis)
      for op_api2 in other_followers2[:3]:
        if op_api2 != op_api:
          add_sequence([source_api, op_api, op_api2, sink_api])

  # Strategy 3: SOURCE -> INIT -> OTHER -> SINK (with initialization)
  logger.info('Generating SOURCE -> INIT -> OTHER -> SINK sequences...')
  init_api_set = {name_to_api[name] for name in classification['INIT'] if name in name_to_api}

  for source_api in source_apis:
    if len(sequences) >= max_sequences:
      break

    sink_api = find_matching_sink(source_api)
    if not sink_api:
      continue

    init_followers = find_followers(source_api, init_api_set)

    for init_api in init_followers[:3]:
      add_sequence([source_api, init_api, sink_api])

      # Add OTHER between INIT and SINK
      other_init_followers = find_followers(init_api, other_apis)
      for op_api in other_init_followers[:2]:
        add_sequence([source_api, init_api, op_api, sink_api])

  # Strategy 4: Multiple SOURCEs with shared OTHER APIs
  logger.info('Generating multi-source sequences...')
  source_list = list(source_apis)[:10]

  for i, source1 in enumerate(source_list):
    if len(sequences) >= max_sequences:
      break

    sink1 = find_matching_sink(source1)
    if not sink1:
      continue

    for source2 in source_list[i+1:i+3]:
      sink2 = find_matching_sink(source2)
      if not sink2:
        continue

      # Find common OTHER APIs
      followers1 = set(find_followers(source1, other_apis))
      followers2 = set(find_followers(source2, other_apis))
      common_others = followers1 & followers2

      for other_api in list(common_others)[:2]:
        add_sequence([source1, source2, other_api, sink1, sink2])

  # Sort sequences by length (longer first) then alphabetically
  sequences.sort(key=lambda x: (-len(x), x[0]))

  # Build classification stats with function names
  classification_stats = {
    'SOURCE': sorted(classification['SOURCE']),
    'SINK': sorted(classification['SINK']),
    'INIT': sorted(classification['INIT']),
    'OTHER': sorted(classification['OTHER'])
  }

  # Add type mapping info
  type_mapping = {}
  for source_api in source_apis:
    source_type = get_type_key(source_api)
    if source_type:
      sink = find_matching_sink(source_api)
      if sink:
        type_mapping[source_type] = {
          'sources': [source_api.function_name],
          'sink': sink.function_name
        }
        # Add other sources for same type
        for other_source in source_apis:
          if other_source != source_api and get_type_key(other_source) == source_type:
            type_mapping[source_type]['sources'].append(other_source.function_name)

  classification_stats['TYPE_MAPPING'] = type_mapping

  return sequences[:max_sequences], classification_stats


def print_dependency_graph_stats(project: str, dep_graph: dict, output_dir: str = None) -> None:
  """Print statistics and sample information about the type dependency graph."""
  if not dep_graph:
    logger.info('Empty dependency graph for project %s', project)
    return

  logger.info('')
  logger.info('=' * 80)
  logger.info('Type Dependency Graph Analysis for %s', project)
  logger.info('=' * 80)

  # Find entry points using the new function
  entry_points, all_apis = find_entry_points(dep_graph)

  # Calculate statistics
  total_apis_with_deps = len(dep_graph)
  total_all_apis = len(all_apis)
  total_dependencies = sum(len(deps) for deps in dep_graph.values())
  avg_dependencies = total_dependencies / total_apis_with_deps if total_apis_with_deps > 0 else 0

  logger.info('')
  logger.info('Statistics:')
  logger.info('  Total APIs in graph: %d', total_all_apis)
  logger.info('  APIs with outgoing dependencies: %d', total_apis_with_deps)
  logger.info('  Total dependency edges: %d', total_dependencies)
  logger.info('  Average dependencies per API: %.2f', avg_dependencies)
  logger.info('')

  # Generate visualization if output directory is provided
  if output_dir:
    visualize_dependency_graph(project, dep_graph, output_dir, entry_points)


def run_local_extraction_for_benchmark(
    benchmark: benchmarklib.Benchmark,
    output_base: str,
    enable_llvm_extraction: bool = True
) -> tuple[str, dict, dict]:
  """Run Clang extraction for a Benchmark object and write type dependency graph.

  Args:
    benchmark: Benchmark object with project info
    output_base: Base directory for output files
    enable_llvm_extraction: If True, also run LLVM extraction to generate
                           conditions.json with provenance data

  Returns:
    Tuple of (outdir, dep_graph, extraction_data):
      - outdir: Path to the directory containing extraction outputs
      - dep_graph: Type dependency graph as dict
      - extraction_data: Additional data for driver generation
  """
  project = benchmark.project
  # Use the OSS-Fuzz project image/container (ProjectContainerTool) by
  # letting ClangAPIExtractor create its default container. The extractor
  # writes outputs inside the container; we'll copy them back locally.
  outdir = os.path.abspath(os.path.join(output_base, project))
  os.makedirs(outdir, exist_ok=True)

  # If LLVM extraction is enabled, use custom base-builder with LLVM 14
  clang_extractor = ClangAPIExtractor(
      benchmark, use_llvm14_builder=enable_llvm_extraction
  )  # creates ProjectContainerTool internally
  script_path = clang_extractor.extract_script
  if not Path(script_path).exists():
    raise RuntimeError(
        f'Liberator extract script not found at {script_path}. '
        'Please provide minimal liberator files under `liberator_adapter/liberator`.')

  # Use a container-internal temp dir for outputs to avoid host path collisions.
  container_output_dir = f'/tmp/liberator_extract_{project}'
  container = clang_extractor.container
  clang_extractor._ensure_output_dir(container_output_dir)
  
  # Generate public_headers.txt following liberator's design:
  # - Format: one header filename per line (e.g., "cJSON.h")
  # - Should list only public API headers, not all headers
  # - We try to find project-specific headers first
  public_headers_path = f'{container_output_dir}/public_headers.txt'
  
  # Strategy: Find public API headers (not all headers)
  # Following liberator's design: public_headers.txt should list only public API headers
  # Priority: include/ directory > project root > system include (filtered)
  project_dir = container.project_dir
  headers_list = []
  
  # Priority 1: Check include/ directory (most common location for public headers)
  include_dir = f'{project_dir}/include'
  if container.execute(f'test -d "{include_dir}" && echo "exists"').stdout.strip() == 'exists':
    find_include_headers_cmd = (
      f'find "{include_dir}" -maxdepth 2 -type f \\( '
      f'-name "*.h" -o -name "*.hpp" -o -name "*.h++" -o -name "*.hh" '
      f'\\) ! -path "*/internal/*" ! -path "*/private/*" ! -path "*/detail/*" '
      f'! -path "*/impl/*" ! -path "*/*_internal.*" ! -path "*/*_private.*" '
      f'-exec basename {{}} \\; | sort -u'
    )
    headers_result = container.execute(find_include_headers_cmd)
    if headers_result.returncode == 0 and headers_result.stdout.strip():
      headers_list = headers_result.stdout.strip().split('\n')
      logger.info(f'Found {len(headers_list)} header(s) in include/ directory: {headers_list[:10]}')
  
  # Priority 2: If no headers in include/, check project root (but exclude internal dirs)
  if not headers_list:
    find_root_headers_cmd = (
      f'find "{project_dir}" -maxdepth 1 -type f \\( '
      f'-name "*.h" -o -name "*.hpp" -o -name "*.h++" -o -name "*.hh" '
      f'\\) ! -name "*_internal.*" ! -name "*_private.*" '
      f'-exec basename {{}} \\; | sort -u'
    )
    headers_result = container.execute(find_root_headers_cmd)
    if headers_result.returncode == 0 and headers_result.stdout.strip():
      headers_list = headers_result.stdout.strip().split('\n')
      logger.info(f'Found {len(headers_list)} header(s) in project root: {headers_list[:10]}')
  
  # Priority 3: Fallback to system include directory, but filter by project name
  if not headers_list:
    logger.warning(f'No headers found in project directory, trying system include with project filter')
    system_include = '/usr/local/include'
    find_system_headers_cmd = (
      f'find "{system_include}" -type f \\( '
      f'-name "*{project}*.h" -o -name "*{project}*.hpp" -o '
      f'-path "*/{project}/*" \\( -name "*.h" -o -name "*.hpp" \\) '
      f'\\) -exec basename {{}} \\; | sort -u'
    )
    headers_result = container.execute(find_system_headers_cmd)
    if headers_result.returncode == 0 and headers_result.stdout.strip():
      headers_list = headers_result.stdout.strip().split('\n')
      logger.info(f'Found {len(headers_list)} header(s) in system include: {headers_list[:10]}')
  
  if not headers_list:
    raise RuntimeError(
      f'Could not find any headers for project {project}. '
      f'Please ensure headers exist in {project_dir} or provide a public_headers.txt file.'
    )
  
  # Write public_headers.txt in liberator format: one filename per line
  headers_content = '\n'.join(headers_list)
  create_file_cmd = f'cat > "{public_headers_path}" << \'EOF\'\n{headers_content}\nEOF'
  create_result = container.execute(create_file_cmd)
  if create_result.returncode != 0:
    raise RuntimeError(f'Failed to create public_headers.txt: {create_result.stderr}')
  
  logger.info(f'Generated public_headers.txt with {len(headers_list)} header(s)')
  
  # Now call extract_with_auto_detect with the public_headers_file
  apis_clang_container_path = clang_extractor.extract_with_auto_detect(
    output_dir=container_output_dir, 
    project_name=project,
    public_headers_file=public_headers_path
  )

  # Copy relevant files from container to local outdir using extractor's method.
  def _copy(container_path: str, local_name: str, required: bool = True) -> str:
    return clang_extractor._copy_from_container(
      container_path, os.path.join(outdir, local_name), required=required
    )

  apis_clang_path = _copy(apis_clang_container_path, 'apis_clang.json', required=True)
  _copy(f'{container_output_dir}/exported_functions.txt', 'exported_functions.txt', required=True)
  _copy(f'{container_output_dir}/incomplete_types.txt', 'incomplete_types.txt', required=True)

  # LLVM extraction for conditions.json with provenance data
  if enable_llvm_extraction:
    logger.info('LLVM extraction enabled, running condition extractor on HOST...')

    # Create LLVM extractor (shares the same container)
    llvm_extractor = LLVMAPIExtractor(benchmark, clang_extractor.container)

    # Compile project to bitcode using wllvm (in container)
    logger.info('Compiling project to bitcode with wllvm...')
    bc_file = llvm_extractor.compile_to_bitcode()
    logger.info(f'Generated bitcode file: {bc_file}')

    # Run condition extractor on HOST (not in container)
    # This avoids complex dependency installation in each container
    logger.info('Running condition extractor on host...')
    llvm_extractor.extract_apis_llvm_on_host(
      bc_file=bc_file,
      apis_clang_path=apis_clang_container_path,
      output_dir=outdir
    )

    # Verify required files exist
    conditions_path = os.path.join(outdir, 'conditions.json')
    data_layout_path = os.path.join(outdir, 'data_layout.txt')
    if not os.path.exists(conditions_path):
      raise RuntimeError(f'conditions.json not found at {conditions_path}')
    if not os.path.exists(data_layout_path):
      raise RuntimeError(f'data_layout.txt not found at {data_layout_path}')

    logger.info('LLVM extraction completed successfully')
  else:
    logger.info('LLVM extraction disabled, skipping condition extraction')
    # Note: conditions.json will NOT be available, provenance filtering will not work

  api_list = convert_apis_clang_json_to_api_list(apis_clang_path)
  logger.info('Parsed %d APIs from clang output for project %s', len(api_list), project)

  # Load conditions data for provenance filtering (always try if files exist)
  function_conditions = None
  conditions_path = os.path.join(outdir, 'conditions.json')
  apis_llvm_path = os.path.join(outdir, 'apis_llvm.json')
  if os.path.exists(conditions_path) and os.path.exists(apis_llvm_path):
    try:
      function_conditions = Utils.prase_function_conditions(conditions_path, apis_llvm_path)
      logger.info('Loaded %d function conditions for provenance filtering',
                  len(function_conditions.fun_cond_set))
    except Exception as e:
      logger.warning('Failed to parse conditions.json: %s', e)
  else:
    if not os.path.exists(conditions_path):
      logger.info('conditions.json not found, provenance filtering will be skipped')
    if not os.path.exists(apis_llvm_path):
      logger.info('apis_llvm.json not found, provenance filtering will be skipped')

  tdg = TypeDependencyGraphGenerator(api_list, function_conditions=function_conditions)
  dependency_graph = tdg.create()

  out_graph = {}
  for a, deps in dependency_graph.items():
    out_graph[a.function_name] = [d.function_name for d in deps]

  graph_path = os.path.join(outdir, 'type_dependency_graph.json')
  with open(graph_path, 'w') as f:
    json.dump(out_graph, f, indent=2)

  logger.info('Wrote type dependency graph to %s', graph_path)

  # Setup ConditionManager for type-aware sequence generation
  condition_manager = None
  data_layout_path = os.path.join(outdir, 'data_layout.txt')
  incomplete_types_path = os.path.join(outdir, 'incomplete_types.txt')
  enum_types_path = os.path.join(outdir, 'enum_types.txt')

  if function_conditions and os.path.exists(data_layout_path):
    try:
      condition_manager = setup_condition_manager(
        api_list=api_list,
        function_conditions=function_conditions,
        apis_clang_path=apis_clang_path,
        apis_llvm_path=apis_llvm_path,
        data_layout_path=data_layout_path,
        incomplete_types_path=incomplete_types_path,
        enum_types_path=enum_types_path
      )
    except Exception as e:
      logger.warning('Failed to setup ConditionManager: %s', e)
      import traceback
      traceback.print_exc()

  # Generate API sequences
  sequences_path = os.path.join(outdir, 'api_sequences.txt')

  if condition_manager:
    # Use type-aware sequence generation
    logger.info('Using TYPE-AWARE sequence generation (ConditionManager)')
    sequences, role_stats = generate_type_aware_sequences(
      api_list=api_list,
      condition_manager=condition_manager,
      dep_graph_api=dependency_graph.graph,  # Use Api objects
      max_sequences=100,
      max_length=5
    )

    with open(sequences_path, 'w') as f:
      f.write("# API Sequences generated with TYPE-AWARE classification\n")
      f.write(f"# Total sequences: {len(sequences)}\n")
      f.write("# Classification: Based on static analysis (ConditionManager)\n\n")

      # Write role classification statistics
      f.write("=" * 60 + "\n")
      f.write("API ROLE CLASSIFICATION (type-aware, static analysis)\n")
      f.write("=" * 60 + "\n\n")

      for role in ['SOURCE', 'SINK', 'INIT', 'OPERATE', 'OTHER']:
        if role in role_stats:
          apis = role_stats[role]
          f.write(f"{role} ({len(apis)} APIs):\n")
          for api in sorted(apis)[:15]:
            f.write(f"  - {api}\n")
          if len(apis) > 15:
            f.write(f"  ... and {len(apis) - 15} more\n")
          f.write("\n")

      # Write type mapping if available
      if 'TYPE_MAPPING' in role_stats and role_stats['TYPE_MAPPING']:
        f.write("=" * 60 + "\n")
        f.write("TYPE -> API MAPPING\n")
        f.write("=" * 60 + "\n\n")
        for type_name, mapping in role_stats['TYPE_MAPPING'].items():
          f.write(f"Type: {type_name}\n")
          f.write(f"  Sources: {', '.join(mapping['sources'][:5])}\n")
          f.write(f"  Sink: {mapping['sink']}\n\n")

      f.write("=" * 60 + "\n")
      f.write("GENERATED SEQUENCES (type-aware)\n")
      f.write("=" * 60 + "\n\n")
      for i, seq in enumerate(sequences, 1):
        f.write(f"{i}. {' -> '.join(seq)}\n")

  else:
    # No ConditionManager available - cannot generate type-aware sequences
    logger.warning('ConditionManager not available - skipping API sequence generation')
    logger.warning('To enable sequence generation, ensure LLVM extraction is enabled')
    sequences = []

  if sequences:
    logger.info('Wrote %d API sequences to %s', len(sequences), sequences_path)

  # Collect extraction data for downstream use (e.g., driver generation)
  extraction_data = {
    'api_list': api_list,
    'dependency_graph': dependency_graph,
    'function_conditions': function_conditions,
    'condition_manager': condition_manager,
    'apis_clang_path': apis_clang_path,
    'apis_llvm_path': apis_llvm_path,
    'data_layout_path': data_layout_path,
    'public_headers_path': public_headers_path,
    'headers_dir': None,  # Will be set if available
  }

  # Try to get headers directory from container
  try:
    if hasattr(clang_extractor, '_include_dir'):
      extraction_data['headers_dir'] = clang_extractor._include_dir
  except Exception:
    pass

  # Return output directory, dependency graph, and extraction data
  return outdir, out_graph, extraction_data


def generate_drivers_for_benchmark(
    benchmark: benchmarklib.Benchmark,
    output_dir: str,
    api_list: List[Api],
    dep_graph: DependencyGraph,
    function_conditions: FunctionConditionsSet,
    condition_manager: ConditionManager,
    num_drivers: int = 10,
    driver_size: int = 5,
    headers_dir: str = None,
    public_headers_file: str = None
) -> List[str]:
  """Generate fuzz drivers using Liberator's CBFactory.

  Args:
    benchmark: Benchmark object with project info
    output_dir: Directory to save generated drivers
    api_list: List of extracted APIs
    dep_graph: Type dependency graph
    function_conditions: Function conditions from static analysis
    condition_manager: Initialized ConditionManager
    num_drivers: Number of drivers to generate
    driver_size: Number of API calls per driver
    headers_dir: Directory containing header files
    public_headers_file: Path to public headers list file

  Returns:
    List of generated driver file paths
  """
  project = benchmark.project
  logger.info('Generating %d fuzz drivers for project %s...', num_drivers, project)

  drivers_dir = os.path.join(output_dir, 'drivers')
  seeds_dir = os.path.join(output_dir, 'seeds')
  os.makedirs(drivers_dir, exist_ok=True)
  os.makedirs(seeds_dir, exist_ok=True)

  try:
    from liberator_adapter.driver.factory.constraint_based import CBFactory
    from liberator_adapter.bias import Bias
    from liberator_adapter.backend.libfuzz import LFBackendDriver

    # Filter API list to only include APIs with conditions
    available_conditions = set(function_conditions.fun_cond_set.keys())
    filtered_api_list = [api for api in api_list if api.function_name in available_conditions]

    if len(filtered_api_list) < len(api_list):
      logger.info('Filtered %d APIs without conditions (keeping %d for driver generation)',
                  len(api_list) - len(filtered_api_list), len(filtered_api_list))

    if not filtered_api_list:
      logger.warning('No APIs with conditions available for driver generation')
      return []

    # Filter dependency graph to only include APIs with conditions
    filtered_dep_graph = DependencyGraph()
    api_name_to_api = {api.function_name: api for api in filtered_api_list}
    for api in dep_graph.graph:
      if api.function_name in available_conditions:
        deps = dep_graph.graph.get(api, set())
        filtered_deps = {d for d in deps if d.function_name in available_conditions}
        if filtered_deps:
          filtered_dep_graph.graph[api] = filtered_deps

    # Create bias (default random selection)
    bias = Bias()

    # Create CBFactory with Z3 validation enabled
    factory = CBFactory(
        api_list=set(filtered_api_list),
        driver_size=driver_size,
        dgraph=filtered_dep_graph,
        conditions=function_conditions,
        bias=bias,
        enable_z3_validation=True  # Use Z3 to validate sequence feasibility
    )

    # Generate drivers
    drivers = []
    for i in range(num_drivers):
      try:
        driver = factory.create_random_driver()
        drivers.append(driver)
        logger.debug('Generated driver %d/%d', i + 1, num_drivers)
      except Exception as e:
        logger.warning('Failed to generate driver %d: %s', i + 1, str(e))
        continue

    if not drivers:
      logger.warning('No drivers were generated')
      return []

    logger.info('Successfully generated %d drivers', len(drivers))

    # Save drivers using LFBackendDriver if headers are available
    saved_files = []
    if headers_dir and public_headers_file and os.path.exists(public_headers_file):
      try:
        backend = LFBackendDriver(
            working_dir=drivers_dir,
            seeds_dir=seeds_dir,
            num_seeds=5,
            headers_dir=headers_dir,
            public_headers=public_headers_file
        )

        for driver in drivers:
          try:
            driver_filename = backend.get_name()
            backend.emit_driver(driver, driver_filename)
            backend.emit_seeds(driver, driver_filename)
            saved_files.append(os.path.join(drivers_dir, driver_filename))
            logger.debug('Saved driver: %s', driver_filename)
          except Exception as e:
            logger.warning('Failed to save driver: %s', str(e))

        logger.info('Saved %d drivers to %s', len(saved_files), drivers_dir)
      except Exception as e:
        logger.warning('Failed to create backend for saving drivers: %s', str(e))
    else:
      logger.warning('Headers not available, drivers generated but not saved to files')
      logger.warning('  headers_dir: %s', headers_dir)
      logger.warning('  public_headers_file: %s', public_headers_file)

    return saved_files

  except Exception as e:
    logger.error('Failed to generate drivers: %s', str(e))
    traceback.print_exc()
    return []


def run_experiments(benchmark: benchmarklib.Benchmark, args) -> Result:
  """Runs an experiment based on the |benchmark| config."""
  try:
    work_dirs = WorkDirs(os.path.join(args.work_dir, f'output-{benchmark.id}'))
    args.work_dirs = work_dirs

    # Model name is passed directly - LangChain handles instantiation
    model_name = args.model

    result = run_single_fuzz.run(benchmark=benchmark,
                                    model_name=model_name,
                                    args=args,
                                    work_dirs=work_dirs)
    return Result(benchmark, result)
  except Exception as e:
    logger.error('Exception while running experiment: %s', str(e))
    traceback.print_exc()
    return Result(benchmark, f'Exception while running experiment: {e}')

def parse_args() -> argparse.Namespace:
  """Parses command line arguments."""
  parser = argparse.ArgumentParser(
      description='Run all experiments that evaluates all target functions.')
  parser.add_argument('-n',
                      '--num-samples',
                      type=int,
                      default=NUM_SAMPLES,
                      help='The number of samples to request from LLM.')
  parser.add_argument(
      '-t',
      '--temperature',
      type=float,
      default=TEMPERATURE,
      help=('A value between 0 and 1 representing the variety of the targets '
            'generated by LLM.'))
  parser.add_argument(
      '-tr',
      '--temperature-list',
      nargs='*',
      type=float,
      default=[],
      help=('A list of values representing the temperatures will be used by '
            'each sample LLM query.'))
  parser.add_argument('-c',
                      '--cloud-experiment-name',
                      type=str,
                      default='',
                      help='The name of the cloud experiment.')
  parser.add_argument('-cb',
                      '--cloud-experiment-bucket',
                      type=str,
                      default='',
                      help='A gcloud bucket to store experiment files.')
  parser.add_argument('-b', '--benchmarks-directory', type=str)
  parser.add_argument('-y',
                      '--benchmark-yaml',
                      type=str,
                      help='A benchmark YAML file.')
  parser.add_argument('-to', '--run-timeout', type=int, default=RUN_TIMEOUT)
  parser.add_argument('-l',
                      '--model',
                      default=models.DEFAULT_MODEL,
                      help=('Models available: '
                            f'{", ".join(models.get_available_models())}.'))
  parser.add_argument('-w', '--work-dir', default=RESULTS_DIR)
  parser.add_argument('--context',
                      action='store_true',
                      default=False,
                      help='Add context to function under test.')
  parser.add_argument('-e',
                      '--introspector-endpoint',
                      type=str,
                      default=introspector.DEFAULT_INTROSPECTOR_ENDPOINT)
  parser.add_argument(
      '-lo',
      '--log-level',
      help=
      f'Sets the logging level. Options available: {", ".join(LOG_LEVELS)}.',
      default='info')
  parser.add_argument(
      '-of',
      '--oss-fuzz-dir',
      help='OSS-Fuzz dir path to use. Create temporary directory by default.',
      default='')
  parser.add_argument(
      '-g',
      '--generate-benchmarks',
      help=('Generate benchmarks and use those for analysis. This is a string '
            'of comma-separated heuristics to use when identifying benchmark '
            'targets. Options available: '
            f'{", ".join(introspector.get_oracle_dict().keys())}.'),
      type=str)
  parser.add_argument(
      '-gp',
      '--generate-benchmarks-projects',
      help='Projects to generate benchmarks for in a comma separated string.',
      type=str)
  parser.add_argument('-gm',
                      '--generate-benchmarks-max',
                      help='Max targets to generate per benchmark heuristic.',
                      type=int,
                      default=5)
  parser.add_argument('--extract-only',
                      action='store_true',
                      default=False,
                      help='Only run Liberator Clang extraction for the provided benchmark YAML(s) and exit.')
  parser.add_argument('--generate-drivers',
                      action='store_true',
                      default=False,
                      help='Generate fuzz drivers using Liberator CBFactory after extraction.')
  parser.add_argument('--num-drivers',
                      type=int,
                      default=10,
                      help='Number of drivers to generate (default: 10).')
  parser.add_argument('--driver-size',
                      type=int,
                      default=5,
                      help='Number of API calls per driver (default: 5).')
  parser.add_argument('--disable-llvm-extraction',
                      action='store_true',
                      default=False,
                      dest='disable_llvm_extraction',
                      help='Disable LLVM extraction (enabled by default). '
                           'LLVM extraction generates conditions.json with provenance data.')
  parser.add_argument(
      '--delay',
      type=int,
      default=0,
      help=('Delay each experiment by certain seconds (e.g., 10s) to avoid '
            'exceeding quota limit in large scale experiments.'))
  parser.add_argument('-p',
                      '--prompt-builder',
                      help='The prompt builder to use for harness generation.',
                      default='DEFAULT')
  # Note: Agent mode (LangGraph) is now the default and only mode.
  # The --agent flag has been removed.
  parser.add_argument('--custom-pipeline', type=str, default='')
  parser.add_argument('-mr',
                      '--max-round',
                      type=int,
                      default=10,
                      help='Max trial round for agents.')
  parser.add_argument('--use-session-memory',
                      action='store_true',
                      default=True,
                      dest='use_session_memory',
                      help='Enable session memory (short-memory) for cross-agent consensus sharing. (default: enabled)')
  parser.add_argument('--no-session-memory',
                      action='store_false',
                      dest='use_session_memory',
                      help='Disable session memory (short-memory) for cross-agent consensus sharing.')

  # Program synthesis configuration (CBFactory + LLM refinement)
  # Note: Synthesis is always enabled - CBFactory generates base drivers, LLM Prototyper refines them
  parser.add_argument('--num-synthesis-drivers',
                      type=int,
                      default=5,
                      dest='num_synthesis_drivers',
                      help='Number of base drivers to generate with CBFactory for LLM refinement (default: 5).')

  args = parser.parse_args()
  if args.num_samples:
    assert args.num_samples > 0, '--num-samples must take a positive integer.'

  if args.temperature:
    assert 2 >= args.temperature >= 0, '--temperature must be within 0 and 2.'

  benchmark_yaml = args.benchmark_yaml
  if benchmark_yaml:
    assert (benchmark_yaml.endswith('.yaml') or
            benchmark_yaml.endswith('yml')), (
                "--benchmark-yaml needs to take an YAML file.")

  bench_yml = bool(benchmark_yaml)
  bench_dir = bool(args.benchmarks_directory)
  bench_gen = bool(args.generate_benchmarks)
  num_options = int(bench_yml) + int(bench_dir) + int(bench_gen)
  assert num_options == 1, (
      'One and only one of --benchmark-yaml, --benchmarks-directory and '
      '--generate-benchmarks. --benchmark-yaml takes one benchmark YAML file, '
      '--benchmarks-directory takes: a directory of them and '
      '--generate-benchmarks generates them during analysis.')

  # Validate cloud experiment configs.
  assert (
      bool(args.cloud_experiment_name) == bool(args.cloud_experiment_bucket)
  ), ('Cannot accept exactly one of --args.cloud-experiment-name and '
      '--args.cloud-experiment-bucket: Local experiment requires neither of '
      'them, cloud experiment needs both.')
  return args

def extend_report_with_coverage_gains() -> None:
  """Process total gain from all generated harnesses for each projects and
  update summary report. This makes it possible to view per-project stats
  as experiments complete rather than only after all experiments run."""
  coverage_gain_dict = _process_total_coverage_gain()
  existing_oss_fuzz_cov = introspector.query_introspector_language_stats()

  total_new_covgains = {}
  for project_dict in coverage_gain_dict.values():
    lang_gains = total_new_covgains.get(project_dict.get('language', 'c'), 0)
    lang_gains += project_dict.get('coverage_ofg_total_new_covered_lines', 0)
    total_new_covgains[project_dict.get('language', 'c')] = lang_gains

  comparative_cov_gains = {}
  for language, lang_cov_gain in total_new_covgains.items():
    try:
      total_coverage_increase = round(
          (lang_cov_gain / existing_oss_fuzz_cov[language]['total']) * 100.0,
          10)
    except (KeyError, ZeroDivisionError):
      total_coverage_increase = 0

    try:
      relative_coverage_increase = round(
          (lang_cov_gain / existing_oss_fuzz_cov[language]['covered']) * 100.0,
          10)
    except (KeyError, ZeroDivisionError):
      relative_coverage_increase = 0
    comparative_cov_gains[language] = {
        'total_coverage_increase': total_coverage_increase,
        'relative_coverage_increase': relative_coverage_increase,
    }
  add_to_json_report(WORK_DIR, 'coverage_gains_per_language',
                     total_new_covgains)
  add_to_json_report(WORK_DIR, 'project_summary', coverage_gain_dict)
  add_to_json_report(WORK_DIR, 'oss_fuzz_language_status',
                     existing_oss_fuzz_cov)
  add_to_json_report(WORK_DIR, 'comperative_coverage_gains',
                     comparative_cov_gains)

def extend_report_with_coverage_gains_process():
  """A process that continuously runs to update coverage gains in the
  background."""
  while True:
    time.sleep(300)  # 5 minutes.
    try:
      extend_report_with_coverage_gains()
    except Exception:
      logger.error('Failed to extend report with coverage gains')
      traceback.print_exc()

def _print_experiment_result(result: Result):
  """Prints the |result| of a single experiment."""
  logger.info('\n**** Finished benchmark %s (project-level) ****\n%s',
              result.benchmark.project,
              result.result)

def _print_experiment_results(results: list[Result],
                              cov_gain: dict[str, dict[str, Any]]):
  """Prints the |results| of multiple experiments."""
  logger.info('\n\n**** FINAL RESULTS: ****\n\n')
  for result in results:
    logger.info('%s\n*%s (project-level)*\n%s\n', '=' * 80, result.benchmark.project,
                result.result)

  # Only print coverage gain for projects in current experiments
  projects_in_results = {result.benchmark.project for result in results}
  relevant_cov_gain = {
      project: gain 
      for project, gain in cov_gain.items() 
      if project in projects_in_results
  }
  
  if relevant_cov_gain:
    logger.info('**** TOTAL COVERAGE GAIN: ****')
    for project in relevant_cov_gain:
      logger.info('*%s: %s', project, relevant_cov_gain[project]["coverage_diff"])

def _setup_logging(verbose: str = 'info') -> None:
  """Set up logging level."""

  if verbose == "debug":
    log_level = logging.DEBUG
  else:
    log_level = logging.INFO
  logging.basicConfig(
      level=log_level,
      format=LOG_FMT,
      datefmt='%Y-%m-%d %H:%M:%S',
  )
  # Set the base logger level
  logging.getLogger('').setLevel(log_level)

def add_to_json_report(outdir: str, key: str, value: Any) -> None:
  """Adds a key/value pair to JSON report."""
  os.makedirs(outdir, exist_ok=True)
  json_report_path = os.path.join(outdir, JSON_REPORT)
  if os.path.isfile(json_report_path):
    with open(json_report_path, 'r') as f:
      json_report = json.load(f)
  else:
    json_report = {}

  json_report[key] = value

  # Overwrite the new json file
  with open(json_report_path, 'w') as f:
    f.write(json.dumps(json_report, indent=2))

def _collect_token_usage_stats() -> dict[str, Any]:
  """Collects token usage statistics from all benchmark results."""
  total_stats = {
      'total_prompt_tokens': 0,
      'total_completion_tokens': 0,
      'total_tokens': 0,
      'total_drivers': 0,
      'successful_drivers': 0,
      'by_agent': {},
      'by_benchmark': {}
  }
  
  # Iterate through all benchmark directories
  for benchmark_dir in os.listdir(WORK_DIR):
    benchmark_path = os.path.join(WORK_DIR, benchmark_dir)
    if not os.path.isdir(benchmark_path):
      continue
    
    # Skip non-benchmark directories
    if not benchmark_dir.startswith('output-'):
      continue
    
    benchmark_token_usage = {
        'total_prompt_tokens': 0,
        'total_completion_tokens': 0,
        'total_tokens': 0,
        'trials': 0
    }
    
    # Check each trial's status directory for token usage
    status_dir = os.path.join(benchmark_path, 'status')
    if not os.path.isdir(status_dir):
      continue
    
    # Look for result.json files for each trial
    for trial_dir in os.listdir(status_dir):
      trial_path = os.path.join(status_dir, trial_dir)
      if not os.path.isdir(trial_path):
        continue
      
      result_file_path = os.path.join(trial_path, 'result.json')
      if not os.path.exists(result_file_path):
        continue
      try:
        with open(result_file_path, 'r') as f:
          result_data = json.load(f)
          
        # Check if token_usage exists in the result
        if 'token_usage' in result_data and result_data['token_usage']:
          token_usage = result_data['token_usage']
          
          # Aggregate totals
          prompt_tokens = token_usage.get('total_prompt_tokens', 0)
          completion_tokens = token_usage.get('total_completion_tokens', 0)
          total_tokens = token_usage.get('total_tokens', 0)
          
          total_stats['total_prompt_tokens'] += prompt_tokens
          total_stats['total_completion_tokens'] += completion_tokens
          total_stats['total_tokens'] += total_tokens
          total_stats['total_drivers'] += 1
          
          # Add to benchmark stats
          benchmark_token_usage['total_prompt_tokens'] += prompt_tokens
          benchmark_token_usage['total_completion_tokens'] += completion_tokens
          benchmark_token_usage['total_tokens'] += total_tokens
          benchmark_token_usage['trials'] += 1
          
          # Check if this trial was successful (has code coverage or compiles)
          if result_data.get('compiles', False):
            total_stats['successful_drivers'] += 1
          
          # Aggregate by agent
          by_agent = token_usage.get('by_agent', {})
          for agent_name, agent_stats in by_agent.items():
            if agent_name not in total_stats['by_agent']:
              total_stats['by_agent'][agent_name] = {
                  'prompt_tokens': 0,
                  'completion_tokens': 0,
                  'total_tokens': 0,
                  'call_count': 0
              }
            
            total_stats['by_agent'][agent_name]['prompt_tokens'] += agent_stats.get('prompt_tokens', 0)
            total_stats['by_agent'][agent_name]['completion_tokens'] += agent_stats.get('completion_tokens', 0)
            total_stats['by_agent'][agent_name]['total_tokens'] += agent_stats.get('total_tokens', 0)
            total_stats['by_agent'][agent_name]['call_count'] += agent_stats.get('call_count', 0)
      
      except Exception as e:
        logger.debug(f'Failed to read token usage from {result_file_path}: {e}')
        continue
    
    # Store per-benchmark stats if there were any trials
    if benchmark_token_usage['trials'] > 0:
      total_stats['by_benchmark'][benchmark_dir] = benchmark_token_usage
  
  # Calculate averages
  if total_stats['total_drivers'] > 0:
    total_stats['avg_prompt_tokens_per_driver'] = round(
        total_stats['total_prompt_tokens'] / total_stats['total_drivers'], 2)
    total_stats['avg_completion_tokens_per_driver'] = round(
        total_stats['total_completion_tokens'] / total_stats['total_drivers'], 2)
    total_stats['avg_total_tokens_per_driver'] = round(
        total_stats['total_tokens'] / total_stats['total_drivers'], 2)
  else:
    total_stats['avg_prompt_tokens_per_driver'] = 0
    total_stats['avg_completion_tokens_per_driver'] = 0
    total_stats['avg_total_tokens_per_driver'] = 0
  
  if total_stats['successful_drivers'] > 0:
    total_stats['avg_tokens_per_successful_driver'] = round(
        total_stats['total_tokens'] / total_stats['successful_drivers'], 2)
  else:
    total_stats['avg_tokens_per_successful_driver'] = 0
  
  return total_stats

def _process_total_coverage_gain() -> dict[str, dict[str, Any]]:
  """Processes and calculates the total coverage gain for each project."""
  textcov_dict: dict[str, list[textcov.Textcov]] = {}

  # Load all the textcov dirs
  for benchmark_dir in os.listdir(WORK_DIR):
    if not os.path.isdir(os.path.join(WORK_DIR, benchmark_dir)):
      continue

    result_benchmark_used_path = os.path.join(
        os.path.join(WORK_DIR, benchmark_dir, 'benchmark.yaml'))
    if not os.path.isfile(result_benchmark_used_path):
      continue

    project_name = ''
    ignore_patterns = []

    benchmark_used = benchmarklib.Benchmark.from_yaml(
        result_benchmark_used_path)
    if not benchmark_used:
      logger.info('Did not find benchmark for %s', benchmark_dir)
      try:
        project_name = '-'.join(benchmark_dir.split('-')[1:-1])
      except:
        continue
    else:
      logger.info('Found benchmark for %s', benchmark_dir)
      project_name = benchmark_used[0].project
      target_basename = os.path.basename(benchmark_used[0].target_path)
      ignore_patterns = [re.compile(r'^' + re.escape(target_basename) + ':')]

    coverage_reports = os.path.join(WORK_DIR, benchmark_dir,
                                    'code-coverage-reports')
    if not os.path.isdir(coverage_reports):
      continue

    if project_name not in textcov_dict:
      textcov_dict[project_name] = []
    for sample in os.listdir(coverage_reports):
      summary = os.path.join(coverage_reports, sample, 'textcov')
      if not os.path.isdir(summary):
        continue

      for textcov_file in os.listdir(summary):
        if textcov_file.endswith('.covreport'):
          with open(os.path.join(summary, textcov_file), 'rb') as f:
            if benchmark_used[0].language != 'rust':
              textcov_dict[project_name].append(textcov.Textcov.from_file(f))
            else:
              textcov_dict[project_name].append(
                  textcov.Textcov.from_rust_file(
                      f, ignore_function_patterns=ignore_patterns))
        elif textcov_file == 'all_cov.json':
          with open(os.path.join(summary, textcov_file)) as f:
            textcov_dict[project_name].append(
                textcov.Textcov.from_python_file(f))
        elif textcov_file == 'jacoco.xml':
          with open(os.path.join(summary, textcov_file)) as f:
            textcov_dict[project_name].append(textcov.Textcov.from_jvm_file(f))

  if not textcov_dict:
    return {}

  coverage_gain: dict[str, dict[str, Any]] = {}
  for project, cov_list in textcov_dict.items():
    total_cov = textcov.Textcov()
    for cov in cov_list:
      total_cov.merge(cov)
    existing_textcov = evaluator.load_existing_textcov(project)
    coverage_summary = evaluator.load_existing_coverage_summary(project)

    try:
      coverage_summary_files = coverage_summary['data'][0]['files']
      lines = [f['summary']['lines']['count'] for f in coverage_summary_files]
    except (KeyError, TypeError):
      lines = []

    total_existing_lines = sum(lines)
    total_cov_covered_lines_before_subtraction = total_cov.covered_lines
    total_cov.subtract_covered_lines(existing_textcov)
    try:
      cov_relative_gain = (total_cov.covered_lines /
                           existing_textcov.covered_lines)
    except ZeroDivisionError:
      cov_relative_gain = 0.0

    total_lines = max(total_cov.total_lines, total_existing_lines)

    if total_lines:
      coverage_gain[project] = {
          'language':
              oss_fuzz_checkout.get_project_language(project),
          'coverage_diff':
              total_cov.covered_lines / total_lines,
          'coverage_relative_gain':
              cov_relative_gain,
          'coverage_ofg_total_covered_lines':
              total_cov_covered_lines_before_subtraction,
          'coverage_ofg_total_new_covered_lines':
              total_cov.covered_lines,
          'coverage_existing_total_covered_lines':
              existing_textcov.covered_lines,
          'coverage_existing_total_lines':
              total_existing_lines,
      }
    else:
      # Fail safe when total_lines is 0 because of invalid coverage report
      logger.warning(
          'Line coverage information missing from the coverage report.')
      coverage_gain[project] = {'coverage_diff': 0.0}

  return coverage_gain

def main():
  global WORK_DIR

  args = parse_args()
  _setup_logging(args.log_level)

  # Capture time at start
  start = time.time()
  add_to_json_report(args.work_dir, 'start_time',
                     time.strftime(TIME_STAMP_FMT, time.gmtime(start)))
  # Add num_samples to report.json
  add_to_json_report(args.work_dir, 'num_samples', args.num_samples)

  # Set introspector endpoint before performing any operations to ensure the
  # right API endpoint is used throughout.
  introspector.set_introspector_endpoints(args.introspector_endpoint)

  run_single_fuzz.prepare(args.oss_fuzz_dir)

  experiment_targets = prepare_experiment_targets(args)
  if args.extract_only or args.generate_drivers:
    mode = 'extraction + driver generation' if args.generate_drivers else 'extraction-only'
    logger.info('Running %s mode for %d benchmark(s).', mode, len(experiment_targets))
    for benchmark in experiment_targets:
      outdir, dep_graph, extraction_data = run_local_extraction_for_benchmark(
        benchmark, args.work_dir,
        enable_llvm_extraction=not args.disable_llvm_extraction
      )
      logger.info('Extraction completed for %s. Results saved to %s', benchmark.project, outdir)

      # Display dependency graph statistics and generate visualization
      print_dependency_graph_stats(benchmark.project, dep_graph, output_dir=outdir)

      # Generate drivers if requested
      if args.generate_drivers:
        if extraction_data.get('condition_manager') and extraction_data.get('function_conditions'):
          saved_drivers = generate_drivers_for_benchmark(
            benchmark=benchmark,
            output_dir=outdir,
            api_list=extraction_data['api_list'],
            dep_graph=extraction_data['dependency_graph'],
            function_conditions=extraction_data['function_conditions'],
            condition_manager=extraction_data['condition_manager'],
            num_drivers=args.num_drivers,
            driver_size=args.driver_size,
            headers_dir=extraction_data.get('headers_dir'),
            public_headers_file=extraction_data.get('public_headers_path')
          )
          if saved_drivers:
            logger.info('Generated %d drivers for %s', len(saved_drivers), benchmark.project)
          else:
            logger.warning('No drivers generated for %s', benchmark.project)
        else:
          logger.warning('Cannot generate drivers for %s: ConditionManager not available', benchmark.project)
          logger.warning('Ensure LLVM extraction is enabled (--disable-llvm-extraction not set)')
    return
  if oss_fuzz_checkout.ENABLE_CACHING:
    oss_fuzz_checkout.prepare_cached_images(experiment_targets)

  logger.info('Running %s experiment(s) in parallels of %s.',
              len(experiment_targets), str(NUM_EXP))

  # Set global variables that are updated throughout experiment runs.
  WORK_DIR = args.work_dir

  # Start parallel coverage aggregate analysis
  coverage_gains_process = Process(
      target=extend_report_with_coverage_gains_process)
  coverage_gains_process.start()

  experiment_results = []
  if NUM_EXP == 1:
    for target_benchmark in experiment_targets:
      result = run_experiments(target_benchmark, args)
      _print_experiment_result(result)
      experiment_results.append(result)
  else:
    experiment_tasks = []
    with Pool(NUM_EXP, maxtasksperchild=1) as p:
      for target_benchmark in experiment_targets:
        experiment_task = p.apply_async(run_experiments,
                                        (target_benchmark, args),
                                        callback=_print_experiment_result)
        experiment_tasks.append(experiment_task)
        time.sleep(args.delay)

      experiment_results = [task.get() for task in experiment_tasks]

      # Signal that no more work will be submitte to the pool.
      p.close()

      # Wait for all workers to complete.
      p.join()

  if coverage_gains_process:
    # Do a final coverage aggregation.
    coverage_gains_process.kill()
    extend_report_with_coverage_gains()

  # Capture time at end
  end = time.time()
  add_to_json_report(args.work_dir, 'completion_time',
                     time.strftime(TIME_STAMP_FMT, time.gmtime(end)))
  add_to_json_report(args.work_dir, 'total_run_time',
                     str(timedelta(seconds=end - start)))

  # Collect and add token usage statistics
  logger.info('Collecting token usage statistics...')
  token_stats = _collect_token_usage_stats()
  add_to_json_report(args.work_dir, 'token_usage_summary', token_stats)
  
  # Print token usage summary
  if token_stats['total_drivers'] > 0:
    logger.info('=' * 60)
    logger.info('Token Usage Summary')
    logger.info('=' * 60)
    logger.info(f"Total Drivers Generated:     {token_stats['total_drivers']}")
    logger.info(f"Successful Drivers:          {token_stats['successful_drivers']}")
    logger.info(f"Total Prompt Tokens:         {token_stats['total_prompt_tokens']:,}")
    logger.info(f"Total Completion Tokens:     {token_stats['total_completion_tokens']:,}")
    logger.info(f"Total Tokens:                {token_stats['total_tokens']:,}")
    logger.info('-' * 60)
    logger.info(f"Avg Tokens per Driver:       {token_stats['avg_total_tokens_per_driver']:,.2f}")
    logger.info(f"Avg Tokens per Success:      {token_stats['avg_tokens_per_successful_driver']:,.2f}")
    logger.info('=' * 60)

  coverage_gain_dict = _process_total_coverage_gain()
  _print_experiment_results(experiment_results, coverage_gain_dict)

if __name__ == '__main__':
  sys.exit(main())
