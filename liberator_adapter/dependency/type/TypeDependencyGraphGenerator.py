import logging

from liberator_adapter.common import Api, Arg
from liberator_adapter.dependency import DependencyGraphGenerator, DependencyGraph
from liberator_adapter.constraints.provenance_checker import ProvenanceChecker, ProvenanceInfo, ProvenanceTag

# Z3 constraint pruning (required)
from liberator_adapter.constraints.z3_solver import Z3DependencyPruner
Z3_AVAILABLE = True  # Z3 is now required

logger = logging.getLogger(__name__)


class TypeDependencyGraphGenerator(DependencyGraphGenerator):
    def __init__(self, api_list, function_conditions=None, enable_provenance_filter=True,
                 enable_z3_pruning=False):
        """
        Initialize type dependency graph generator

        Args:
            api_list: API list
            function_conditions: Function constraint condition set
            enable_provenance_filter: Whether to enable Provenance filtering
            enable_z3_pruning: Whether to enable Z3 constraint pruning (requires z3-solver installation)
        """
        super().__init__()
        self.apis_list = api_list
        self.function_conditions = function_conditions
        self.enable_provenance_filter = enable_provenance_filter
        self.enable_z3_pruning = enable_z3_pruning and Z3_AVAILABLE
        self.provenance_stats = {"filtered": 0, "kept": 0}
        self.z3_stats = {"filtered": 0, "kept": 0}

        # Build API name to FunctionConditions mapping (for fast lookup)
        self.function_conditions_map = {}
        if function_conditions:
            # FunctionConditionsSet uses fun_cond_set dict, iterate over values
            for func_name, fc in function_conditions.fun_cond_set.items():
                self.function_conditions_map[func_name] = fc

        # Initialize Z3 pruner
        self.z3_pruner = None
        if self.enable_z3_pruning:
            try:
                self.z3_pruner = Z3DependencyPruner()
                logger.info("[Z3 Pruner] Enabled")
            except Exception as e:
                logger.warning(f"[Z3 Pruner] Failed to initialize: {e}")
                self.enable_z3_pruning = False

    def create(self) -> DependencyGraph:
        dependency_graph = DependencyGraph()

        for api_a in self.apis_list:
            for api_b in self.apis_list:
                # api_a_functionname = api_a.function_name
                # api_b_functionname = api_b.function_name
                # Skip self-dependencies: a function should not depend on itself
                if api_a != api_b and self.dependency_on(api_a, api_b):
                    dependency_graph.add_edge(api_a, api_b)
                    # api_a_depdences = dependency_graph.get(api_a_functionname, [])
                    # api_a_depdences += [api_b_functionname]
                    # dependency_graph[api_a_functionname] = api_a_depdences

        # sum_dep_nodes = 0
        # num_dep_nodes = 0
        # with open("type.log", "w") as l:
        #     for k, v in dependency_graph.graph.items():
        #         sum_dep_nodes += len(v)
        #         num_dep_nodes += 1
        #         l.write(f"{k.function_name} {len(v)}\n")

        # avg_dep_nodes = sum_dep_nodes/num_dep_nodes
        # print(f"Average dependencies: {avg_dep_nodes}")
        # print(f"Num. keys: {len(dependency_graph.keys())}")
        # exit(1)

        # Print provenance filtering statistics
        if self.enable_provenance_filter:
            total = self.provenance_stats["filtered"] + self.provenance_stats["kept"]
            if total > 0:
                filter_rate = (self.provenance_stats["filtered"] / total) * 100
                print(f"[Provenance Filter] Filtered {self.provenance_stats['filtered']}/{total} "
                      f"dependencies ({filter_rate:.1f}%)")

        # Print Z3 filtering statistics
        if self.enable_z3_pruning:
            total = self.z3_stats["filtered"] + self.z3_stats["kept"]
            if total > 0:
                filter_rate = (self.z3_stats["filtered"] / total) * 100
                print(f"[Z3 Pruner] Filtered {self.z3_stats['filtered']}/{total} "
                      f"dependencies ({filter_rate:.1f}%)")

        return dependency_graph

    def dependency_on(self, api_a: Api, api_b: Api):

        # api_a_functionname = api_a.function_name
        # api_b_functionname = api_b.function_name
        input_a, _ = self.get_input_output(api_a)
        _, output_b = self.get_input_output(api_b)

        # print("-"*30)

        # print(f"does '{api_a_functionname}' depends on '{api_b_functionname}'?")
        # print(f"input {input_a}")
        # print(f"output {output_a}")

        # print()

        # print(f"input {input_b}")
        # print(f"output {output_b}")

        intersection_ina_outb = self.intersection_args(input_a, output_b)

        # print(f"intersection_ina_outb")
        # print(intersection_ina_outb)
        # print()

        if len(intersection_ina_outb) == 0:
            return False

        # Apply provenance filtering
        if self.enable_provenance_filter:
            # Check if the type dependency is compatible with provenance
            is_compatible = self._check_provenance_compatibility(api_a, api_b, input_a, output_b)

            if is_compatible:
                self.provenance_stats["kept"] += 1
            else:
                self.provenance_stats["filtered"] += 1
                return False  # Early return if provenance incompatible

        # Apply Z3 constraint-based pruning
        if self.enable_z3_pruning and self.z3_pruner:
            source_cond = self.function_conditions_map.get(api_b.function_name)
            target_cond = self.function_conditions_map.get(api_a.function_name)

            try:
                should_prune, reason = self.z3_pruner.prune_dependency_edge(
                    api_b, api_a, source_cond, target_cond
                )

                if should_prune:
                    self.z3_stats["filtered"] += 1
                    return False
                else:
                    self.z3_stats["kept"] += 1
            except Exception as e:
                logger.debug(f"Z3 pruning failed for {api_b.function_name} -> {api_a.function_name}: {e}")
                # If Z3 fails, conservatively keep this edge
                self.z3_stats["kept"] += 1

        # Accept type dependency
        return True

    def _check_provenance_compatibility(self, api_a: Api, api_b: Api,
                                        input_a, output_b) -> bool:
        """
        Check provenance compatibility between two APIs

        api_a depends on api_b means: api_b's output can be used as api_a's input
        Need to check: whether output_b's provenance can be passed to input_a's provenance
        """

        # Get api_b's return value provenance (as source)
        source_prov = self._extract_provenance_from_arg(api_b, api_b.return_info, is_return=True)

        # Check each input parameter's provenance of api_a (as sink)
        for arg_a in input_a:
            # Check if types match
            type_a_clean = arg_a.type.replace("*", "").replace(" ", "")

            for arg_b in output_b:
                type_b_clean = arg_b.type.replace("*", "").replace(" ", "")

                if type_a_clean == type_b_clean:
                    # Types match, check provenance
                    sink_prov = self._extract_provenance_from_arg(api_a, arg_a, is_return=False)

                    if not ProvenanceChecker.is_compatible(source_prov, sink_prov):
                        # Provenance incompatible, reject this dependency
                        return False

        # All matching types are provenance compatible
        return True

    def _extract_provenance_from_arg(self, api: Api, arg: Arg, is_return: bool) -> ProvenanceInfo:
        """
        Extract provenance information from API's parameter or return value

        Get provenance tag by looking up AccessTypeSet in FunctionConditions
        """

        # If no conditions data, return conservative UNKNOWN
        if not self.function_conditions_map:
            return ProvenanceInfo(tag=ProvenanceTag.UNKNOWN)

        # Find FunctionConditions for this API
        fc = self.function_conditions_map.get(api.function_name)
        if not fc:
            return ProvenanceInfo(tag=ProvenanceTag.UNKNOWN)

        # Get corresponding ValueMetadata
        if is_return:
            value_metadata = fc.return_at
        else:
            # Find matching parameter (by name matching)
            param_idx = -1
            for i, api_arg in enumerate(api.arguments_info):
                if api_arg.name == arg.name:
                    param_idx = i
                    break

            if param_idx == -1 or param_idx >= len(fc.argument_at):
                return ProvenanceInfo(tag=ProvenanceTag.UNKNOWN)

            value_metadata = fc.argument_at[param_idx]

        # Extract provenance from AccessTypeSet
        # Prefer using first AccessType's provenance (simplified handling)
        ats = value_metadata.ats
        if ats and len(ats.access_type_set) > 0:
            first_at = next(iter(ats.access_type_set))
            if hasattr(first_at, 'provenance') and first_at.provenance is not None:
                return first_at.provenance

        # If no provenance information found, return UNKNOWN (conservative handling)
        return ProvenanceInfo(tag=ProvenanceTag.UNKNOWN)

    
    def get_input_output(self, api: Api):
        input_a = []
        output_a = []
        
        if api.return_info.type != "void":
            output_a += [api.return_info]

        for arg in api.arguments_info:
            if arg.type != "void":
                if arg.flag == "ref":
                    output_a += [arg]
                input_a += [arg]

        return input_a, output_a

    def intersection_args(self, args_a, args_b):

        intersection_set = set()
        for arg_a in args_a:
            for arg_b in args_b:
                type_a_clean = arg_a.type.replace("*", "").replace(" ", "") 
                type_b_clean = arg_b.type.replace("*", "").replace(" ", "")

                if type_a_clean == type_b_clean: # or size_match:
                    intersection_set.add((arg_a.name, arg_b.name))

        return intersection_set

#     print("Dependency graph")
#     for f, ds in dependency_graph.items():
#         d_str = ", ".join(ds)
#         print(f"{f} depends on: {d_str}")

#     plot_graph(dependency_graph)

#     with open("dependency_graph.json", "w") as f:
#         json.dump(dependency_graph, f, indent=4, sort_keys=True)
