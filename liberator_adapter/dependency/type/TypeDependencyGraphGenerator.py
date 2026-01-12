import json, os

from liberator_adapter.common import Utils, Api, Arg
from liberator_adapter.dependency import DependencyGraphGenerator, DependencyGraph
from liberator_adapter.constraints.provenance_checker import ProvenanceChecker, ProvenanceInfo, ProvenanceTag


class TypeDependencyGraphGenerator(DependencyGraphGenerator):
    def __init__(self, api_list, function_conditions=None, enable_provenance_filter=True):
        super().__init__()
        self.apis_list = api_list
        self.function_conditions = function_conditions
        self.enable_provenance_filter = enable_provenance_filter
        self.provenance_stats = {"filtered": 0, "kept": 0}

        # 构建API名称到FunctionConditions的映射（用于快速查找）
        self.function_conditions_map = {}
        if function_conditions:
            for fc in function_conditions.conditions_list:
                self.function_conditions_map[fc.function_name] = fc

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

            return is_compatible

        # No provenance filter, accept type dependency
        return True

    def _check_provenance_compatibility(self, api_a: Api, api_b: Api,
                                        input_a, output_b) -> bool:
        """
        检查两个API之间的provenance兼容性

        api_a依赖api_b意味着：api_b的output可以作为api_a的input
        需要检查：output_b的provenance是否可以传给input_a的provenance
        """

        # 获取api_b的返回值provenance（作为source）
        source_prov = self._extract_provenance_from_arg(api_b, api_b.return_info, is_return=True)

        # 检查api_a的每个输入参数的provenance（作为sink）
        for arg_a in input_a:
            # 检查类型是否匹配
            type_a_clean = arg_a.type.replace("*", "").replace(" ", "")

            for arg_b in output_b:
                type_b_clean = arg_b.type.replace("*", "").replace(" ", "")

                if type_a_clean == type_b_clean:
                    # 类型匹配，检查provenance
                    sink_prov = self._extract_provenance_from_arg(api_a, arg_a, is_return=False)

                    if not ProvenanceChecker.is_compatible(source_prov, sink_prov):
                        # Provenance不兼容，拒绝这个依赖
                        return False

        # 所有匹配的类型都provenance兼容
        return True

    def _extract_provenance_from_arg(self, api: Api, arg: Arg, is_return: bool) -> ProvenanceInfo:
        """
        从API的参数或返回值中提取provenance信息

        通过查找FunctionConditions中的AccessTypeSet获取provenance标签
        """

        # 如果没有conditions数据，返回保守的UNKNOWN
        if not self.function_conditions_map:
            return ProvenanceInfo(tag=ProvenanceTag.UNKNOWN)

        # 查找该API的FunctionConditions
        fc = self.function_conditions_map.get(api.function_name)
        if not fc:
            return ProvenanceInfo(tag=ProvenanceTag.UNKNOWN)

        # 获取对应的ValueMetadata
        if is_return:
            value_metadata = fc.return_at
        else:
            # 查找匹配的参数（通过名称匹配）
            param_idx = -1
            for i, api_arg in enumerate(api.arguments_info):
                if api_arg.name == arg.name:
                    param_idx = i
                    break

            if param_idx == -1 or param_idx >= len(fc.argument_at):
                return ProvenanceInfo(tag=ProvenanceTag.UNKNOWN)

            value_metadata = fc.argument_at[param_idx]

        # 从AccessTypeSet中提取provenance
        # 优先使用第一个AccessType的provenance（简化处理）
        ats = value_metadata.ats
        if ats and len(ats.access_type_set) > 0:
            first_at = next(iter(ats.access_type_set))
            if hasattr(first_at, 'provenance') and first_at.provenance is not None:
                return first_at.provenance

        # 如果没有找到provenance信息，返回UNKNOWN（保守处理）
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
