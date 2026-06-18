
import json, collections, copy, os, random, string, logging, subprocess
from typing import List, Set #, Dict, Tuple, Optional

logger = logging.getLogger(__name__)

from liberator_adapter.common.api import Api, Arg
from liberator_adapter.common.conditions import *


def demangle_cpp_name(mangled: str) -> str:
    """Demangle a C++ mangled name to its readable form."""
    if not mangled.startswith('_Z'):
        return mangled  # Not mangled
    try:
        result = subprocess.run(
            ['c++filt', '-n', mangled],
            capture_output=True, text=True, timeout=1
        )
        if result.returncode == 0:
            demangled = result.stdout.strip()
            # Extract just the function name (before the first '(')
            if '(' in demangled:
                # Handle templates and namespaces
                name_part = demangled.split('(')[0]
                # Get the last component (function name)
                if '::' in name_part:
                    return name_part.split('::')[-1]
                return name_part
            return demangled
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return mangled  # Return original if demangling fails

class CoerceArgument:
    def __init__(self, original_type):
        self.original_type = original_type
        self.coerce_names = []
        self.coerce_types = []
        self.coerce_sizes = []
        self.arg_pos = []

    def getSize(self):
        return sum(self.coerce_sizes)

    def getMinPos(self):
        return min(self.arg_pos)

    def getOriginalPos(self):
        return set(self.arg_pos)

    def add_coerce_argument(self, arg_pos, coerce_name, coerce_type, coerce_size):
        self.arg_pos += [arg_pos]
        self.coerce_names += [coerce_name]
        self.coerce_types += [coerce_type]
        self.coerce_sizes += [coerce_size]

    def toString(self):
        return json.dumps(self.__dict__)

    def __str__(self):
        return self.toString()

    def __repr__(self):
        return self.toString()

class CoerceFunction:
    def __init__(self, f_name):
        self.function_name = f_name
        self.arguments = {}

    def add_coerce_argument(self, arg_pos, original_name, original_type, coerce_name, coerce_type, coerce_size):
        # self.arguments[arg_pos] = CoerceArgument(original_name, original_type, coerce_name, coerce_type, coerce_size)

        cArg = self.arguments.get(original_name, None)

        if cArg is None:
            cArg = CoerceArgument(original_type)
            
        cArg.add_coerce_argument(arg_pos, coerce_name, coerce_type, coerce_size)

        self.arguments[original_name] = cArg

    def toString(self):
        s = self.function_name + " " + str(self.arguments)
        # return json.dumps(self.__dict__.items())
        return s

    def __str__(self):
        return self.toString()

    def __repr__(self):
        return self.toString()

class Utils:
    @staticmethod
    def read_coerce_log(coerce_log_file):

        coerce_info = {}

        with open(coerce_log_file, 'r') as f:
            for l in f:
                l = l.strip()
                if not l:
                    continue
                l_arr = l.split("|")

                f_name = l_arr[0]
                arg_pos = int(l_arr[1])
                original_name = l_arr[2]
                original_type = l_arr[3]
                coerce_name = l_arr[4]
                coerce_type = l_arr[5]
                coerce_size = int(l_arr[6])

                cFunc = coerce_info.get(f_name, None)
                if cFunc is None:
                    cFunc = CoerceFunction(f_name)
                cFunc.add_coerce_argument(arg_pos, original_name, original_type, coerce_name, coerce_type, coerce_size)

                coerce_info[f_name] = cFunc

        return coerce_info

    @staticmethod
    def get_incomplete_types_list(incomplete_types):
        incomplete_types_list = []
        with open(incomplete_types) as f:
            for l in f:
                incomplete_types_list += [l.strip()]

        return incomplete_types_list

    @staticmethod
    def get_data_layout(data_layout_p):
        data_layout = {}
        with open(data_layout_p) as f:
            for l in f:
                l = l.strip()
                if l:
                    (type, size, hash, fuzz_friendly) = l.split(" ")
                    # 1 => fuzz friendly, 0 => otherwise
                    fuzz_friendly = fuzz_friendly == "1"
                    if hash == "<random>":
                        length = 20
                        letters = string.ascii_lowercase
                        hash = ''.join(random.choice(letters) for i in range(length))
                    data_layout["%" + type] = (int(size), hash, fuzz_friendly)
        return data_layout

    @staticmethod
    def get_apis_llvm_list(apis_llvm):
        apis_llvm_list = {}

        with open(apis_llvm) as  f:
            for l in f:
                if not l.strip():
                    continue
                if l.startswith("#"):
                    continue
                api = json.loads(l)

                function_name = api["function_name"]

                # if function_name in apis_llvm_list:
                #     raise Exception(f"Function '{function_name}' already extracted!")
                arguments_info = api["arguments_info"]
                return_info = api["return_info"]

                ret_args = [a for a in arguments_info if a["flag"] == "ret"]

                if len(ret_args) > 1 and return_info["type"] == "void":
                    print(f"[INFO] skip {function_name},  has something wrong!")
                    continue
                    # raise Exception(f"Function {function_name} has more than 1 ret argument, that's weird")

                if len(ret_args) == 1 and return_info["type"] == "void":
                    r = ret_args[0]
                    arguments_info.remove(r)
                    # r["type"] = r["type"].replace("*", "")
                    r["flag"] = "ref"
                    return_info = r
                    return_info["size"] = -1

                api["arguments_info"] = arguments_info
                api["return_info"] = return_info                

                apis_llvm_list[function_name] = copy.deepcopy(api)
        
        return apis_llvm_list


    @staticmethod
    def get_apis_clang_list(apis_clang):

        apis_clang_list = {}
        duplicate_count = 0

        with open(apis_clang) as  f:
            for l in f:
                if not l.strip():
                    continue
                if l.startswith("#"):
                    continue
                api = json.loads(l)

                function_name = api["function_name"]

                # Handle C++ function overloading: use composite key if duplicate
                if function_name in apis_clang_list:
                    # For overloaded functions, append argument signature to make unique key
                    # This allows keeping both overloads while maintaining backwards compatibility
                    args_info = api.get("arguments_info", [])
                    arg_types = "_".join(arg.get("type_clang", arg.get("type", "")).replace(" ", "").replace("*", "p").replace("&", "r") for arg in args_info)
                    unique_key = f"{function_name}__overload_{arg_types}" if arg_types else f"{function_name}__overload_{duplicate_count}"
                    if unique_key not in apis_clang_list:
                        apis_clang_list[unique_key] = copy.deepcopy(api)
                    duplicate_count += 1
                else:
                    apis_clang_list[function_name] = copy.deepcopy(api)

        if duplicate_count > 0:
            logger.debug(f"Handled {duplicate_count} overloaded C++ functions in apis_clang")

        return apis_clang_list

    @staticmethod
    def get_api_list(apis_llvm, apis_clang, coerce_map, hedader_folder, incomplete_types, minimum_apis) -> Set[Api]:

        coerce_info = Utils.read_coerce_log(coerce_map)
        included_functions = Utils.get_include_functions(hedader_folder)
        incomplete_types_list = Utils.get_incomplete_types_list(incomplete_types)

        minimum_apis_list = []
        if os.path.isfile(minimum_apis):
            with open(minimum_apis) as f:
                for l in f:
                    l = l.strip()
                    if l:
                        minimum_apis_list += [l]
        else:
            logger.debug("minimum_apis file not found, considering all APIs")

        if len(minimum_apis_list) != 0:
            included_functions = minimum_apis_list

        # TODO: make a white list form the original header
        blacklist = ["__cxx_global_var_init", "_GLOBAL__sub_I_network_lib.cpp"]

        apis_clang_list = Utils.get_apis_clang_list(apis_clang)

        # Build a set of demangled function names for matching
        # This handles C++ name mangling
        included_functions_set = set(included_functions)

        apis_list = set()
        mangled_count = 0
        matched_count = 0

        with open(apis_llvm) as  f:
            for l in f:
                if not l.strip():
                    continue
                if l.startswith("#"):
                    continue
                try:
                    api = json.loads(l)
                except Exception as e:
                    logger.error(f"Failed to parse JSON line: {l[:100]}...")
                    continue
                function_name = api["function_name"]
                if function_name in blacklist:
                    continue

                # Handle C++ mangled names
                if function_name.startswith('_Z'):
                    mangled_count += 1
                    demangled = demangle_cpp_name(function_name)
                    # Check both original mangled and demangled names
                    if function_name not in included_functions_set and demangled not in included_functions_set:
                        continue
                else:
                    # C-style name, direct match
                    if function_name not in included_functions_set:
                        continue

                matched_count += 1
                apis_list.add(Utils.normalize_coerce_args(api, apis_clang_list,
                                coerce_info, incomplete_types_list))

        if mangled_count > 0:
            logger.debug(f"C++ project detected: {mangled_count} mangled names, {matched_count} matched")

        return apis_list

    @staticmethod
    def normalize_coerce_args(api, apis_clang_list, coerce_info, incomplete_types_list) -> Api:
        function_name = api["function_name"]
        is_vararg = api["is_vararg"]
        # print(f"doing: {function_name}")
        arguments_info = api["arguments_info"]
        return_info = api["return_info"]

        namespace = []
        # Try to find the function in apis_clang_list
        # For C++ mangled names, also try the demangled name
        lookup_name = function_name
        if function_name not in apis_clang_list and function_name.startswith('_Z'):
            demangled = demangle_cpp_name(function_name)
            if demangled in apis_clang_list:
                lookup_name = demangled

        if lookup_name in apis_clang_list:
            namespace = apis_clang_list[lookup_name]["namespace"]

        ret_args = [a for a in arguments_info if a["flag"] == "ret"]

        if len(ret_args) > 1:
            raise Exception(f"Function {function_name} has more than 1 ret argument, that's weird")

        if len(ret_args) == 1 and return_info["type"] == "void":
            r = ret_args[0]
            arguments_info.remove(r)
            r["type"] = r["type"].replace("*", "")
            r["flag"] = "val"
            return_info = r
            return_info["size"] = -1

        if function_name in coerce_info:
            coerce_arguments = coerce_info[function_name].arguments

            # print("the function has coerce arguments")
            # print(coerce_arguments)
            # print(arguments_info)

            args_to_keep = set(range(len(arguments_info)))
            new_args = {}
            for arg_name, args_coerce in coerce_arguments.items():

                arg = {}
                arg["name"] = arg_name
                arg["flag"] = "val"
                arg["size"] = args_coerce.getSize()
                # normalize type name
                arg["type"] = "%{}".format(args_coerce.original_type.replace(" ", "."))

                arg_pos = args_coerce.getMinPos()
                new_args[arg_pos] = arg

                args_to_keep = args_to_keep - args_coerce.getOriginalPos()

            for pos, arg in enumerate(arguments_info):
                if pos in args_to_keep:
                    new_args[pos] = arg

            # print(new_args)

            new_args_ordered = collections.OrderedDict(sorted(new_args.items()))

            # print(arguments_info)
            arguments_info_json = list(new_args_ordered.values())
            # print(arguments_info)
            # exit()

            arguments_info = []
            for i, a_json in enumerate(arguments_info_json):
                is_const = apis_clang_list[lookup_name]["arguments_info"][i]["const"] if lookup_name in apis_clang_list and i < len(apis_clang_list[lookup_name].get("arguments_info", [])) else [False]
                a = Arg(a_json["name"], a_json["flag"],
                        a_json["size"], a_json["type"], is_const)

                arguments_info.append(a)

        else:
            arguments_info_json = arguments_info
            arguments_info = []
            for i, a_json in enumerate(arguments_info_json):
                is_const = apis_clang_list[lookup_name]["arguments_info"][i]["const"] if lookup_name in apis_clang_list and i < len(apis_clang_list[lookup_name].get("arguments_info", [])) else [False]
                a = Arg(a_json["name"], a_json["flag"],
                        a_json["size"], a_json["type"], is_const)

                arguments_info.append(a)

        is_const = apis_clang_list[lookup_name]["return_info"]["const"] if lookup_name in apis_clang_list else [False]
        return_info = Arg(return_info["name"], return_info["flag"],
                            return_info["size"], return_info["type"], is_const)

        # normalize arguments_info and return_info
        if return_info.flag in ["val", "ref", "fun"]:
            if lookup_name in apis_clang_list:
                return_info.type = apis_clang_list[lookup_name]["return_info"]["type_clang"]

        for i, arg_info in enumerate(arguments_info):
            if arg_info.flag in ["val", "ref", "fun"]:
                if lookup_name in apis_clang_list and i < len(apis_clang_list[lookup_name].get("arguments_info", [])):
                    arg_info.type = apis_clang_list[lookup_name]["arguments_info"][i]["type_clang"]
                # {"const": true, "type_clang": "char**"} becomes:
                # {"const": true, "type_clang": "char const*"}
                # if ((not function_name.startswith("minijail_") or
                #     not function_name.startswith("pcap_")) and 
                if function_name.startswith("cJSON_"):
                    if arg_info.is_const and arg_info.type.endswith("char**"):
                        arg_info.type = "char const**"
                    if (arg_info.type.endswith("char const*") and
                        "const" in arg_info.type):
                        arg_info.type = arg_info.type.replace(" const", "").strip()

        return Api(function_name, is_vararg, return_info,
                   arguments_info, namespace)

    @staticmethod
    def get_include_functions(hedader_folder) -> List[str]:

        exported_functions = set()

        with open(hedader_folder) as f:
            for l in f:
                l_strip = l.strip()
                p_par = l_strip.find("(")
                exported_functions |= { l_strip[:p_par] }

        return list(exported_functions)
        
    @staticmethod
    def get_value_metadata(mdata_json) -> ValueMetadata:
        ats = Utils.get_access_type_set(mdata_json["access_type_set"])
        
        # this is a trick to infer the type form the conditions
        is_a_string = False
        for x_type in ats.access_type_set:
            if x_type.type_string == "i8*" and x_type.parent is None:
                is_a_string = True
                break
        
        is_array = mdata_json["is_array"]
        # NOTE: due to static analysis overapprox, we consider file path
        # condition only if the type is string-like.   
        # In this case, I use the information in the coindition to infer the
        # type, otherwise I would need too much code rewriting.
        is_file_path = mdata_json["is_file_path"] and is_a_string
        is_malloc_size = mdata_json["is_malloc_size"]
        len_depends_on = mdata_json["len_depends_on"]
        set_by = mdata_json["set_by"]

        return ValueMetadata(ats, is_array, is_malloc_size, 
                is_file_path, len_depends_on, set_by)

    @staticmethod
    def get_access_type(at_json) -> AccessType:

        access = None
        if at_json["access"] == "read":
            access = Access.READ
        elif at_json["access"] == "write":
            access = Access.WRITE
        elif at_json["access"] == "return":
            access = Access.RETURN
        elif at_json["access"] == "create":
            access = Access.CREATE
        elif at_json["access"] == "delete":
            access = Access.DELETE
        elif at_json["access"] == "none":
            access = Access.NONE

        if access == None:
            print("'access' is None, what should I do?")
            exit(1)

        fields = at_json["fields"]
        type = at_json["type"]
        type_string = at_json["type_string"]

        # Create AccessType object
        at = AccessType(access, fields, type, type_string)

        # Parse provenance information (if exists)
        if "provenance" in at_json:
            from liberator_adapter.constraints.provenance_checker import ProvenanceInfo
            prov_info = ProvenanceInfo.from_dict(at_json)
            at.provenance = prov_info

        return at

    @staticmethod
    def get_access_type_set(ats_json) -> AccessTypeSet:
        ats = set()
        for at_json in ats_json:
            
            at = Utils.get_access_type(at_json)
            if at_json["parent"] != 0:
                at.parent = Utils.get_access_type(at_json["parent"])
            
            ats.add(at)

        return AccessTypeSet(ats)

    @staticmethod
    def prase_function_conditions(conditions_file, apis_llvm) -> FunctionConditionsSet:

        fcs = FunctionConditionsSet()

        api = Utils.get_apis_llvm_list(apis_llvm)

        with open(conditions_file) as  f:
            conditions = json.load(f)

            for fc_json in conditions:

                function_name = fc_json["function_name"]

                if function_name not in api:
                    continue

                params_at = []
                p_idx = 0
                while True:
                    try:
                        mdata = Utils.get_value_metadata(
                            fc_json[f"param_{p_idx}"])
                        params_at += [mdata]
                    except KeyError as e:
                        break
                    p_idx += 1

                return_at = Utils.get_value_metadata(fc_json[f"return"])

                if len(api[function_name]["arguments_info"]) != len(params_at):
                    return_at = params_at[0]
                    params_at = []


                fc = FunctionConditions(function_name, params_at, return_at)
                fcs.add_function_conditions(fc)

        return fcs
    

    @staticmethod
    def get_enum_types_list(enum_types_file: str) -> List[str]:

        enum_list = []

        with open(enum_types_file) as  f:
            for l in f:
                l = l.strip()
                if l:
                    enum_list += [l]

        return enum_list
    
