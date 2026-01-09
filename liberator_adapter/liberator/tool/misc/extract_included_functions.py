#!/usr/bin/env python3

import argparse, tempfile, json, copy, os, re
import clang.cindex


function_declarations = [] # List of AST node objects that are function declarations
type_incomplete = set()    # List of incomplete types
apis_definition = []       # List of APIs with original argument types and extra info (e.g., const)
type_enum = set()

all_types = set()

def find_api(api, apis_definition):
    # from IPython import embed; embed(); exit(1)
    api_hash = str(api)
    if api_hash == "{}":
        return True
    for a in apis_definition:
        a_hash = str(a)
        if api_hash == a_hash:
            return True
    return False

def get_argument_info(type):

    info = {}

    # this trick expands typedef into their real types
    atd = type.get_declaration()
    if (atd.kind.is_declaration() and 
        "::" not in type.spelling and 
        atd.underlying_typedef_type.spelling != ""):
        type_str = atd.underlying_typedef_type.spelling
    else:
        type_str = type.spelling

    all_types.add(type_str)

    ## OLD const handling
    # # type is a function pointer
    # if "(*)" in type_str:
    #     info["type_clang"] = type_str
    #     info["const"] = False
    # else:
    #     # clean any form of [] and *
    #     n_asterix = type_str.count("*") + type_str.count("[")
    #     if "[" in type_str:
    #         # stuffs like char[100] into char*
    #         type_str = re.sub('\[\d*\]', '', type_str)
    #     type_str = type_str.replace("*","")
        
    #     info["const"] = False
    #     type_str_token = type_str.strip().split(" ")
    #     for bad_token in ["enum", "struct", "const"]:
    #         if bad_token in type_str_token:
    #             type_str_token.remove(bad_token)
    #             if bad_token == "const":
    #                 info["const"] = True

    #     # re-append the * at the end of the type
    #     info["type_clang"] = " ".join(type_str_token) + "*"*n_asterix
    ## OLD const handling

    # type is a function pointer
    if "(*)" in type_str:
        info["type_clang"] = type_str
        info["const"] = []
    else:
        # clean any form of [] and *
        n_asterix = type_str.count("*") + type_str.count("[")
        if "[" in type_str:
            # stuffs like char[100] into char*
            type_str = re.sub('\[\d*\]', '*', type_str)
        # type_str = type_str.replace("*","")
        
        
        type_str_token = type_str.strip().replace("*", " * ").split()
        for bad_token in ["enum", "struct"]:
            if bad_token in type_str_token:
                type_str_token.remove(bad_token)
        
        n_const = n_asterix             
        const_pos = [False for _ in range(n_const + 1)]

        print(type_str_token)

        i = 0
        for t in type_str_token:
            if t == "const":
                if i < len(const_pos):
                    const_pos[i] = True
            elif t == "*" and i == 1:
                continue
            else:
                i = i + 1

        while "const" in type_str_token:
            type_str_token.remove("const")
    
        info["type_clang"] = " ".join(type_str_token)
        info["const"] = const_pos

    return info

# generate an API structure from the AST node
def get_api(node, namespace):
    # {"function_name": "NotConfigured", "is_vararg": false,
    #           "return_info": {"name": "return", "flag": "val", "size": 32, "type": "i32"},
    #           "arguments_info": [{"name": "tif", "flag": "ref", "size": 64, "type": "%struct.tiff*"}, {"name": "scheme", "flag": "val", "size": 32, "type": "i32"}]}

    api_obj = {}
    try:
        function_name = node.displayname[:node.displayname.index("(")]
    except ValueError:
        print(f"Cant find '(' in {node.displayname}")
        function_name = node.displayname
        # from IPython import embed; embed(); exit(1)
        return {}
    api_obj["function_name"] = function_name
    api_obj["namespace"] = copy.deepcopy(namespace)

    nt = node.type

    rt = nt.get_result()
    api_obj["return_info"] = get_argument_info(rt)
    # rt_str = rt.spelling
    # api_obj["return_info"] = get_argument_info(rt_str)

    # if function_name == "pthreadpool_parallelize_4d_tile_1d":
    #     print(f"debug {function_name}")
    #     from IPython import embed; embed(); exit(1)

    arguments_info = []
    for a in nt.argument_types():
        info = get_argument_info(a)
        # a_str = a.spelling
        # info = get_argument_info(a_str)
        arguments_info.append(copy.deepcopy(info))
    api_obj["arguments_info"] = arguments_info

    return api_obj

# SOME NOTES HOW TO NAVIGATE THE CURSOR
# a = [f for f in node.get_arguments()][0]
# at = a.type
# atd = at.get_declaration()
# at = a.type
# a = [f for f in node.get_arguments()][0]
# a.spelling
# ## Out[120]: 'threadpool'
# at.spelling
# ## Out[121]: 'pthreadpool_t'
# atd.underlying_typedef_type.spelling
# ## 122]: 'struct pthreadpool *'

# ENUM
# In [6]: node.type.spelling
# Out[6]: 'minijail_hook_event_t'
# In [7]: node.type
# Out[7]: <clang.cindex.Type at 0x7f78ff3f51c0>

# In [8]: node.type.kind
# Out[8]: TypeKind.ENUM

# Traverse the AST tree
def traverse(node, include_folder, namespace):

    if node.kind == clang.cindex.CursorKind.NAMESPACE:
        namespace += [node.displayname]

    # Recurse for children of this node
    for child in node.get_children():
        traverse(child, include_folder, copy.deepcopy(namespace))

    # if node.type.kind == clang.cindex.TypeKind.FUNCTIONPROTO and str(node.location.file).startswith("./include/"):
    if (node.type.kind == clang.cindex.TypeKind.FUNCTIONPROTO and 
        include_folder in str(node.location.file)):
        function_declarations.append(node)
        api = get_api(node, namespace)
        if not find_api(api, apis_definition):
            apis_definition.append(api)
        # from IPython import embed; embed(); exit(1)

    # type of size -2 is a special case for incomplete types
    # from IPython import embed; embed(); exit(1)
    if (node.kind in 
        [clang.cindex.CursorKind.TYPEDEF_DECL, 
         clang.cindex.CursorKind.STRUCT_DECL] and
        node.type.get_size() == -2):
        type_incomplete.add("%" + node.type.spelling)

    # if node.kind == clang.cindex.CursorKind.TYPEDEF_DECL:
    #     print(f"TYPEDEF_DECL {node.spelling}")

    # if node.type.get_size() == -2:
    #     print(f"get_size == -2 {node.spelling}")
    #     from IPython import embed; embed(); exit(1)

    if node.kind == clang.cindex.CursorKind.ENUM_DECL:
        type_enum.add(node.type.spelling)
    # pass

MAIN_STUB = "int main(int argc, char** argv) {return 0;}"

def get_stub_file(include_folder, public_headers):

    # return "/tmp/tmpicriipu6.cc"
    stub_file = tempfile.NamedTemporaryFile(suffix='.cc', delete=False).name

    public_headers_lst = set()
    with open(public_headers, 'r') as ph:
        lines = ph.readlines()
        if(len(lines) == 0):
            print(f"No header in {public_headers}. Aborting...")
            exit(1)
        for l in lines:
            l = l.strip()
            if l:
                public_headers_lst.add(l)

    # from IPython import embed; embed(); exit()

    with open(stub_file, 'w') as tmp:
        for root, _, files in os.walk(include_folder):
            for h in files:
                # print(f"candidate header {h}: ", end='')
                if (h.endswith(".h") or h.endswith(".h++") or h.endswith(".hh") 
                    or h.endswith(".hpp")) and h in public_headers_lst:
                    h_path = os.path.join(root, h)
                    tmp.write(f"#include \"{h_path}\"\n")

        tmp.write("\n")

        tmp.write(MAIN_STUB)

    return stub_file

def _main():

    parser = argparse.ArgumentParser(description='Extract list of exprted function from header files.')
    parser.add_argument('-include_folder', '-i', type=str, help='Folder with header files!', required=True)
    parser.add_argument('-exported_functions', '-e', type=str, help='List of exported functions', required=True)
    parser.add_argument('-incomplete_types', '-t', type=str, help='List of incomplete types', required=True)
    parser.add_argument('-apis_list', '-a', type=str, help='List of APIs with types from the AST', required=True)
    parser.add_argument('-public_headers', '-p', type=str, help='List of public header files', required=True)
    parser.add_argument('-enum_list', '-n', type=str, help='List of enum types', required=False)

    args = parser.parse_args()

    include_folder = args.include_folder
    exported_functions = args.exported_functions
    incomplete_types = args.incomplete_types
    apis_list = args.apis_list
    public_headers = args.public_headers
    enum_list = args.enum_list

    target = os.environ["TARGET_NAME"]

    type_log = f"./alltypes_{target}.txt"

    tmp_file = get_stub_file(include_folder, public_headers)

    print(tmp_file)

    # exit()

    # Eventually, tell clang.cindex where libclang.dylib is -- or else apt install and good luck
    # clang.cindex.Config.set_library_path("/Users/tomgong/Desktop/build/lib")
    clang.cindex.Config.set_library_file(os.path.join(os.path.expanduser('~'), ".local/lib/python3.8/site-packages/clang/native/libclang.so"))
    index = clang.cindex.Index.create()

    # Generate AST from filepath passed in the command line
    include_paths = [f"-I{include_folder}", 
                     "-I/usr/bin/../lib/gcc/x86_64-linux-gnu/9/../../../../include/c++/9", 
                     "-I/usr/bin/../lib/gcc/x86_64-linux-gnu/9/../../../../include/c++/9/backward", 
                     "-I/usr/lib/llvm-12/lib/clang/12.0.0/include", 
                     "-I/usr/include/x86_64-linux-gnu", 
                     "-I/usr/include"]


    tu = index.parse(tmp_file, args=include_paths)
    # NOTE: this is for diagnosing in case of unexcepted behavior
    # for diag in tu.diagnostics:
    #     print(diag)
    # exit(1)

    root = tu.cursor        # Get the root of the AST
    traverse(root, include_folder, [])

    # FOR DEBUGGING TYPE PARSING
    with open(type_log, "w") as log:
        for t in all_types:
            log.write(f"{t}\n")

    with open(exported_functions, 'w') as out_f:
        for f in function_declarations:
            out_f.write(f"{f.displayname}\n")

    with open(incomplete_types, 'w') as out_f:
        for t in type_incomplete:
            out_f.write(f"{t}\n")

    # print("functions:")
    with open(apis_list, 'w') as out_f:
        for a in apis_definition:
            out_f.write(f"{json.dumps(a)}\n")

    if enum_list is not None:
        with open(enum_list, "w") as out_f:
            for e in type_enum:
                out_f.write(f"{e}\n")
        

if __name__ == "__main__":
    _main()
