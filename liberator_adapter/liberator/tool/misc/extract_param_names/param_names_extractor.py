import tempfile, json
import os, re
import clang.cindex


class ParamNamesExtractor:
    def __init__(self, include_folder, input_file):
        self.root = self._get_ast_root(include_folder)
        with open(input_file, 'r') as f:
            self.extractor_data = json.load(f)
        self.field_names_and_types_map = {}
        self.output = []
    
    def get_field_names_for_all_functions(self, output_file=''):
        for function_data in self.extractor_data:
            data = self._add_field_names_to_function_data(function_data)
            self.output.append(data)

        if output_file:
            with open(output_file, "w") as out_file:
                json.dump(self.output, out_file, indent=4)
        return self.output

    def get_field_names_for_a_function(self, function_name):
        data = {}
        for function_data in self.extractor_data:
            if function_data["functionName"] == function_name:
                data = self._add_field_names_to_function_data(function_data)
        if data:
            return data
        else:
            return f"Could not find field names for function '{function_name}'"

    def get_field_name_using_class_type_and_index(self, class_type, field_index):
        succ, field_names_and_types = self.find_field_names_and_types(class_type)
        if not succ:
            return False, f"Could not find '{class_type}'"
        self.field_names_and_types_map[class_type] = field_names_and_types
        field_type = field_names_and_types[field_index][0]
        field_name = field_names_and_types[field_index][1]
        return {"fieldName": field_name, "fieldType": field_type}

    def _get_ast_root(self, include_folder):
        tmp_file = self._get_stub_file(include_folder)
        clang.cindex.Config.set_library_file(os.path.join(os.path.expanduser('~'), ".local/lib/python3.8/site-packages/clang/native/libclang.so"))
        index = clang.cindex.Index.create()
        tu = index.parse(tmp_file)
        root = tu.cursor  # Get the root of the AST
        return root

    def _get_stub_file(self, include_folder):
        stub_file = tempfile.NamedTemporaryFile(suffix='.cc', delete=False).name
        with open(stub_file, 'w') as tmp:
            for root, subdirs, files in os.walk(include_folder):
                for h in files:
                    if h.endswith(".h") or h.endswith(".h++") or h.endswith(".hh") or h.endswith(".hpp"):
                        h_path = os.path.join(root, h)
                        tmp.write(f"#include \"{h_path}\"\n")
            tmp.write("\n")
            tmp.write("int main(int argc, char** argv) {return 0;}")
        return stub_file

    def _find_base_type(self, node, type):
        if type == node.displayname and node.type.kind == clang.cindex.TypeKind.TYPEDEF:
            for child in node.get_children():
                if child.displayname:
                    return True, child.displayname.replace("struct ", "")
        for child in node.get_children():
            succ, res = self._find_base_type(child, type)
            if succ:
                return succ, res

        return False, ''

    def _find_return_and_param_types(self, node, function_name):
        if node.displayname.startswith(f"{function_name}(") and node.type.kind == clang.cindex.TypeKind.FUNCTIONPROTO:
            rt = node.type.get_result()
            result = {"return": self._get_base_type(rt.spelling)}
            for idx, a in enumerate(node.type.argument_types()):
                a_str = self._get_base_type(a.spelling)
                result[f"param_{idx}"] = a_str        
            return True, result

        for child in node.get_children():
            succ, res = self._find_return_and_param_types(child, function_name)
            if succ:
                return True, res

        return False, {}
    
    def _get_base_type(self, type_str):
        if type_str.startswith("const "):
            type_str = type_str[len("const "):]
        type_str = type_str.replace(" ", "").replace("unsigned", "unsigned ").replace("*", "")
        if "[" in type_str:
            type_str = re.sub('\[\d*\]', '*', type_str)
        return type_str

    def _find_field_names_and_types(self, node, type_name):
        if type_name in node.displayname and node.type.kind == clang.cindex.TypeKind.RECORD:
            field_names_and_types = []
            for child in node.get_children():
                children = list(child.get_children())
                if len(children) == 0:
                    type = 'basic_type'
                elif len(children) == 1:
                    type = children[0].displayname
                else:
                    continue

                field_names_and_types.append((type if type else "other_type", child.displayname))

            if field_names_and_types:
                return True, field_names_and_types
        elif type_name in node.displayname and node.type.kind == clang.cindex.TypeKind.TYPEDEF:
            field_names_and_types = []
            for child in node.get_children():
                if child.kind == clang.cindex.CursorKind.STRUCT_DECL:
                    for child in child.get_children():
                        children = list(child.get_children())
                        if len(children) == 0:
                            type = 'basic_type'
                        elif len(children) == 1:
                            type = children[0].displayname
                        else:
                            continue

                        field_names_and_types.append((type if type else "other_type", child.displayname))

            if field_names_and_types:
                return True, field_names_and_types

        for child in node.get_children():
            succ, res = self._find_field_names_and_types(child, type_name)
            if succ:
                return True, res

        return False, ""

    def _add_field_names_to_function_data(self, function_data):
        function_name = function_data["functionName"]

        succ, function_types = self._find_return_and_param_types(self.root, function_name)
        if not succ:
            print(f"Could not find return and param types for function '{function_name}'")
            return False, {}
        
        for name, type in function_types.items():
            succ, base_type = self._find_base_type(self.root, type)
            if not succ:
                base_type = type
            
            succ, field_names_and_types = self._find_field_names_and_types(self.root, base_type)
            if not succ:
                print(f"Could not find field names and types for '{base_type}' in {name}.")
                for access in function_data[name]:
                    access["field_name"] = "N/A"
                continue
            self.field_names_and_types_map[base_type] = field_names_and_types
            for access in function_data[name]:
                access_types_list = [base_type]
                access_param_names_list = []
                fields = [field for field in access["fields"] if field != -1]
                for field_idx in fields:
                    try:
                        prev_field_type = access_types_list[-1]
                        if prev_field_type in ["other_type", "basic_type"]:
                            continue
                        if prev_field_type in self.field_names_and_types_map:
                            access_types_list.append(self.field_names_and_types_map[prev_field_type][field_idx][0])
                            access_param_names_list.append(self.field_names_and_types_map[prev_field_type][field_idx][1])
                        else:
                            succ, field_names_and_types = self._find_field_names_and_types(self.root, prev_field_type)
                            self.field_names_and_types_map[prev_field_type] = field_names_and_types
                            access_types_list.append(field_names_and_types[field_idx][0])
                            access_param_names_list.append(field_names_and_types[field_idx][1])
                    except:
                        continue
                if access_param_names_list:
                    access["field_name"] = access_param_names_list
                else:
                    access["field_name"] = "N/A"
        return function_data
