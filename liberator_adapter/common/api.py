from typing import List, Optional
class Arg:
    name: str
    flag: str
    size: int
    type: str
    # these are attributes from my perspective
    is_const: List[bool]
    # Whether the type is incomplete (opaque struct pointer)
    is_type_incomplete: bool

    def __init__(self, name, flag, size, type, is_const, is_type_incomplete: bool = False):
        self.name = name
        self.flag = flag
        self.size = size
        self.type = type
        self.is_const = is_const
        # Infer incomplete type from LLVM IR struct pointers if not explicitly provided
        # Types like "%struct.foo*" indicate opaque/incomplete struct pointers
        if is_type_incomplete:
            self.is_type_incomplete = True
        else:
            # Auto-detect: LLVM IR struct pointers are typically opaque
            self.is_type_incomplete = (
                flag == "struct" or
                (isinstance(type, str) and "%struct." in type and type.endswith("*"))
            )

    def __str__(self):
        return f"Arg(name={self.name})"

    def __repr__(self):
        return str(self)

    def __key(self):
        arg_lst = []
        arg_lst += [self.name]
        arg_lst += [self.flag]
        arg_lst += [self.size]
        arg_lst += [self.type]
        arg_lst += ["".join([f"{x}" for x in self.is_const])]
        return tuple(arg_lst)

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        return hash(self) == hash(other)

    @classmethod
    def from_clang_data(cls, name: str, flag: str, type_str: str,
                        is_const: 'List[bool]', size: int = 0,
                        is_type_incomplete: bool = False) -> 'Arg':
        """Create Arg from clang data (without LLVM-specific fields)."""
        return cls(
            name=name,
            flag=flag,
            size=size,
            type=type_str,
            is_const=is_const,
            is_type_incomplete=is_type_incomplete
        )

class Api:
    function_name: str
    is_vararg: bool
    return_info: Arg
    arguments_info: List[Arg]

    namespace: List[str]

    def __init__(self, function_name: str, is_vararg: bool, 
                    return_info: Arg, arguments_info: List[Arg],
                    namespace: List[str]):
        self.function_name = function_name
        self.is_vararg = is_vararg
        self.return_info = return_info
        self.arguments_info = arguments_info
        self.namespace = namespace

    def __str__(self):
        return f"Api(function_name={self.function_name})"

    def __repr__(self):
        return str(self)

    def __key(self):
        arg_lst = []
        arg_lst += [self.function_name]
        arg_lst += [self.is_vararg]
        arg_lst += [hash(self.return_info)]
        arg_lst += [hash(a) for a in self.arguments_info]
        arg_lst += [hash(a) for a in self.namespace]
        return tuple(arg_lst)

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        return hash(self) == hash(other)

    @classmethod
    def from_clang_only(cls, function_name: str, clang_data: dict) -> Optional['Api']:
        """
        Create Api object from clang-only data (no LLVM data).

        This is a fallback when LLVM extraction fails. The resulting Api
        will have limited information (no size, simplified flags).

        Args:
            function_name: Function name
            clang_data: Dictionary from apis_clang.json line

        Returns:
            Api object, or None if parsing fails
        """
        try:
            is_vararg = clang_data.get("is_vararg", False)
            namespace = clang_data.get("namespace", [])

            # Parse return info
            return_info_data = clang_data.get("return_info", {})
            return_type = return_info_data.get("type_clang", "void")
            return_const = return_info_data.get("const", [False])
            return_info = Arg(
                name="return",
                flag=cls._infer_flag_from_type(return_type),
                size=0,  # Unknown without LLVM data
                type=return_type,
                is_const=return_const if isinstance(return_const, list) else [return_const]
            )

            # Parse arguments info
            arguments_info = []
            for arg_data in clang_data.get("arguments_info", []):
                arg_name = arg_data.get("name", "")
                arg_type = arg_data.get("type_clang", "")
                arg_const = arg_data.get("const", [False])
                arg = Arg(
                    name=arg_name,
                    flag=cls._infer_flag_from_type(arg_type),
                    size=0,  # Unknown without LLVM data
                    type=arg_type,
                    is_const=arg_const if isinstance(arg_const, list) else [arg_const]
                )
                arguments_info.append(arg)

            return cls(
                function_name=function_name,
                is_vararg=is_vararg,
                return_info=return_info,
                arguments_info=arguments_info,
                namespace=namespace
            )
        except Exception:
            return None

    @staticmethod
    def _infer_flag_from_type(type_str: str) -> str:
        """Infer type flag from C type string (simplified heuristic)."""
        if not type_str:
            return "other"
        type_lower = type_str.lower()
        if "*" in type_str or "[]" in type_str:
            if "char" in type_lower or "uint8" in type_lower or "int8" in type_lower:
                return "str"
            return "ptr"
        if "struct" in type_lower:
            return "struct"
        if "enum" in type_lower:
            return "enum"
        if any(t in type_lower for t in ["int", "long", "short", "size_t", "ssize_t"]):
            return "int"
        if any(t in type_lower for t in ["float", "double"]):
            return "float"
        if "bool" in type_lower or "_Bool" in type_str:
            return "int"
        if "void" in type_lower:
            return "void"
        return "other"

