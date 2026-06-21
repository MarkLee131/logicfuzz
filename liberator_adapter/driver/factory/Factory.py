import copy, re

from liberator_adapter.common import Api, Utils, DataLayout
from liberator_adapter.driver.ir import Type, PointerType, TypeTag, ApiCall


class Factory:
    """
    Factory utility class:
    - normalize_type: Normalize types extracted by Liberator to IR Type
    - api_to_apicall: Convert Api object to ApiCall (context-free call node)
    """

    @staticmethod
    def api_to_apicall(api: Api) -> ApiCall:
        """
        Convert Liberator Api object to IR layer ApiCall.
        """
        function_name = api.function_name
        return_info = api.return_info
        arguments_info = api.arguments_info
        namespace = getattr(api, "namespace", "")

        arg_list_type = []
        for arg in arguments_info:
            # NOTE: const is treated as non-const to maintain compatibility with Liberator IR
            the_type = Factory.normalize_type(arg.type, arg.size, arg.flag, arg.is_const)
            arg_list_type.append(the_type)

        if return_info.size == 0:
            ret_type = Factory.normalize_type("void", 0, "val", [False])
        else:
            ret_type = Factory.normalize_type(
                return_info.type, return_info.size, return_info.flag, return_info.is_const
            )

        return ApiCall(api, function_name, namespace, arg_list_type, ret_type)

    @staticmethod
    def normalize_type(a_type, a_size, a_flag, a_is_const) -> Type:
        """
        Normalize type: Convert string type to Type object
        """
        if not isinstance(a_is_const, list):
            raise Exception(f"a_is_const must be a list, \"{type(a_is_const)}\" given!")

        # Strip trailing pointer qualifiers — they're compiler hints, not part of
        # the type's semantic shape (libpng: ``png_struct * __restrict__``;
        # OpenSSL idioms: ``X * const``; Linux kernel: ``T * __must_check``).
        # Without this the "*$" pointer-shape check below misclassifies the type,
        # AND the downstream ``a_type.replace("*","")`` concatenates the qualifier
        # into the type name (``png_struct__restrict``) and DataLayout lookup fails.
        # `restrict` is a pure optimizer hint, legal ONLY on a pointer; libpng
        # places it MID-string (``png_struct __restrict *``) where the trailing
        # strip below misses it, leaving a mangled DataLayout key
        # (``png_struct__restrict``). Drop it wherever it appears first
        # (word-boundary, always safe), then strip trailing qualifiers.
        a_type = re.sub(r"\b(?:__restrict__|__restrict|restrict)\b", " ", a_type)
        a_type = " ".join(a_type.split())
        # Explicit alternatives (cover GCC ``__keyword__`` spellings):
        a_type = re.sub(
            r"(\s*(__restrict__|__restrict|restrict|"
            r"__const__|__const|const|"
            r"__volatile__|__volatile|volatile|"
            r"__must_check|__attribute__\s*\(\([^()]*\)\)))+\s*$",
            "", a_type
        ).rstrip()

        if a_flag == "ref" or a_flag == "ret":
            if not re.search(r"\*$", a_type) and "*" in a_type:
                raise Exception(f"Type '{a_type}' is not a valid pointer")
        elif a_flag == "val":
            if "*" in a_type:
                # For C++ projects, type aliases or templates may expand to pointer types
                # but still have 'val' flag from LLVM. Fix the flag to 'ref' instead of crashing.
                import logging
                logging.getLogger(__name__).debug(
                    f"Type '{a_type}' has pointer but flag is 'val', treating as 'ref'"
                )
                a_flag = "ref"

        if a_flag == "fun" and "(*)" in a_type:
            a_type_core = a_type
            a_size_core = 0
            a_incomplete_core = True
            a_is_const = True
            type_tag = TypeTag.FUNCTION
            type_core = Type(a_type_core, a_size_core, a_incomplete_core, 
                             a_is_const, type_tag)
            
            return_type = PointerType(
                a_type_core + "*" , copy.deepcopy(type_core))
            return_type.to_function = True
        else:
            pointer_level = a_type.count("*")
            a_type_core = a_type.replace("*", "").replace(" ", "")
            
            # Fix some type names
            if a_type_core == "unsignedlonglong":
                a_type_core = "unsigned long long"
            if a_type_core == "longlong":
                a_type_core = "long long"
            if a_type_core == "unsignedlong":
                a_type_core = "unsigned long"
            if a_type_core == "unsignedint":
                a_type_core = "unsigned int"
            if a_type_core == "signedchar":
                a_type_core = "signed char"
            if a_type_core == "unsignedchar":
                a_type_core = "unsigned char"
            if a_type_core == "unsignedshort":
                a_type_core = "unsigned short"
            
            # Type size, completeness, and STRUCT/PRIMITIVE tag come from
            # ``DataLayout``. Production callers always initialise it (see
            # ``data_context.py`` Step 3.5: build_data_layout, which runs
            # BEFORE Step 4 grammar gen for this exact reason). The earlier
            # try/except defaults (size=0, incomplete=False, tag=PRIMITIVE)
            # silently corrupted type metadata when DataLayout was missing,
            # in violation of the SSOT "No fallbacks" principle. Now we let
            # the AttributeError surface so the caller knows the
            # initialisation order is broken.
            dl = DataLayout.instance()
            try:
                a_size = dl.get_type_size(a_type_core)
                a_incomplete_core = dl.is_incomplete(a_type_core)
                type_tag = TypeTag.STRUCT if dl.is_a_struct(a_type_core) else TypeTag.PRIMITIVE
            except KeyError:
                if pointer_level >= 1:
                    # Opaque handle pointer — common C-API idiom that
                    # intentionally hides the struct (libucl ``ucl_parser*``,
                    # openssl, sqlite3, ...). Treat as incomplete struct so the
                    # driver can plumb the handle through APIs without knowing
                    # its layout.
                    a_size = 0
                    a_incomplete_core = True
                    type_tag = TypeTag.STRUCT
                else:
                    # Value-passed unknown type — almost always an ENUM that the
                    # clang-only extraction fallback didn't register in
                    # DataLayout (libucl ``ucl_string_flags``, ``ucl_emit_type``,
                    # ...). Default to int-sized primitive: the fuzzer feeds an
                    # integer, which is the correct shape for enums (the
                    # dominant case) and works for typedef'd scalars. The rare
                    # struct-by-value of an unknown type would produce a driver
                    # that fails to compile — preflight drops it before merge,
                    # so the failure surfaces as "driver rejected" not "silent
                    # wrong analysis".
                    a_size = 4
                    a_incomplete_core = False
                    type_tag = TypeTag.PRIMITIVE
                
            type_core = Type(a_type_core, a_size, a_incomplete_core, a_is_const[-1] if a_is_const else False, type_tag)

            return_type = type_core
            for x in range(1, pointer_level + 1):
                const_val = a_is_const[-(x+1)] if len(a_is_const) > x else False
                return_type = copy.deepcopy(PointerType( a_type_core + "*"*x , copy.deepcopy(return_type), const_val))

            return_type.to_function = False

        return return_type

