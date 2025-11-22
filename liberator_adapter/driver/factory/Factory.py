import copy, re

from liberator_adapter.common import Api, Utils, DataLayout
from liberator_adapter.driver.ir import Type, PointerType, TypeTag

class Factory:
    """
    最小化的 Factory 类，仅提供 normalize_type 静态方法用于类型规范化
    """
    
    @staticmethod
    def normalize_type(a_type, a_size, a_flag, a_is_const) -> Type:
        """
        规范化类型：将字符串类型转换为 Type 对象
        """
        if not isinstance(a_is_const, list):
            raise Exception(f"a_is_const must be a list, \"{type(a_is_const)}\" given!")
        
        if a_flag == "ref" or a_flag == "ret":
            if not re.search("\*$", a_type) and "*" in a_type:
                raise Exception(f"Type '{a_type}' is not a valid pointer")
        elif a_flag == "val":
            if "*" in a_type:
                raise Exception(f"Type '{a_type}' seems a pointer while expecting a 'val'")

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
            
            # 修复一些类型名称
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
            
            # 获取类型大小和完整性信息
            try:
                a_size = DataLayout.instance().get_type_size(a_type_core)
            except:
                # 如果 DataLayout 未初始化，使用默认值
                a_size = 0
            
            try:
                a_incomplete_core = DataLayout.instance().is_incomplete(a_type_core)
            except:
                # 如果 DataLayout 未初始化，假设类型是完整的
                a_incomplete_core = False

            # 判断是 STRUCT 还是 PRIMITIVE
            type_tag = TypeTag.PRIMITIVE
            try:
                if DataLayout.instance().is_a_struct(a_type_core):
                    type_tag = TypeTag.STRUCT
            except:
                pass
                
            type_core = Type(a_type_core, a_size, a_incomplete_core, a_is_const[-1] if a_is_const else False, type_tag)

            return_type = type_core
            for x in range(1, pointer_level + 1):
                const_val = a_is_const[-(x+1)] if len(a_is_const) > x else False
                return_type = copy.deepcopy(PointerType( a_type_core + "*"*x , copy.deepcopy(return_type), const_val))

            return_type.to_function = False

        return return_type

