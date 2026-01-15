from typing import List, Set, Dict, Tuple, Optional

from . import Value, Address, PointerType

class Function(Value):
    """
    Function 表示一个回调函数（函数指针）

    Attributes:
        token: 函数名
        addr: 函数地址
        arg_types: 参数类型字符串
        ret_type: 返回类型字符串
        stub_code: 增强的 stub 实现代码（由 DriverEnhancer 生成，可选）
        callback_type: 回调类型（如 comparator, handler, reader 等，可选）
    """
    token: str
    addr: Address
    arg_types:  str
    ret_type:   str
    stub_code: Optional[str]
    callback_type: Optional[str]

    def __init__(self, func_name, type: PointerType):

        if not isinstance(type, PointerType):
            raise Exception(f"{type} is not a PointerType")

        if not type.to_function:
            raise Exception(f"{type} is not a function pointer")

        token = type.get_pointee_type().token

        if "(*)" not in token:
            raise Exception(f"{type} seems not a function I can handle")

        ret_token, args_token = [t.strip() for t in token.split("(*)")]

        if args_token.endswith(" __va_list_tag *)"):
            args_token = args_token.replace(" __va_list_tag *)", "va_list)")

        self.token = func_name
        self.addr = None
        self.arg_types = args_token
        self.ret_type = ret_token

        # 增强的 stub 代码（由 DriverEnhancer 生成）
        self.stub_code = None
        self.callback_type = None

        self.addr   = Address.Address(token, self)

        # print("Function")
        # from IPython import embed; embed(); exit(1)

    def get_token(self):
        return self.token

    def get_type(self):
        return self.buffer.get_type()

    def __str__(self):
        return f"{self.__class__.__name__}(name={self.token})"
    
    def __repr__(self):
        return str(self)

    # for an element, the hash is just the key + type
    def __hash__(self):
        return hash(self.token + str(self.__class__.__name__))

    def __eq__(self, other):
        return hash(self) == hash(other)