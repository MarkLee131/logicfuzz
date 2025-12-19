import random
import copy
from typing import Set, Dict, List

from liberator_adapter.grammar import Grammar, Terminal, NonTerminal
from liberator_adapter.common import Api
from liberator_adapter.driver import Driver, Context
from liberator_adapter.driver.factory import Factory
from liberator_adapter.driver.ir import (
    Statement,
    ApiCall,
    BuffDecl,
    Type,
    PointerType,
    Variable,
    Address,
)


class OTFactory(Factory):
    """
    Only-Type Factory：基于文法和类型信息随机生成 Driver（Liberator 原生 only_type 流程移植）。
    """

    def __init__(self, api_list: Set[Api], driver_size: int, grammar: Grammar, max_nonterminals: int = 3, max_expansion_trials: int = 16):
        self.concretization_logic = self.load_concretization_logic(api_list)
        self.max_nonterminals = max_nonterminals
        self.driver_size = driver_size
        self.grammar = grammar
        self.dependency_graph = grammar.dependency_graph
        # 防止死循环的展开上限（原始实现遗漏了定义）
        self.max_expansion_trials = max_expansion_trials

    # === Public API ===

    def create_random_driver(self) -> Driver:
        driver_context_free = self.generate_driver_context_free(self.grammar)
        driver_second = self.generate_driver_context_aware(driver_context_free)
        return driver_second

    # === Internal helpers ===

    def load_concretization_logic(self, apis_list: List[Api]) -> Dict[Terminal, ApiCall]:
        concretization_logic = {}
        for api in apis_list:
            stmt = Factory.api_to_apicall(api)
            concretization_logic[Terminal(api.function_name)] = stmt
        return concretization_logic

    def nonterminals(self, terms):
        return [s for s in terms if isinstance(s, NonTerminal)]

    def generate_driver_context_free(self, grammar: Grammar):
        symbols = [grammar.get_start_symbol()]
        expansion_trials = 0

        while len(self.nonterminals(symbols)) > 0 and len(symbols) <= self.driver_size:
            symbol_to_expand = random.choice(self.nonterminals(symbols))

            expansions = grammar[symbol_to_expand]
            expansion = random.choice(tuple(expansions))

            old_symbol_idx = symbols.index(symbol_to_expand)
            del symbols[old_symbol_idx]
            for i, e in enumerate(expansion):
                symbols.insert(old_symbol_idx + i, e)

            if len(self.nonterminals(symbols)) < self.max_nonterminals:
                expansion_trials = 0
            else:
                expansion_trials += 1
                if expansion_trials >= self.max_expansion_trials:
                    raise Exception(f"Cannot expand {symbol_to_expand}")

        symbols_only_terminal = []
        for s in symbols:
            if s.name == "start":
                continue

            if isinstance(s, Terminal):
                symbols_only_terminal.append(copy.deepcopy(s))
            elif isinstance(s, NonTerminal):
                symbols_only_terminal.append(copy.deepcopy(s).convertToTerminal())
            else:
                raise Exception(f"Unexpected symbol type '{s}'")

        return symbols_only_terminal

    def generate_driver_context_aware(self, driver_ctx_free) -> Driver:
        new_statement = lambda x: copy.deepcopy(self.concretization_logic[x])
        statements = [new_statement(s) for s in driver_ctx_free if s.name != "end"]

        context = Context()
        for statement in statements:
            if isinstance(statement, ApiCall):
                for arg_pos, arg_type in statement.get_pos_args_types():
                    if context.is_void_pointer(arg_type):
                        arg_var = context.randomly_gimme_a_var(context.stub_char_array, statement.function_name)
                    elif isinstance(arg_type, PointerType) and arg_type.to_function:
                        arg_var = context.get_function_pointer(arg_type)
                    else:
                        arg_var = context.randomly_gimme_a_var(arg_type, statement.function_name)
                    statement.set_pos_arg_var(arg_pos, arg_var)

                if statement.is_vararg:
                    for i, _ in enumerate(statement.vararg_var):
                        new_buff = context.create_new_var(context.stub_char_array, False)
                        val = new_buff.get_address()
                        var_t = val.get_variable() if isinstance(val, Address) else val
                        statement.vararg_var[i] = var_t.get_address()

                if context.is_void_pointer(statement.ret_type):
                    ret_var = context.randomly_gimme_a_var(copy.deepcopy(context.stub_char_array), statement.function_name, True)
                elif isinstance(statement.ret_type, PointerType) and statement.ret_type.to_function:
                    ret_var = context.get_null_constant()
                else:
                    ret_var = context.randomly_gimme_a_var(statement.ret_type, statement.function_name, True)
                statement.set_ret_var(ret_var)
            else:
                raise Exception(f"Don't know how to handle {statement}")

        statements_buffdecl = context.generate_buffer_decl()
        statements_buffinit = context.generate_buffer_init()

        stub_functions = context.get_stub_functions()

        d = Driver(statements_buffdecl + statements_buffinit + statements, context)
        d.add_stub_functions(stub_functions)

        return d

