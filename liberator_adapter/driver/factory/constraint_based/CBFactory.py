"""
CBFactory: Constraint-Based Factory for driver generation

Constraint-based driver generation strategy, using ConditionManager and RunningContext
to ensure generated drivers satisfy API call constraints.

Supports optional Z3 constraint solving validation.
"""
import copy
import logging
from typing import Dict, List, Optional, Set, Tuple

from liberator_adapter.common import Api, FunctionConditionsSet, FunctionConditions, DataLayout
from liberator_adapter.common import ValueMetadata, AccessTypeSet
from liberator_adapter.constraints import ConditionUnsat, RunningContext, ConditionManager
from liberator_adapter.dependency import DependencyGraph
from liberator_adapter.driver import Driver
from liberator_adapter.driver.factory import Factory
from liberator_adapter.driver.ir import (
    ApiCall, PointerType, Variable, AllocType, Constant,
    NullConstant, AssertNull, SetNull, Address, Function
)
from liberator_adapter.bias import Bias

# DriverEnhancer for enhanced callback generation (optional)
try:
    from liberator_adapter.driver.driver_enhancer import DriverEnhancer
except ImportError:
    DriverEnhancer = None

# Z3 sequence validation (optional)
try:
    from liberator_adapter.constraints.z3_solver import (
        Z3SequenceValidator, is_z3_available
    )
    Z3_AVAILABLE = is_z3_available()
except ImportError:
    Z3_AVAILABLE = False
    Z3SequenceValidator = None

logger = logging.getLogger(__name__)


class CBFactory(Factory):
    """
    Constraint-Based Factory: Constraint-based driver generation
    
    Uses ConditionManager to identify source/sink/init APIs, and uses RunningContext
    to manage variables and constraints, ensuring generated drivers satisfy API call semantic constraints.
    """
    
    MAX_ALLOC_SIZE = 1024
    
    def __init__(self, api_list: Set[Api], driver_size: int,
                 dgraph: DependencyGraph, conditions: FunctionConditionsSet,
                 bias: Bias, enable_z3_validation: bool = False,
                 driver_enhancer: Optional['DriverEnhancer'] = None):
        """
        Initialize CBFactory

        Args:
            api_list: API set
            driver_size: Number of API calls in driver
            dgraph: Dependency graph (will be reversed)
            conditions: Function constraint condition set
            bias: Random selection strategy
            enable_z3_validation: Whether to enable Z3 sequence validation
            driver_enhancer: DriverEnhancer instance (optional, for enhanced callback generation)
        """
        self.api_list = api_list
        self.driver_size = driver_size
        self.conditions = conditions
        self.bias = bias
        self.enable_z3_validation = enable_z3_validation and Z3_AVAILABLE
        self.driver_enhancer = driver_enhancer

        # Initialize Z3 validator
        self.z3_validator = None
        if self.enable_z3_validation:
            try:
                self.z3_validator = Z3SequenceValidator()
                logger.info("[Z3 Validator] Enabled for sequence validation")
            except Exception as e:
                logger.warning(f"[Z3 Validator] Failed to initialize: {e}")
                self.enable_z3_validation = False

        # Build function condition mapping
        self.conditions_map: Dict[str, FunctionConditions] = {}
        for _, fc in self.conditions:
            self.conditions_map[fc.function_name] = fc

        # Initialize RunningContext type_to_hash (for building synthesis constraints)
        RunningContext.type_to_hash = {}
        for _, c in self.conditions:
            for arg in c.argument_at + [c.return_at]:
                for at in arg.ats:
                    RunningContext.type_to_hash[at.type_string] = at.type

        # DependencyGraph needs to be reversed (Liberator's design)
        inv_dep_graph = dict((k, set()) for k in list(dgraph.keys()))
        for api, deps in dgraph.items():
            for dep in deps:
                if dep not in inv_dep_graph:
                    inv_dep_graph[dep] = set()
                inv_dep_graph[dep].add(api)
        self.dependency_graph = inv_dep_graph

        self.condition_manager = ConditionManager.instance()

        self.source_api = list(self.condition_manager.get_source_api())
        self.init_api = list(self.condition_manager.get_init_api())

        # Build API name to Api object mapping (for enhanced callback generation)
        self.api_name_to_api: Dict[str, Api] = {
            api.function_name: api for api in self.api_list
        }

    def try_to_instantiate_api_call(self, api_call: ApiCall,
                                    conditions: FunctionConditions, 
                                    rng_ctx: RunningContext) -> Tuple[Optional[RunningContext], Set]:
        """
        Try to instantiate an API call, satisfying its constraints
        
        Returns:
            (RunningContext, unsat_vars): Returns new context on success, None and unsatisfied variable set on failure
        """
        rng_ctx = copy.deepcopy(rng_ctx)
        unsat_vars = set()

        # First round: Initialize dependent parameters (len_depends_on)
        for arg_pos, arg_type in api_call.get_pos_args_types():
            arg_cond = conditions.argument_at[arg_pos]

            # Get var-len dependency index
            # Prefer static analysis results, fallback to DriverEnhancer analysis if not available
            len_depends_idx = None
            if arg_cond.len_depends_on != "":
                # Static analysis has found var-len relationship
                len_depends_idx = int(arg_cond.len_depends_on.replace("param_", ""))
            elif self.driver_enhancer is not None:
                # Use DriverEnhancer's VarLen analysis as fallback
                varlen_info = self.driver_enhancer.get_buffer_size_constraint(
                    api_call.function_name, arg_pos
                )
                if varlen_info:
                    len_depends_idx, relationship = varlen_info
                    logger.debug(
                        f"VarLen fallback for {api_call.function_name} "
                        f"arg {arg_pos}: len_idx={len_depends_idx}, rel={relationship}"
                    )

            if (len_depends_idx is not None and
                (isinstance(arg_type, PointerType) and
                (not arg_type.get_base_type().is_incomplete or
                 arg_type.get_base_type() == rng_ctx.stub_void))):
                idx = len_depends_idx
                idx_type = api_call.arg_types[idx]

                if idx_type.get_token() not in DataLayout.size_types:
                    arg_cond.len_depends_on = ""
                else:
                    if (isinstance(arg_type, PointerType) and 
                        arg_type.get_pointee_type() == rng_ctx.stub_void):
                        arg_var = rng_ctx.create_new_var(
                            rng_ctx.stub_char_array, arg_cond, False)
                    else:
                        arg_var = rng_ctx.create_new_var(
                            arg_type, arg_cond, False)
                        
                    x = arg_var
                    if (isinstance(arg_var, Variable) and 
                        isinstance(arg_type, PointerType)):
                        arg_var = arg_var.get_address()
                    api_call.set_pos_arg_var(arg_pos, arg_var)

                    idx_cond = conditions.argument_at[idx]
                    if DataLayout.is_ptr_level(arg_type, 2):
                        var = arg_var.get_variable()
                        buff = var.get_buffer()
                        n_elem = buff.get_number_elements()
                        b_len = rng_ctx.create_new_const_int(n_elem)
                        b_len_arg = rng_ctx.create_new_var(idx_type, idx_cond, False)

                        try:
                            api_call.set_pos_arg_var(idx, b_len)
                        except Exception as e:
                            logger.warning(f"Exception setting len_depends_on arg: {e}")
                            raise

                        rng_ctx.update(api_call, arg_cond, arg_pos)
                        rng_ctx.update(api_call, idx_cond, idx)
                        rng_ctx.var_to_cond[x].len_depends_on = b_len_arg
                    else:
                        b_len = rng_ctx.create_new_var(idx_type, idx_cond, False)
                        try:
                            api_call.set_pos_arg_var(idx, b_len)
                        except Exception as e:
                            logger.warning(f"Exception setting len_depends_on arg: {e}")
                            raise

                        rng_ctx.update(api_call, arg_cond, arg_pos)
                        rng_ctx.update(api_call, idx_cond, idx)
                        rng_ctx.var_to_cond[x].len_depends_on = b_len

        # Second round: Initialize all other parameters
        for arg_pos, arg_type in api_call.get_pos_args_types():
            arg_cond = conditions.argument_at[arg_pos]

            if api_call.arg_vars[arg_pos] is not None:
                continue

            try:
                if isinstance(arg_type, PointerType) and arg_type.to_function:
                    # Use DriverEnhancer to generate enhanced callback stub (if available)
                    arg_var = self._get_enhanced_function_pointer(
                        arg_type, api_call.function_name, arg_pos, rng_ctx
                    )
                else:
                    arg_var = rng_ctx.try_to_get_var(api_call, conditions, arg_pos)
                
                if (arg_cond.is_malloc_size and 
                    arg_type.token in DataLayout.size_types):
                    api_call.set_pos_arg_var(arg_pos, arg_var, 
                                             CBFactory.MAX_ALLOC_SIZE)
                else:
                    api_call.set_pos_arg_var(arg_pos, arg_var)
            except ConditionUnsat:
                unsat_vars.add((arg_pos, arg_cond))
        
        # Handle variadic arguments
        if api_call.is_vararg:
            ats_t = AccessTypeSet()
            cond_t = ValueMetadata(ats_t, False, False, False, "", [])

            for i, _ in enumerate(api_call.vararg_var):
                new_buff = rng_ctx.create_new_var(rng_ctx.stub_char_array, 
                                                  cond_t, False)
                val = new_buff.get_address()
                var_t = None
                if isinstance(val, Address):
                    var_t = val.get_variable()
                elif isinstance(val, Variable):
                    var_t = val
                api_call.vararg_var[i] = var_t.get_address()

        # Handle return value
        ret_cond = conditions.return_at
        ret_type = api_call.ret_type
        try:
            if isinstance(ret_type, PointerType) and ret_type.to_function:
                ret_var = rng_ctx.get_null_constant()
            else:
                ret_var = rng_ctx.try_to_get_var(api_call, conditions, -1)
            api_call.set_ret_var(ret_var)
        except ConditionUnsat:
            unsat_vars.add((-1, ret_cond))
        
        if len(unsat_vars) != 0:
            return (None, unsat_vars)

        # Update context
        for arg_pos, arg_type in api_call.get_pos_args_types():
            arg_cond = conditions.argument_at[arg_pos]
            rng_ctx.update(api_call, arg_cond, arg_pos)

        if api_call.ret_var is not None:
            rng_ctx.update(api_call, ret_cond, -1)

        # Handle pending variables (e.g., array length control)
        for var, var_len, cond_len in rng_ctx.new_vars:
            rng_ctx.update_var(var_len, cond_len)
            rng_ctx.var_to_cond[var].len_depends_on = var_len
        rng_ctx.new_vars.clear()

        return (rng_ctx, {})

    def _get_enhanced_function_pointer(
        self,
        arg_type: PointerType,
        api_name: str,
        arg_pos: int,
        rng_ctx: RunningContext
    ) -> Function:
        """
        Get callback function pointer, prefer using DriverEnhancer to generate enhanced stub

        Args:
            arg_type: callback parameter type
            api_name: API name
            arg_pos: argument position
            rng_ctx: RunningContext

        Returns:
            Function object
        """
        # If DriverEnhancer is available, use enhanced stub generation
        if self.driver_enhancer is not None:
            api = self.api_name_to_api.get(api_name)
            if api is not None:
                try:
                    func_name = f"fuzz_cb_{api_name}_{arg_pos}"
                    stub_code, cb_type = self.driver_enhancer.generate_callback_stub(
                        api, arg_pos, func_name
                    )

                    # Check if stub has already been generated for this type
                    if arg_type in rng_ctx.stub_functions:
                        return rng_ctx.stub_functions[arg_type]

                    # Create Function object
                    func = Function(func_name, arg_type)
                    func.stub_code = stub_code
                    # Save to context's stub_functions
                    rng_ctx.stub_functions[arg_type] = func

                    logger.debug(
                        f"Generated enhanced callback stub for {api_name} "
                        f"arg {arg_pos}: {cb_type.value if hasattr(cb_type, 'value') else cb_type}"
                    )
                    return func
                except Exception as e:
                    logger.debug(
                        f"Failed to generate enhanced callback for {api_name} "
                        f"arg {arg_pos}: {e}, falling back to default"
                    )

        # Fallback to default function pointer generation
        return rng_ctx.get_function_pointer(arg_type)

    def validate_sequence_with_z3(self, api_sequence: List[Api]) -> Tuple[bool, List[str]]:
        """
        Use Z3 to validate if API sequence satisfies constraints

        Args:
            api_sequence: API call sequence

        Returns:
            (is_valid, violations): Whether valid, and list of violated constraints
        """
        if not self.enable_z3_validation or not self.z3_validator:
            return True, []

        try:
            return self.z3_validator.validate_sequence(api_sequence, self.conditions_map)
        except Exception as e:
            logger.warning(f"Z3 validation failed: {e}")
            return True, []  # Conservative handling: consider valid when validation fails

    def get_random_source_api(self):
        """Randomly select a source API"""
        return self.bias.get_random_candidate([], self.source_api)

    def get_random_candidate(self, candidate_api):
        """Randomly select one from candidate APIs"""
        apis = [a[2] for a in candidate_api]
        a = self.bias.get_random_candidate([], apis)         
        for ca in candidate_api:
            if ca[2] == a:
                return ca
        
        raise Exception(f"Did not match {a} with the {candidate_api}")

    def create_random_driver(self) -> Driver:
        """
        Create a random driver that satisfies constraints
        """
        rng_ctx = RunningContext()

        get_cond = lambda x: self.conditions.get_function_conditions(x.function_name)
        to_api = lambda x: Factory.api_to_apicall(x)

        if len(self.source_api) == 0:
            raise Exception("I cannot find APIs to begin with :(")

        # List[(ApiCall, RunningContext)]
        drv = list()

        # Start with source API
        begin_api = self.get_random_source_api()
        begin_condition = get_cond(begin_api)
        call_begin = to_api(begin_api)

        rng_ctx_1, unsat_var_1 = self.try_to_instantiate_api_call(
            call_begin, begin_condition, rng_ctx)

        if len(unsat_var_1) > 0:
            logger.error(f"Cannot instantiate the first function: {unsat_var_1}")
            raise Exception(f"Cannot instantiate the first function: {unsat_var_1}")

        logger.debug(f"Starting with {call_begin.function_name}")
        drv.append((call_begin, rng_ctx_1))

        api_n = begin_api
        while len(drv) < self.driver_size:
            # List[(ApiCall, RunningContext, Api)]
            candidate_api = []

            if api_n in self.dependency_graph:
                for next_possible in self.dependency_graph[api_n]:
                    if next_possible in self.source_api:
                        continue

                    logger.debug(f"Trying: {next_possible.function_name}")

                    next_condition = get_cond(next_possible)
                    call_next = to_api(next_possible)

                    rng_ctx_2, unsat_var_2 = self.try_to_instantiate_api_call(
                        call_next, next_condition, rng_ctx_1)

                    l_unsat_var = len(unsat_var_2)
                    if l_unsat_var == 0:
                        logger.debug("This works!")
                        candidate_api.append((call_next, rng_ctx_2, next_possible))
                    else:
                        logger.debug(f"Unsat vars: {l_unsat_var}")
                        for p, c in unsat_var_2:
                            arg_type = call_next.arg_types[p]
                            logger.debug(f" => arg{p}: {arg_type} -> {c}")

            logger.debug(f"Complete doable functions: {len(candidate_api)}")

            # Avoid driver degenerating into repeated calls of a single API
            if len(candidate_api) == 1 and candidate_api[0][2] == api_n:
                candidate_api = []
                
            if candidate_api:
                # (ApiCall, RunningContext, Api)
                (api_call, rng_ctx_1, api_n) = self.get_random_candidate(candidate_api)
                logger.debug(f"Choose {api_call.function_name}")

                drv.append((api_call, rng_ctx_1))
            else:
                # Start new chain
                api_n = self.get_random_source_api()
                begin_condition = get_cond(api_n)
                call_begin = to_api(api_n)

                logger.debug(f"Starting new chain with {api_n.function_name}")

                rng_ctx_1, unsat_var_1 = self.try_to_instantiate_api_call(
                    call_begin, begin_condition, rng_ctx_1)

                if len(unsat_var_1) > 0:
                    logger.error(f"Cannot instantiate the first function [second]: {unsat_var_1}")
                    raise Exception(f"Cannot instantiate the first function [second]: {unsat_var_1}")

                drv.append((call_begin, rng_ctx_1))

        # Use the last RunningContext
        context = [rng_ctx for _, rng_ctx in drv][-1]

        statements_apicall = []
        for api_call, _ in drv:
            statements_apicall.append(api_call)
            if (isinstance(api_call.ret_type, PointerType) and
                not isinstance(api_call.ret_var, NullConstant)):
                var = api_call.ret_var.get_variable()
                statements_apicall.append(AssertNull(var.get_buffer()))
            
            # Sink APIs need cleanup
            if self.condition_manager.is_sink(api_call):
                arg = api_call.arg_vars[0]
                if isinstance(arg, Address):
                    buff = arg.get_variable().get_buffer()
                elif isinstance(arg, Variable):
                    buff = arg.get_buffer()
                if buff.alloctype == AllocType.HEAP:
                    statements_apicall.append(SetNull(buff))

        context.generate_auxiliary_operations()

        statements = []
        statements.extend(context.generate_buffer_decl())
        statements.extend(context.generate_buffer_init())
        statements.extend(statements_apicall)

        clean_up_sec = context.generate_clean_up()
        counter_size = context.get_counter_size()
        stub_functions = context.get_stub_functions()

        d = Driver(statements, context)
        d.add_clean_up(clean_up_sec)
        d.add_counter_size(counter_size)
        d.add_stub_functions(stub_functions)

        return d

