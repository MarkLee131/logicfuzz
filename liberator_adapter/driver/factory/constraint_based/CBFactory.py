"""
CBFactory: Constraint-Based Factory for driver generation

Constraint-based driver generation strategy, using ConditionManager and RunningContext
to ensure generated drivers satisfy API call constraints.

Supports optional Z3 constraint solving validation.

Key enhancement: Initialization chain backtracking
- When an API cannot be instantiated due to unsatisfied constraints,
  the factory attempts to find and prepend initialization APIs that can
  produce the required values.
"""
import copy
import logging
import random
from typing import Any, Dict, List, Optional, Set, Tuple

from liberator_adapter.common import Api, FunctionConditionsSet, FunctionConditions, DataLayout
from liberator_adapter.common import ValueMetadata, AccessTypeSet, Access
from liberator_adapter.constraints import ConditionUnsat, RunningContext, ConditionManager
from liberator_adapter.dependency import DependencyGraph
from liberator_adapter.driver import Driver
from liberator_adapter.driver.factory import Factory
from liberator_adapter.driver.ir import (
    ApiCall, PointerType, Variable, AllocType, Constant,
    NullConstant, AssertNull, SetNull, Address, Function, Type
)
from liberator_adapter.bias import Bias

# Import skeleton generation types
try:
    from liberator_adapter.driver.synthesis.skeleton_generator import (
        DriverSkeleton, SkeletonGenerator
    )
    SKELETON_AVAILABLE = True
except ImportError:
    SKELETON_AVAILABLE = False
    DriverSkeleton = None

# DriverEnhancer for enhanced callback generation (optional)
try:
    from liberator_adapter.driver.driver_enhancer import DriverEnhancer
except ImportError:
    DriverEnhancer = None

# Z3 sequence validation (required)
from liberator_adapter.constraints.z3_solver import (
    Z3SequenceValidator, is_z3_available
)
Z3_AVAILABLE = True  # Z3 is now required

# Z3-guided synthesis (required)
from liberator_adapter.constraints.z3_guided_synthesis import (
    Z3GuidedSynthesisController,
    is_z3_guided_available,
    create_guided_controller,
    DiagnosisType,
    RecoveryAction,
    Z3GuidedSynthesisError,
)
Z3_GUIDED_AVAILABLE = True  # Z3 is now required

logger = logging.getLogger(__name__)


def _cross_source_bind_enabled() -> bool:
    """Gate ``LOGICFUZZ_CROSS_SOURCE_BIND`` (default-off). When on, the binding
    post-pass below re-points a CREATOR's repeated same-type handle arg to a
    DIFFERENT earlier producer (cross-profile transform). See the construction
    side in ``sequence_constructor._inject_cross_source``."""
    import os as _os
    return _os.environ.get("LOGICFUZZ_CROSS_SOURCE_BIND", "0").strip().lower() in (
        "1", "true", "yes", "on")


def _validity_contract_enabled() -> bool:
    """Gate ``LOGICFUZZ_VALIDITY_CONTRACT`` (default-off). When on (and a model
    is supplied), ``_signature_handle_bindings`` binds opaque handle args by
    handle FAMILY (I3, Task 10) instead of the collapsed nearest-void* match."""
    import os as _os
    return _os.environ.get("LOGICFUZZ_VALIDITY_CONTRACT", "0").strip().lower() in (
        "1", "true", "yes", "on")


def _distribute_cross_source(
    bindings: Dict[Tuple[str, int], str],
    ordered: List[Dict[str, Any]],
) -> Dict[Tuple[str, int], str]:
    """Re-point a CREATOR's repeated same-type handle args across DISTINCT
    earlier producers so a transform built from two same-type handles uses two
    DIFFERENT instances (the cross-profile idiom).

    ``ordered`` is the sequence (in call order), one record per API::

        {"name": str, "is_producer": bool, "ret_token": str|None,
         "arg_tokens": {arg_pos: type_token}}   # only producer-bound args

    Pure: gate-off the caller never invokes it, so behaviour is byte-identical.

    Safety (mirrors ``sequence_constructor._wants_cross_source``):
      * CREATOR-scoped via ``is_producer`` — a copy/state API like
        ``deflateCopy`` returns ``int`` (not a handle) ⇒ ``is_producer`` False ⇒
        skipped, so its (dest, src) relationship is never broken.
      * name-deny (copy|clone|dup|detach) — belt-and-suspenders for handle-
        returning parent-child/copy APIs (e.g. ``cJSON_DetachItemViaPointer``).
      * only re-points when ALL of an API's same-type bound args currently share
        ONE producer AND a DISTINCT earlier producer of that type exists; picks
        the NEAREST earlier alternate first (= the construction-injected
        synthetic producer placed right before the creator).
    """
    try:
        from liberator_adapter.analysis.sequence_constructor import (
            _CROSS_SRC_DENY as _deny,
        )
    except Exception:
        _deny = ("copy", "clone", "dup", "detach")

    out = dict(bindings)
    # producers seen so far, in order: list of (name, ret_token).
    seen_producers: List[Tuple[str, str]] = []
    for rec in ordered:
        name = rec.get("name")
        if not name:
            continue
        is_producer = bool(rec.get("is_producer"))
        ret_token = rec.get("ret_token")
        nm_low = name.lower()
        if is_producer and not any(k in nm_low for k in _deny):
            # group this API's producer-bound args by type token.
            by_token: Dict[str, List[int]] = {}
            for j, tok in (rec.get("arg_tokens") or {}).items():
                if (name, j) in out and tok:
                    by_token.setdefault(tok, []).append(j)
            for tok, positions in by_token.items():
                if len(positions) < 2:
                    continue
                positions = sorted(positions)
                bound = {out[(name, p)] for p in positions}
                if len(bound) > 1:
                    continue  # already cross-source — leave it
                p0 = out[(name, positions[0])]
                # alternates: distinct earlier producers of this token, nearest
                # first, excluding the currently-bound one and self.
                alts: List[str] = []
                for pn, pt in reversed(seen_producers):
                    if pt != tok:
                        continue
                    cand = f"ret_{pn}"
                    if cand == p0 or pn == name or cand in alts:
                        continue
                    alts.append(cand)
                if not alts:
                    continue
                ring = [p0] + alts
                for i, p in enumerate(positions):
                    out[(name, p)] = ring[i % len(ring)]
        if is_producer and ret_token:
            seen_producers.append((name, ret_token))
    return out


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
                 driver_enhancer: Optional['DriverEnhancer'] = None,
                 enable_z3_guidance: bool = True,
                 z3_strict_mode: bool = True,
                 z3_timeout_ms: int = 1000,
                 automaton_artifact: Optional[Any] = None,
                 automaton_threshold: float = 0.6):
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
            enable_z3_guidance: Whether to enable Z3-guided decision making
            z3_strict_mode: If True, raise errors on Z3 failures (for debugging)
            z3_timeout_ms: Z3 solving timeout in milliseconds
            automaton_artifact: Optional ``AutomatonArtifact`` (Phase H). When
                supplied and the artifact is "strong", Z3-guided candidate
                checks gain a hard-pruning acceptance gate that rejects
                proposals whose running-sequence acceptance falls below
                ``automaton_threshold``. ``None`` preserves legacy behaviour.
            automaton_threshold: Acceptance floor for the guard.
        """
        self.api_list = api_list
        self.driver_size = driver_size
        self.conditions = conditions
        self.bias = bias
        self.enable_z3_validation = enable_z3_validation and Z3_AVAILABLE
        self.driver_enhancer = driver_enhancer

        # Z3-guided synthesis configuration
        self.enable_z3_guidance = enable_z3_guidance and Z3_GUIDED_AVAILABLE
        self.z3_strict_mode = z3_strict_mode
        self.z3_timeout_ms = z3_timeout_ms
        self.automaton_artifact = automaton_artifact
        self.automaton_threshold = float(automaton_threshold)

        # Initialize Z3 validator
        self.z3_validator = None
        if self.enable_z3_validation:
            try:
                self.z3_validator = Z3SequenceValidator()
                logger.info("[Z3 Validator] Enabled for sequence validation")
            except Exception as e:
                logger.warning(f"[Z3 Validator] Failed to initialize: {e}")
                self.enable_z3_validation = False

        # Initialize Z3-guided synthesis controller
        self.z3_controller: Optional['Z3GuidedSynthesisController'] = None
        if self.enable_z3_guidance:
            try:
                self.z3_controller = create_guided_controller(
                    timeout_ms=self.z3_timeout_ms,
                    strict_mode=self.z3_strict_mode,
                    automaton_artifact=self.automaton_artifact,
                    automaton_threshold=self.automaton_threshold,
                )
                if self.z3_controller:
                    guard_state = "off"
                    if self.z3_controller.automaton_guard is not None:
                        guard_state = (
                            "strong" if self.z3_controller.automaton_guard.is_strong()
                            else "weak"
                        )
                    logger.info("[Z3 Guided] Enabled for decision guidance "
                               f"(strict={z3_strict_mode}, timeout={z3_timeout_ms}ms, "
                               f"automaton_guard={guard_state})")
                else:
                    self.enable_z3_guidance = False
            except Exception as e:
                logger.warning(f"[Z3 Guided] Failed to initialize: {e}")
                self.enable_z3_guidance = False

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

        # Keep original dependency graph for backward chaining (initialization lookup)
        # Original graph: api -> {deps} means api needs values produced by deps
        self.original_dep_graph: Dict[Api, Set[Api]] = {}
        for api, deps in dgraph.items():
            self.original_dep_graph[api] = set(deps)

        # DependencyGraph needs to be reversed (Liberator's design)
        # Reversed graph: dep -> {apis} means dep's return value is used by apis
        inv_dep_graph = dict((k, set()) for k in list(dgraph.keys()))
        for api, deps in dgraph.items():
            for dep in deps:
                if dep not in inv_dep_graph:
                    inv_dep_graph[dep] = set()
                inv_dep_graph[dep].add(api)
        self.dependency_graph = inv_dep_graph

        # ConditionManager may be uninitialised when LLVM extraction fell back
        # to clang-only (no condition data). Without these the validated path
        # (``create_skeleton_for_sequence`` + ``_try_all_source_apis``) won't
        # work, but the model-unchecked render path doesn't touch them — so we
        # default to empty lists and let CBFactory degrade to unchecked-only
        # usage rather than crashing on construction.
        self.condition_manager = ConditionManager.instance()
        try:
            self.source_api = list(self.condition_manager.get_source_api())
            self.init_api = list(self.condition_manager.get_init_api())
        except (AttributeError, KeyError):
            self.source_api = []
            self.init_api = []

        # Build API name to Api object mapping (for enhanced callback generation)
        self.api_name_to_api: Dict[str, Api] = {
            api.function_name: api for api in self.api_list
        }

        # Build type to producer APIs mapping for initialization chain lookup
        self._build_type_producer_map()

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
        Use Z3 to validate if API sequence satisfies constraints.

        Returns ``(True, [])`` only when Z3 is disabled. When Z3 is on,
        a check failure returns ``(False, ["z3_error: ..."])`` rather
        than the previous "swallow exception, claim valid" behaviour
        which masked real bugs in the constraint encoding (e.g.
        ``add_type_match_constraint``'s contradictory assertion). Under
        ``z3_strict_mode`` the exception is re-raised instead.
        """
        if not self.enable_z3_validation or not self.z3_validator:
            return True, []

        try:
            return self.z3_validator.validate_sequence(
                api_sequence, self.conditions_map)
        except Exception as e:
            if self.z3_strict_mode:
                raise
            logger.warning("Z3 validation raised %r; reporting as INVALID", e)
            return False, [f"z3_error: {type(e).__name__}: {e}"]

    def _build_type_producer_map(self):
        """
        Build a mapping from return types to APIs that produce them.
        Used for initialization chain backtracking.
        """
        self.type_to_producers: Dict[str, List[Api]] = {}

        for api in self.api_list:
            ret_type = api.return_info.type
            if ret_type and ret_type != "void":
                # Normalize type string
                type_key = ret_type.replace(" ", "").replace("const", "").strip()
                if type_key not in self.type_to_producers:
                    self.type_to_producers[type_key] = []
                self.type_to_producers[type_key].append(api)

        logger.debug(f"Built type-to-producer map with {len(self.type_to_producers)} types")

    def find_producer_apis(self, required_type: str,
                           required_cond: Optional[ValueMetadata] = None) -> List[Api]:
        """
        Find APIs that can produce a value of the required type.

        Args:
            required_type: The type string we need (e.g., "cmsHPROFILE", "void*")
            required_cond: Optional condition metadata to match

        Returns:
            List of APIs that can produce this type
        """
        producers = []

        # Normalize the required type
        type_key = required_type.replace(" ", "").replace("const", "").strip()

        # Direct match
        if type_key in self.type_to_producers:
            producers.extend(self.type_to_producers[type_key])

        # Try without pointer suffix (for opaque pointer types)
        if type_key.endswith("*"):
            base_type = type_key[:-1]
            if base_type in self.type_to_producers:
                producers.extend(self.type_to_producers[base_type])

        # Filter by source condition if provided
        if required_cond is not None and producers:
            filtered = []
            for api in producers:
                if api.function_name in self.conditions_map:
                    ret_cond = self.conditions_map[api.function_name].return_at
                    # Check if return is a CREATE access (source)
                    if self.condition_manager.is_source(ret_cond):
                        filtered.append(api)
            if filtered:
                producers = filtered

        # Prioritize source APIs (they are more likely to be valid starting points)
        source_producers = [p for p in producers if p in self.source_api]
        if source_producers:
            return source_producers

        return producers

    def _get_arg_type_info(self, api: Api, arg_pos: int) -> Tuple[str, bool]:
        """
        Get type information for an API argument.

        Returns:
            (type_string, is_opaque_pointer)
        """
        if arg_pos < 0 or arg_pos >= len(api.arguments_info):
            return ("", False)

        arg_info = api.arguments_info[arg_pos]
        type_str = arg_info.type

        # Check if it's an opaque pointer (incomplete struct pointer)
        is_opaque = (arg_info.is_type_incomplete and
                     type_str.endswith("*") and
                     arg_info.flag == "struct")

        return (type_str, is_opaque)

    # ========== Z3-Guided Synthesis Methods ==========

    def _get_required_types(self, api: Api) -> List[str]:
        """
        Get the types required by an API (input parameter types).

        Args:
            api: API object

        Returns:
            List of required type strings (filtered for pointer/opaque types)
        """
        required = []
        for arg_info in api.arguments_info:
            type_str = arg_info.type
            # Focus on pointer types that need to be provided
            if type_str and type_str.endswith("*") and type_str != "void*":
                # Normalize
                type_key = type_str.replace(" ", "").replace("const", "").strip()
                required.append(type_key)
        return required

    def _get_produced_types(self, api: Api) -> List[str]:
        """
        Get the types produced by an API (return type).

        Args:
            api: API object

        Returns:
            List of produced type strings
        """
        ret_type = api.return_info.type
        if ret_type and ret_type != "void":
            type_key = ret_type.replace(" ", "").replace("const", "").strip()
            return [type_key]
        return []

    def _compute_api_complexity(self, api: Api) -> float:
        """
        Compute a complexity score for an API (lower is better).

        Based on:
        - Number of parameters
        - Number of opaque pointer parameters
        - Name length (heuristic: shorter names are often simpler)
        """
        score = 0.0

        # Parameter count
        score += len(api.arguments_info) * 1.0

        # Opaque pointer parameters (harder to satisfy)
        for arg_info in api.arguments_info:
            if arg_info.is_type_incomplete and arg_info.type.endswith("*"):
                score += 2.0

        # Name length heuristic
        score += len(api.function_name) * 0.01

        return score

    def _try_find_init_chain(self, target_api: Api, unsat_vars: Set,
                              rng_ctx: RunningContext,
                              max_depth: int = 3,
                              visited: Optional[Set[str]] = None) -> Optional[List[Tuple[ApiCall, RunningContext]]]:
        """
        Find an initialization chain for unsatisfied variables.

        Uses Z3 to validate chain feasibility and guide producer selection when available.
        Falls back to random selection when Z3 is not available.

        Args:
            target_api: The API we're trying to instantiate
            unsat_vars: Set of (arg_pos, condition) tuples that couldn't be satisfied
            rng_ctx: Current running context
            max_depth: Maximum recursion depth to prevent infinite loops
            visited: Set of visited API names to prevent cycles

        Returns:
            List of (ApiCall, RunningContext) tuples forming the init chain, or None if failed
        """
        if max_depth <= 0:
            return None

        if visited is None:
            visited = set()

        if target_api.function_name in visited:
            return None

        visited = visited | {target_api.function_name}

        init_chain = []
        current_ctx = copy.deepcopy(rng_ctx)
        chain_position = 0

        get_cond = lambda x: self.conditions.get_function_conditions(x.function_name)
        to_api = lambda x: Factory.api_to_apicall(x)

        sorted_unsat = sorted(list(unsat_vars), key=lambda x: x[0])

        for arg_pos, arg_cond in sorted_unsat:
            if arg_pos < 0:
                continue

            type_str, is_opaque = self._get_arg_type_info(target_api, arg_pos)
            if not type_str:
                continue

            logger.debug(f"Finding producer for {type_str} ({target_api.function_name} arg {arg_pos})")

            producers = self.find_producer_apis(type_str, arg_cond)
            if not producers:
                logger.debug(f"No producer found for {type_str}")
                continue

            # Rank producers (Z3-guided or random)
            if self.enable_z3_guidance and self.z3_controller:
                producer_candidates = []
                for producer in producers:
                    if producer.function_name in visited:
                        continue
                    required = self._get_required_types(producer)
                    produced = self._get_produced_types(producer)
                    result = self.z3_controller.solver.check_candidate(
                        producer.function_name, required, produced
                    )
                    if result.is_feasible:
                        score = result.score + self._compute_api_complexity(producer)
                        producer_candidates.append((producer, score))
                producer_candidates.sort(key=lambda x: x[1])
            else:
                # Random order
                filtered = [p for p in producers if p.function_name not in visited]
                random.shuffle(filtered)
                producer_candidates = [(p, 0.0) for p in filtered]

            for producer, score in producer_candidates[:5]:
                logger.debug(f"Trying producer {producer.function_name}")

                checkpoint = None
                if self.z3_controller:
                    checkpoint = self.z3_controller.checkpoint()

                producer_cond = get_cond(producer)
                producer_call = to_api(producer)

                new_ctx, producer_unsat = self.try_to_instantiate_api_call(
                    producer_call, producer_cond, current_ctx
                )

                if len(producer_unsat) == 0:
                    # Producer works directly
                    if self.z3_controller:
                        try:
                            required = self._get_required_types(producer)
                            produced = self._get_produced_types(producer)
                            self.z3_controller.add_api_to_sequence(
                                producer, position=chain_position,
                                required_types=required, produced_types=produced
                            )
                        except Exception as e:
                            logger.debug(f"Z3 rejected producer: {e}")
                            if checkpoint is not None:
                                self.z3_controller.rollback_to(checkpoint)
                            continue

                    chain_position += 1
                    init_chain.append((producer_call, new_ctx))
                    current_ctx = new_ctx
                    logger.debug(f"Producer {producer.function_name} added to chain")
                    break
                else:
                    # Producer needs initialization - recurse
                    sub_chain = self._try_find_init_chain(
                        producer, producer_unsat, current_ctx,
                        max_depth - 1, visited
                    )

                    if sub_chain:
                        init_chain.extend(sub_chain)
                        current_ctx = sub_chain[-1][1]
                        chain_position += len(sub_chain)

                        # Try producer again
                        producer_call = to_api(producer)
                        new_ctx, producer_unsat = self.try_to_instantiate_api_call(
                            producer_call, producer_cond, current_ctx
                        )

                        if len(producer_unsat) == 0:
                            if self.z3_controller:
                                try:
                                    required = self._get_required_types(producer)
                                    produced = self._get_produced_types(producer)
                                    self.z3_controller.add_api_to_sequence(
                                        producer, position=chain_position,
                                        required_types=required, produced_types=produced
                                    )
                                except Exception as e:
                                    logger.debug(f"Z3 rejected after sub-chain: {e}")
                                    if checkpoint is not None:
                                        self.z3_controller.rollback_to(checkpoint)
                                    continue

                            chain_position += 1
                            init_chain.append((producer_call, new_ctx))
                            current_ctx = new_ctx
                            break

                # Rollback Z3 state if we didn't break
                if self.z3_controller and checkpoint is not None:
                    self.z3_controller.rollback_to(checkpoint)

        return init_chain if init_chain else None

    def _track_api_in_z3(self, api: Api, position: int):
        """
        Track an API addition in the Z3 controller state.

        Idempotent on ``api.function_name``: the constraint model assigns one
        order var per API, so re-tracking the same name at a new position
        would surface as a (correct) UNSAT. The init-chain recursion can
        produce a chain that revisits an already-added API; silently skip
        such re-tracks at the boundary so callers don't have to know.

        Args:
            api: API object being added to the sequence
            position: Position in the sequence
        """
        if not self.enable_z3_guidance or not self.z3_controller:
            return

        if api.function_name in self.z3_controller.solver.api_sequence:
            logger.debug(
                f"[Z3Guided] API {api.function_name} already tracked, "
                f"skipping re-track at position {position}"
            )
            return

        try:
            required = self._get_required_types(api)
            produced = self._get_produced_types(api)
            self.z3_controller.add_api_to_sequence(
                api, position=position,
                required_types=required, produced_types=produced
            )
            logger.debug(f"[Z3Guided] Tracked API {api.function_name} at position {position}")
        except Exception as e:
            if self.z3_strict_mode:
                raise
            logger.debug(f"[Z3Guided] Failed to track API {api.function_name}: {e}")

    def _evaluate_candidates_with_z3(self, candidates: List[Tuple[ApiCall, RunningContext, Api]],
                                     current_position: int) -> List[Tuple[ApiCall, RunningContext, Api, float]]:
        """
        Evaluate candidate APIs using Z3 and return them with scores.

        Args:
            candidates: List of (api_call, context, api) tuples
            current_position: Current position in the sequence

        Returns:
            List of (api_call, context, api, score) tuples, sorted by score
        """
        if not self.enable_z3_guidance or not self.z3_controller:
            # Return with default scores
            return [(call, ctx, api, 0.0) for call, ctx, api in candidates]

        scored = []
        for api_call, ctx, api in candidates:
            required = self._get_required_types(api)
            produced = self._get_produced_types(api)

            result = self.z3_controller.solver.check_candidate(
                api.function_name, required, produced
            )

            if result.is_feasible:
                score = result.score + self._compute_api_complexity(api)
                scored.append((api_call, ctx, api, score))
            else:
                # Still include but with high score (low priority)
                score = 100.0 + self._compute_api_complexity(api)
                scored.append((api_call, ctx, api, score))

        # Sort by score (lower is better)
        scored.sort(key=lambda x: x[3])
        return scored

    def _try_all_source_apis(self, rng_ctx: RunningContext) -> Optional[Tuple[Api, ApiCall, RunningContext, List]]:
        """
        Try all source APIs and return the first one that can be instantiated,
        or the one with the fewest unsatisfied variables for backtracking.

        Uses Z3-guided selection when enabled, falls back to random selection otherwise.

        Returns:
            (api, api_call, context, init_chain) on success, or
            (best_api, None, None, unsat_vars) if all failed
        """
        get_cond = lambda x: self.conditions.get_function_conditions(x.function_name)
        to_api = lambda x: Factory.api_to_apicall(x)

        # Prepare source API candidates
        if self.enable_z3_guidance and self.z3_controller:
            # Z3-guided: evaluate and rank source APIs
            self.z3_controller.reset()
            candidates = []
            for api in self.source_api:
                required = self._get_required_types(api)
                produced = self._get_produced_types(api)
                result = self.z3_controller.solver.check_candidate(
                    api.function_name, required, produced
                )
                if result.is_feasible:
                    score = result.score + self._compute_api_complexity(api)
                    candidates.append((api, score))
                    logger.debug(f"[Z3] Source {api.function_name} feasible, score={score:.2f}")
                else:
                    logger.debug(f"[Z3] Source {api.function_name} not feasible")

            candidates.sort(key=lambda x: x[1])
            if not candidates:
                # Fallback: use all sources with random order
                candidates = [(api, 0.0) for api in self.source_api]
                random.shuffle(candidates)
        else:
            # Non-guided: random order
            shuffled = list(self.source_api)
            random.shuffle(shuffled)
            candidates = [(api, 0.0) for api in shuffled]

        best_api = None
        best_unsat = None
        min_unsat_count = float('inf')

        for api, score in candidates:
            api_cond = get_cond(api)
            api_call = to_api(api)

            # Create Z3 checkpoint if available
            checkpoint = None
            if self.z3_controller:
                checkpoint = self.z3_controller.checkpoint()

            new_ctx, unsat_vars = self.try_to_instantiate_api_call(
                api_call, api_cond, rng_ctx
            )

            if len(unsat_vars) == 0:
                # Success
                if self.z3_controller:
                    required = self._get_required_types(api)
                    produced = self._get_produced_types(api)
                    self.z3_controller.add_api_to_sequence(
                        api, position=0, required_types=required, produced_types=produced
                    )
                logger.debug(f"Source API {api.function_name} instantiated")
                return (api, api_call, new_ctx, [])

            # Track best candidate
            if len(unsat_vars) < min_unsat_count:
                min_unsat_count = len(unsat_vars)
                best_api = api
                best_unsat = unsat_vars

            # Rollback Z3 state
            if self.z3_controller and checkpoint is not None:
                self.z3_controller.rollback_to(checkpoint)

        # Try backtracking on best candidate
        if best_api is not None and best_unsat is not None:
            logger.info(f"Attempting init chain for {best_api.function_name} "
                       f"({len(best_unsat)} unsat vars)")

            init_chain = self._try_find_init_chain(best_api, best_unsat, rng_ctx)

            if init_chain:
                last_ctx = init_chain[-1][1]
                api_call = to_api(best_api)
                api_cond = get_cond(best_api)

                new_ctx, unsat_vars = self.try_to_instantiate_api_call(
                    api_call, api_cond, last_ctx
                )

                if len(unsat_vars) == 0:
                    logger.info(f"Init chain succeeded for {best_api.function_name}")
                    return (best_api, api_call, new_ctx, init_chain)

        return (best_api, None, None, best_unsat)

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
        Create a random driver that satisfies constraints.

        Uses initialization chain backtracking when direct instantiation fails:
        1. Try all source APIs (with Z3 guidance if enabled)
        2. For the best candidate (fewest unsat vars), try to build init chain
        3. Prepend init chain APIs to the driver
        4. Continue adding APIs with Z3-guided candidate selection
        """
        rng_ctx = RunningContext()

        get_cond = lambda x: self.conditions.get_function_conditions(x.function_name)
        to_api = lambda x: Factory.api_to_apicall(x)

        if len(self.source_api) == 0:
            raise Exception("I cannot find APIs to begin with :(")

        # Reset Z3 controller for new driver synthesis
        if self.enable_z3_guidance and self.z3_controller:
            self.z3_controller.reset()
            logger.debug("[Z3Guided] Controller reset for new driver synthesis")

        # List[(ApiCall, RunningContext)]
        drv = list()
        current_position = 0  # Track position for Z3

        # Try all source APIs with backtracking support
        result = self._try_all_source_apis(rng_ctx)
        begin_api, call_begin, rng_ctx_1, init_chain_or_unsat = result

        if call_begin is None or rng_ctx_1 is None:
            # All source APIs failed even with backtracking
            logger.error(f"Cannot instantiate any source API. Best candidate: "
                        f"{begin_api.function_name if begin_api else 'None'}, "
                        f"unsat vars: {init_chain_or_unsat}")
            raise Exception(f"Cannot instantiate any source API. "
                           f"Best candidate had unsat vars: {init_chain_or_unsat}")

        # Add init chain APIs first (if any)
        if init_chain_or_unsat:  # This is the init_chain list when successful
            for init_call, init_ctx in init_chain_or_unsat:
                logger.debug(f"Adding init chain API: {init_call.function_name}")
                drv.append((init_call, init_ctx))
                # Track in Z3 (find the Api object)
                init_api = self.api_name_to_api.get(init_call.function_name)
                if init_api:
                    self._track_api_in_z3(init_api, current_position)
                current_position += 1

        logger.debug(f"Starting with {call_begin.function_name}")
        drv.append((call_begin, rng_ctx_1))
        self._track_api_in_z3(begin_api, current_position)
        current_position += 1

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
                # Use Z3 to evaluate and rank candidates if enabled
                if self.enable_z3_guidance and self.z3_controller and len(candidate_api) > 1:
                    scored_candidates = self._evaluate_candidates_with_z3(candidate_api, current_position)
                    # Pick the best candidate (lowest score)
                    api_call, rng_ctx_1, api_n, score = scored_candidates[0]
                    logger.debug(f"[Z3Guided] Choose {api_call.function_name} (score={score:.2f})")
                else:
                    # (ApiCall, RunningContext, Api)
                    (api_call, rng_ctx_1, api_n) = self.get_random_candidate(candidate_api)
                    logger.debug(f"Choose {api_call.function_name}")

                drv.append((api_call, rng_ctx_1))
                self._track_api_in_z3(api_n, current_position)
                current_position += 1
            else:
                # Start new chain - use backtracking mechanism
                logger.debug("Starting new chain with backtracking support")

                # Use the current context for the new chain attempt
                result = self._try_all_source_apis(rng_ctx_1)
                new_api, new_call, new_ctx, chain_or_unsat = result

                if new_call is None or new_ctx is None:
                    # Failed to find any working source API
                    # Try a simpler fallback: just pick a random one and continue
                    # This allows partial drivers to be generated
                    logger.warning(f"New chain backtracking failed for {new_api.function_name if new_api else 'None'}, "
                                  f"trying simple fallback")

                    # Simple fallback: try each source API once without backtracking
                    fallback_success = False
                    for fallback_api in self.source_api:
                        fallback_cond = get_cond(fallback_api)
                        fallback_call = to_api(fallback_api)
                        fallback_ctx, fallback_unsat = self.try_to_instantiate_api_call(
                            fallback_call, fallback_cond, rng_ctx_1)
                        if len(fallback_unsat) == 0:
                            api_n = fallback_api
                            rng_ctx_1 = fallback_ctx
                            drv.append((fallback_call, rng_ctx_1))
                            self._track_api_in_z3(fallback_api, current_position)
                            current_position += 1
                            fallback_success = True
                            logger.debug(f"Fallback succeeded with {fallback_api.function_name}")
                            break

                    if not fallback_success:
                        logger.error(f"Cannot start new chain, all source APIs failed")
                        # Instead of raising, break the loop and return partial driver
                        logger.warning(f"Returning partial driver with {len(drv)} API calls")
                        break
                else:
                    # Success - add any init chain APIs
                    if chain_or_unsat:
                        for init_call, init_ctx in chain_or_unsat:
                            logger.debug(f"Adding new chain init API: {init_call.function_name}")
                            drv.append((init_call, init_ctx))
                            # Track in Z3
                            init_api = self.api_name_to_api.get(init_call.function_name)
                            if init_api:
                                self._track_api_in_z3(init_api, current_position)
                            current_position += 1

                    api_n = new_api
                    rng_ctx_1 = new_ctx
                    drv.append((new_call, rng_ctx_1))
                    self._track_api_in_z3(new_api, current_position)
                    current_position += 1
                    logger.debug(f"Starting new chain with {new_api.function_name}")

        # Use the last RunningContext
        context = [rng_ctx for _, rng_ctx in drv][-1]

        # Z3 Validation: Check if the generated sequence is feasible
        if self.enable_z3_validation and self.z3_validator:
            # Extract API sequence for validation
            api_sequence = []
            for api_call, _ in drv:
                # Find the original Api object from api_list
                for api in self.api_list:
                    if api.function_name == api_call.function_name:
                        api_sequence.append(api)
                        break

            is_valid, violations = self.validate_sequence_with_z3(api_sequence)
            if not is_valid:
                violation_str = ", ".join(violations[:3]) if violations else "unknown"
                logger.warning(f"Z3 validation failed for sequence: {violation_str}")
                raise Exception(f"Z3 validation failed: sequence violates constraints ({violation_str})")

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

    # ========== Skeleton Mode Methods ==========

    def create_random_driver_skeleton(self) -> Optional['DriverSkeleton']:
        """
        Create a random driver skeleton with holes instead of complete driver.

        This method generates a structurally correct driver skeleton that:
        - Has the correct API call sequence
        - Has type-safe variable declarations
        - Marks uncertain parts (callbacks, buffer sizes, etc.) as holes

        Returns:
            DriverSkeleton with holes to be filled by LLM, or None if skeleton
            generation is not available.
        """
        if not SKELETON_AVAILABLE:
            logger.warning("Skeleton generation not available")
            return None

        # Generate API sequence using existing logic
        api_sequence = self._generate_api_sequence()
        if not api_sequence:
            logger.warning("Failed to generate API sequence for skeleton")
            return None

        # Create skeleton from sequence
        return self._create_skeleton_from_sequence(api_sequence)

    def _generate_api_sequence(self) -> List[Api]:
        """
        Generate a valid API sequence using constraint-based selection.

        This extracts the sequence generation logic from create_random_driver()
        to be reusable for skeleton generation.

        Returns:
            List of Api objects forming a valid sequence.
        """
        rng_ctx = RunningContext()

        get_cond = lambda x: self.conditions.get_function_conditions(x.function_name)
        to_api = lambda x: Factory.api_to_apicall(x)

        if len(self.source_api) == 0:
            logger.error("No source APIs available")
            return []

        # Reset Z3 controller for new sequence
        if self.enable_z3_guidance and self.z3_controller:
            self.z3_controller.reset()

        api_sequence = []
        current_position = 0

        # Try all source APIs with backtracking support
        result = self._try_all_source_apis(rng_ctx)
        begin_api, call_begin, rng_ctx_1, init_chain_or_unsat = result

        if call_begin is None or rng_ctx_1 is None:
            logger.error("Cannot instantiate any source API")
            return []

        # Add init chain APIs first (if any)
        if init_chain_or_unsat:
            for init_call, init_ctx in init_chain_or_unsat:
                init_api = self.api_name_to_api.get(init_call.function_name)
                if init_api:
                    api_sequence.append(init_api)
                current_position += 1

        # Add the source API
        api_sequence.append(begin_api)
        current_position += 1

        api_n = begin_api
        while len(api_sequence) < self.driver_size:
            candidate_api = []

            if api_n in self.dependency_graph:
                for next_possible in self.dependency_graph[api_n]:
                    if next_possible in self.source_api:
                        continue

                    next_condition = get_cond(next_possible)
                    call_next = to_api(next_possible)

                    rng_ctx_2, unsat_var_2 = self.try_to_instantiate_api_call(
                        call_next, next_condition, rng_ctx_1)

                    if len(unsat_var_2) == 0:
                        candidate_api.append((call_next, rng_ctx_2, next_possible))

            # Avoid repeated single API
            if len(candidate_api) == 1 and candidate_api[0][2] == api_n:
                candidate_api = []

            if candidate_api:
                if self.enable_z3_guidance and self.z3_controller and len(candidate_api) > 1:
                    scored = self._evaluate_candidates_with_z3(candidate_api, current_position)
                    api_call, rng_ctx_1, api_n, score = scored[0]
                else:
                    (api_call, rng_ctx_1, api_n) = self.get_random_candidate(candidate_api)

                api_sequence.append(api_n)
                current_position += 1
            else:
                # Start new chain
                result = self._try_all_source_apis(rng_ctx_1)
                new_api, new_call, new_ctx, chain_or_unsat = result

                if new_call is None or new_ctx is None:
                    # Simple fallback
                    for fallback_api in self.source_api:
                        fallback_cond = get_cond(fallback_api)
                        fallback_call = to_api(fallback_api)
                        fallback_ctx, fallback_unsat = self.try_to_instantiate_api_call(
                            fallback_call, fallback_cond, rng_ctx_1)
                        if len(fallback_unsat) == 0:
                            api_n = fallback_api
                            rng_ctx_1 = fallback_ctx
                            api_sequence.append(fallback_api)
                            current_position += 1
                            break
                    else:
                        # No valid continuation, return partial sequence
                        break
                else:
                    # Add init chain APIs
                    if chain_or_unsat:
                        for init_call, init_ctx in chain_or_unsat:
                            init_api = self.api_name_to_api.get(init_call.function_name)
                            if init_api:
                                api_sequence.append(init_api)
                            current_position += 1

                    api_n = new_api
                    rng_ctx_1 = new_ctx
                    api_sequence.append(new_api)
                    current_position += 1

        return api_sequence

    def create_skeleton_for_sequence(
        self, target_seq: List[Api], dep_model=None
    ) -> Optional['DriverSkeleton']:
        """
        Generate a Z3-validated DriverSkeleton (with holes) for a SPECIFIC
        API sequence supplied by the caller.

        This is the program-synthesis-as-precondition path used by
        ``data_context.py`` Step 10 to upgrade the per-sequence base
        drivers from "pattern-rendered" to "constraint-validated":

          - **Viability is decided by the constraint solver, not by an
            arbitrary numeric cap**. ``validate_sequence_with_z3`` returns
            False when the sequence cannot satisfy type / lifecycle /
            provenance constraints — we drop those sequences silently
            (the caller's filtered list shrinks naturally).
          - **The skeleton structure is correct by construction** because
            ``_create_skeleton_from_sequence`` reuses the same
            ``varlen_relations`` extracted from CBFactory's conditions
            (which are themselves derived from LLVM IR analysis).
          - **Holes mark the parts that need LLM judgment** — callbacks,
            buffer sizes, loop conditions. The LLM refines the skeleton
            (PromeFuzz-aligned scaffolding pattern) instead of generating
            from scratch.

        Differs from ``create_random_driver_skeleton()`` (which calls
        ``_generate_api_sequence`` to RANDOMLY pick a source API + walk
        the dependency graph). Here we honor the caller's sequence and
        use Z3 only to *validate*.

        Args:
            target_seq: Caller-provided list of Api objects (e.g. one
                of the L4-validated viable sequences).

        Returns:
            DriverSkeleton with holes if the sequence passes Z3
            validation; None if Z3 rejects (caller treats as "this
            specific sequence is infeasible, skip").
        """
        if not SKELETON_AVAILABLE:
            logger.warning("Skeleton generation not available (SKELETON_AVAILABLE=False)")
            return None
        if not target_seq:
            return None
        is_valid, violations = self.validate_sequence_with_z3(target_seq)
        if not is_valid:
            logger.info(
                "Z3 rejected viable-candidate sequence %s; first violations: %s",
                [api.function_name for api in target_seq],
                violations[:3],
            )
            return None
        return self._create_skeleton_from_sequence(target_seq, dep_model=dep_model)

    def create_skeleton_unchecked(
        self, target_seq: List[Api], dep_model=None
    ) -> Optional['DriverSkeleton']:
        """Render a skeleton for a sequence WITHOUT the Z3 / RunningContext
        provenance gate (redesign G5 follow-through).

        Rationale (first-principles): the reconciled semantic model already
        tells us each argument's *source* — a handle (use a prior producer's
        return), a fuzzer buffer, a length, an output local, or a scalar
        config. Writing the driver is a per-arg role lookup; it does NOT
        require Z3 to *prove* provenance for every argument.
        ``create_skeleton_for_sequence`` rejects a whole sequence the moment
        RunningContext can't bind one scalar/``void*`` (lcms
        ``cmsCreateTransform`` / ``cmsBuildGamma``) — which silently drops the
        very baseline-uncovered (gap) APIs we most want to reach.

        This path keeps Z3 as an *optional* confirmation only: it wires handle
        args to prior producers by type-match (single-pointer types,
        including opaque ``void*`` handles) and leaves every other arg as a
        ``SkeletonGenerator`` hole for the LLM to fill (guided by G4 value
        intents). It never rejects — every non-empty sequence yields a
        skeleton. Z3-clean sequences still go through
        ``create_skeleton_for_sequence``; this is the fallback that recovers
        the rest.
        """
        if not SKELETON_AVAILABLE or not target_seq:
            return None
        bindings = self._signature_handle_bindings(target_seq, dep_model=dep_model)
        varlen_relations = self._extract_varlen_relations(target_seq)
        generator = SkeletonGenerator()
        skeleton = generator.generate(
            api_sequence=target_seq,
            varlen_relations=varlen_relations,
            driver_name="model_skeleton",
            arg_bindings=bindings,
            dep_model=dep_model,
        )
        skeleton.metadata['synthesis_method'] = 'model_unchecked'
        skeleton.metadata['api_count'] = len(target_seq)
        skeleton.metadata['api_names'] = [a.function_name for a in target_seq]
        return skeleton

    def _signature_handle_bindings(
        self, api_sequence: List[Api], dep_model=None
    ) -> Dict[Tuple[str, int], str]:
        """Wire single-pointer handle args to a prior producer's ``ret_<api>``
        by normalized type-match. Never rejects; returns only the bindings it
        can make (the rest become holes). Out-pointers (``T**``) and fuzzer
        buffers are left to SkeletonGenerator (output local / FUZZ_INPUT).

        I3 (Task 10, LOGICFUZZ_VALIDITY_CONTRACT + ``dep_model``): opaque handle
        typedefs (cmsHPROFILE / cmsHTRANSFORM) both desugar to ``void *`` in the
        IR, so the normalized-type match collapses them and a profile arg can
        bind to the nearest void* producer (a transform). When the model is
        threaded in, recover each consumer arg's handle FAMILY from the model's
        real ``type_str`` and each producer's family from its NAME, and bind by
        FAMILY first. ADDITIVE: the legacy void* match is the FALLBACK whenever
        family info is absent (non-lcms / no model) ⇒ those libs are unchanged.
        """
        from liberator_adapter.analysis.usedef import normalize_handle_type
        from liberator_adapter.analysis.validity_contract import _family
        i3 = bool(dep_model) and _validity_contract_enabled()
        bindings: Dict[Tuple[str, int], str] = {}
        produced: Dict[str, str] = {}   # normalized handle type -> ret var
        # I3: family -> last producer ret var (family from the producer NAME).
        produced_by_family: Dict[str, str] = {}
        cross = _cross_source_bind_enabled()
        ordered: List[Dict[str, Any]] = []   # for the cross-source post-pass

        def _arg_family(api_name: str, j: int) -> Optional[str]:
            """Handle family of (api, arg j) from the model's real type_str."""
            if not i3:
                return None
            sem = dep_model.get(api_name) if hasattr(dep_model, "get") else None
            if sem is None:
                return None
            for a in (getattr(sem, "args", ()) or ()):
                if getattr(a, "index", None) == j:
                    return _family(getattr(a, "type_str", "") or "")
            return None

        for api in api_sequence:
            arg_tokens: Dict[int, str] = {}
            for j, arg in enumerate(getattr(api, 'arguments_info', []) or []):
                t = getattr(arg, 'type', '') or ''
                if t.count('*') == 1:   # single-pointer ⇒ candidate input handle
                    key = normalize_handle_type(t)
                    bound = False
                    # I3: prefer a SAME-FAMILY producer over the collapsed-void*
                    # nearest match. Only overrides when the model knows the
                    # arg's family AND a same-family producer exists.
                    if i3:
                        fam = _arg_family(api.function_name, j)
                        if fam and fam in produced_by_family:
                            bindings[(api.function_name, j)] = \
                                produced_by_family[fam]
                            bound = True
                    if not bound and key and key in produced:
                        bindings[(api.function_name, j)] = produced[key]
                    if cross and key:
                        arg_tokens[j] = key
            ri = getattr(api, 'return_info', None)
            rt = getattr(ri, 'type', '') if ri else ''
            is_prod = bool(rt and rt not in ('void', '') and rt.count('*') == 1)
            ret_token = normalize_handle_type(rt) if is_prod else None
            if is_prod:
                produced[ret_token] = f"ret_{api.function_name}"
                if i3:
                    # Producer family from its NAME (cmsOpenProfileFromMem →
                    # profile, cmsCreateTransform → transform) — the model's
                    # ``produces`` is empty for IR-erased opaque void* returns.
                    pf = _family(api.function_name)
                    if pf:
                        produced_by_family[pf] = f"ret_{api.function_name}"
            if cross:
                ordered.append({
                    "name": api.function_name, "is_producer": is_prod,
                    "ret_token": ret_token, "arg_tokens": arg_tokens,
                })
        if cross:
            # Re-point a CREATOR's repeated same-type handle arg to a DISTINCT
            # earlier producer (cross-profile transform). Legacy ``produced``
            # keeps only the LAST producer per type → both same-type args
            # collapse to one; this restores the cross-source pairing.
            bindings = _distribute_cross_source(bindings, ordered)
        return bindings

    def _create_skeleton_from_sequence(self, api_sequence: List[Api], dep_model=None) -> Optional['DriverSkeleton']:
        """
        Convert an API sequence to a skeleton with holes.

        The variable wiring (which arg references which prior call's
        return) is computed by upstream's
        ``RunningContext.try_to_get_var`` machinery — we drive it via
        ``try_to_instantiate_api_call`` per API in the caller's sequence.
        That gives us:
          1. Validation by construction: if any API fails to instantiate
             (unsat vars), the sequence is genuinely infeasible — return
             None directly.
          2. A precomputed wiring map: ``(api_name, arg_idx) -> ret_<prev>``
             when an arg reuses a prior call's return value. Passed to
             SkeletonGenerator as ``arg_bindings``; the generator just
             renders.

        See ``CLAUDE.md`` Design Principles ("Reuse upstream Liberator")
        and the module-level comment in ``skeleton_generator.py``.

        Args:
            api_sequence: List of Api objects to generate skeleton for

        Returns:
            DriverSkeleton with holes, or None when the sequence is
            infeasible under upstream's variable-binding semantics.
        """
        # Step 1: drive RunningContext over the caller's sequence and
        # extract a (api_name, arg_idx) -> wired-text map. Returns None
        # when any API is infeasible.
        bindings = self._compute_arg_bindings_via_running_context(api_sequence)
        if bindings is None:
            return None

        # Step 2: SkeletonGenerator owns the rendering layer. It receives
        # the upstream-computed bindings and applies them to consumer-arg
        # init_value, leaving Holes for callbacks / buffer sizes etc.
        varlen_relations = self._extract_varlen_relations(api_sequence)
        generator = SkeletonGenerator()
        skeleton = generator.generate(
            api_sequence=api_sequence,
            varlen_relations=varlen_relations,
            driver_name="cbfactory_skeleton",
            arg_bindings=bindings,
            dep_model=dep_model,
        )

        skeleton.metadata['synthesis_method'] = 'CBFactory'
        skeleton.metadata['api_count'] = len(api_sequence)
        skeleton.metadata['api_names'] = [api.function_name for api in api_sequence]

        return skeleton

    def _compute_arg_bindings_via_running_context(
        self, api_sequence: List[Api]
    ) -> Optional[Dict[Tuple[str, int], str]]:
        """Drive ``try_to_instantiate_api_call`` over a fixed sequence and
        translate the resulting Variable identities to SkeletonGenerator's
        ``ret_<api>`` naming.

        The upstream contract: ``try_to_instantiate_api_call(call, cond,
        rng_ctx)`` mutates ``call.arg_vars`` and ``call.ret_var``, picking
        existing live variables when a sink/init/setby category matches.
        When it picks a *prior call's* return value, that's the wiring
        signal we want — the consumer arg is reusing the producer's
        output.

        We resolve via Python identity: each prior ``ApiCall.ret_var``
        (unwrapped from Address) is recorded; when a later call's
        ``arg_vars[j]`` resolves (also unwrapped) to that same Variable
        object, we emit ``bindings[(api, j)] = "ret_<prev_api>"``.

        Returns:
            ``{(api_name, arg_idx): wired_text}`` on success (possibly
            empty if no cross-API reuse occurred), or ``None`` if any
            API in the sequence is infeasible per upstream's binding
            rules.
        """
        if not api_sequence:
            return {}

        seq_names = [a.function_name for a in api_sequence]
        rng_ctx = RunningContext()
        drv_calls: List[Tuple[Api, ApiCall]] = []

        for pos, api in enumerate(api_sequence):
            try:
                cond = self.conditions.get_function_conditions(api.function_name)
            except KeyError:
                # Missing FunctionConditions for this API — upstream
                # cannot wire it. Treat as infeasible on this path.
                # (get_function_conditions raises KeyError, never returns None.)
                logger.info(
                    "[CBFactory.binding] reject seq=%s at pos=%d (%s): "
                    "no FunctionConditions for this API",
                    seq_names, pos, api.function_name,
                )
                return None
            call = Factory.api_to_apicall(api)
            try:
                rng_ctx_next, unsat = self.try_to_instantiate_api_call(
                    call, cond, rng_ctx)
            except Exception as exc:
                logger.info(
                    "[CBFactory.binding] reject seq=%s at pos=%d (%s): "
                    "try_to_instantiate_api_call crashed: %s: %s",
                    seq_names, pos, api.function_name,
                    type(exc).__name__, exc,
                )
                return None
            if unsat:
                # ``unsat`` is a Set[Variable] (per try_to_instantiate_api_call
                # return type) — iterate, don't slice. Take the first ≤5
                # via iteration so set / list / tuple all work uniformly.
                unsat_iter = iter(unsat)
                sample = []
                for _ in range(5):
                    try:
                        v = next(unsat_iter)
                    except StopIteration:
                        break
                    try:
                        sample.append(str(v)[:80])
                    except Exception:
                        sample.append(f"<{type(v).__name__}>")
                logger.info(
                    "[CBFactory.binding] reject seq=%s at pos=%d (%s): "
                    "RunningContext has %d unsat var(s); sample=%s",
                    seq_names, pos, api.function_name,
                    len(unsat), sample,
                )
                return None
            drv_calls.append((api, call))
            rng_ctx = rng_ctx_next

        # Build a map: id(Variable) -> producer api_name.
        # We only consider direct Variable returns. NullConstant returns
        # don't enter the map (no name to reuse).
        var_id_to_producer: Dict[int, str] = {}
        for prev_api, prev_call in drv_calls:
            ret = prev_call.ret_var
            if ret is None:
                continue
            base = ret.get_variable() if isinstance(ret, Address) else ret
            if isinstance(base, Variable):
                var_id_to_producer[id(base)] = prev_api.function_name

        # Walk each call's args; emit a binding when an arg resolves to
        # a known prior producer (and isn't this call's own ret).
        bindings: Dict[Tuple[str, int], str] = {}
        for api, call in drv_calls:
            for j, arg_var in enumerate(call.arg_vars):
                if arg_var is None:
                    continue
                base = arg_var
                if isinstance(arg_var, Address):
                    base = arg_var.get_variable()
                if not isinstance(base, Variable):
                    continue
                producer = var_id_to_producer.get(id(base))
                if producer is None or producer == api.function_name:
                    continue
                bindings[(api.function_name, j)] = f"ret_{producer}"

        if _cross_source_bind_enabled():
            # LOGICFUZZ_CROSS_SOURCE_BIND post-pass: a CREATOR's repeated same-
            # type handle args were bound to ONE producer above (upstream defers
            # context update until all args resolve). Re-point the 2nd to a
            # DISTINCT earlier producer of that type — the construction-injected
            # synthetic profile — so the transform is CROSS-profile, not same-
            # profile (~identity). Built from the resolved Variable type tokens
            # so it respects upstream's opaque-handle (i8*) typing.
            ordered: List[Dict[str, Any]] = []
            for api, call in drv_calls:
                ret = call.ret_var
                rbase = ret.get_variable() if isinstance(ret, Address) else ret
                is_prod = isinstance(rbase, Variable)
                ret_token = None
                if is_prod:
                    try:
                        ret_token = rbase.get_type().get_token()
                    except Exception:
                        ret_token = None
                arg_tokens: Dict[int, str] = {}
                for j, av in enumerate(call.arg_vars):
                    if av is None:
                        continue
                    ab = av.get_variable() if isinstance(av, Address) else av
                    if isinstance(ab, Variable):
                        try:
                            arg_tokens[j] = ab.get_type().get_token()
                        except Exception:
                            pass
                ordered.append({
                    "name": api.function_name, "is_producer": is_prod,
                    "ret_token": ret_token, "arg_tokens": arg_tokens,
                })
            bindings = _distribute_cross_source(bindings, ordered)

        return bindings

    def _extract_varlen_relations(self, api_sequence: List[Api]) -> Dict[str, List[Tuple[int, int, str]]]:
        """
        Extract var-len (buffer-size) relationships from CBFactory conditions.

        These relationships indicate which parameters represent buffer pointers
        and which represent their sizes.

        Args:
            api_sequence: List of Api objects

        Returns:
            Dict mapping api_name to list of (buffer_idx, length_idx, relationship) tuples
        """
        relations = {}

        for api in api_sequence:
            api_relations = []
            cond = self.conditions_map.get(api.function_name)

            if cond:
                for arg_idx, arg_cond in enumerate(cond.argument_at):
                    if arg_cond.len_depends_on and arg_cond.len_depends_on != "":
                        try:
                            len_idx = int(arg_cond.len_depends_on.replace("param_", ""))
                            api_relations.append((arg_idx, len_idx, ">="))
                        except ValueError:
                            pass

            if api_relations:
                relations[api.function_name] = api_relations

        return relations
