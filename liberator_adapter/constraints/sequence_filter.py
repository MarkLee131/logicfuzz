"""
API Sequence Filter - LLM-based filtering

Uses LLM for semantic filtering of API sequences, without relying on hardcoded heuristic rules.

Design principles:
1. Do not use static analysis heuristic rules (avoid false positives)
2. Use LLM to understand API semantics
3. Validate based on API lifecycle
"""

import logging
from enum import Enum
from typing import List, Tuple, Optional, Dict, Any, Protocol
from dataclasses import dataclass, field

from liberator_adapter.common.api import Api
from liberator_adapter.common.conditions import FunctionConditionsSet
from liberator_adapter.prompt_loader import get_prompt_manager
from llm_toolkit.adapter import create_llm_adapter

logger = logging.getLogger(__name__)


# =============================================================================
# LLM Client Protocol
# =============================================================================

class LLMClient(Protocol):
    """LLM client protocol"""
    def query(self, prompt: str) -> str:
        """Send prompt and return response"""
        ...


# =============================================================================
# Data Structures
# =============================================================================

class APILifecyclePhase(Enum):
    """API lifecycle phase"""
    CREATE = "create"       # Create/allocate resources
    INIT = "init"           # Initialize resources
    USE = "use"             # Use resources (read/write/transform)
    CLEANUP = "cleanup"     # Cleanup/release resources
    UNKNOWN = "unknown"     # Unknown


@dataclass
class APILifecycleInfo:
    """API lifecycle information"""
    api_name: str
    phase: APILifecyclePhase
    resource_type: Optional[str] = None  # Resource type being operated on
    reasoning: str = ""                  # Reasoning basis


@dataclass
class FilterResult:
    """Filter result"""
    is_valid: bool
    reason: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

    @staticmethod
    def valid() -> 'FilterResult':
        return FilterResult(is_valid=True)

    @staticmethod
    def invalid(reason: str, details: Optional[Dict[str, Any]] = None) -> 'FilterResult':
        return FilterResult(is_valid=False, reason=reason, details=details)


@dataclass
class LifecycleValidationResult:
    """Lifecycle validation result"""
    is_valid: bool
    violations: List[str] = field(default_factory=list)
    lifecycle_info: List[APILifecycleInfo] = field(default_factory=list)
    reasoning: str = ""


# =============================================================================
# LLM-based API Lifecycle Classifier
# =============================================================================

class LLMLifecycleValidator:
    """
    LLM-based API lifecycle validator

    Completely relies on LLM to understand API semantics, does not use hardcoded heuristic rules.
    """

    def __init__(self, llm_client: Optional[LLMClient] = None):
        """
        Args:
            llm_client: LLM client, needs to implement query(prompt) -> str method
        """
        self.llm_client = llm_client
        self._cache: Dict[str, APILifecycleInfo] = {}

    def set_llm_client(self, llm_client: LLMClient):
        """Set LLM client"""
        self.llm_client = llm_client

    def classify_api(self, api: Api) -> APILifecycleInfo:
        """
        Use LLM to classify single API's lifecycle phase

        Args:
            api: API object

        Returns:
            APILifecycleInfo: Lifecycle information
        """
        # Check cache
        if api.function_name in self._cache:
            return self._cache[api.function_name]

        # No LLM client, return UNKNOWN
        if self.llm_client is None:
            return APILifecycleInfo(
                api_name=api.function_name,
                phase=APILifecyclePhase.UNKNOWN,
                reasoning="No LLM client available"
            )

        result = self._llm_classify_single(api)
        self._cache[api.function_name] = result
        return result

    def classify_batch(self, apis: List[Api]) -> List[APILifecycleInfo]:
        """
        Batch classify APIs (more efficient)

        Args:
            apis: API list

        Returns:
            List of classification results
        """
        if not apis:
            return []

        # Check which ones need classification
        uncached = [api for api in apis if api.function_name not in self._cache]

        if uncached and self.llm_client:
            # Batch call LLM
            batch_results = self._llm_classify_batch(uncached)
            for info in batch_results:
                self._cache[info.api_name] = info

        # Return all results (from cache)
        return [
            self._cache.get(
                api.function_name,
                APILifecycleInfo(api.function_name, APILifecyclePhase.UNKNOWN),
            )
            for api in apis
        ]

    def validate_sequence(self, sequence: List[Api]) -> LifecycleValidationResult:
        """
        Validate API sequence lifecycle validity

        Completely uses LLM for semantic validation, does not use hardcoded rules.

        Args:
            sequence: API sequence

        Returns:
            LifecycleValidationResult: Validation result
        """
        if not sequence:
            return LifecycleValidationResult(is_valid=True)

        if self.llm_client is None:
            # No LLM, cannot validate, default to pass
            return LifecycleValidationResult(
                is_valid=True,
                reasoning="No LLM client available, skipping validation"
            )

        # First get lifecycle classification (for result return)
        lifecycle_infos = self.classify_batch(sequence)

        # Use LLM to validate sequence
        return self._llm_validate_sequence(sequence, lifecycle_infos)

    def _llm_classify_single(self, api: Api) -> APILifecycleInfo:
        """Use LLM to classify single API"""
        params_desc = ", ".join([
            f"{arg.type} {arg.name}" for arg in api.arguments_info
        ]) or "void"

        signature = f"{api.return_info.type} {api.function_name}({params_desc})"

        # Use prompt_loader to get prompt
        pm = get_prompt_manager()
        prompt = pm.get_lifecycle_classify_prompt(
            api_name=api.function_name,
            signature=signature,
            return_type=api.return_info.type,
            parameters=params_desc
        )

        try:
            response = self.llm_client.query(prompt)  # type: ignore
            result = self._parse_json_response(response)

            phase_map = {
                "CREATE": APILifecyclePhase.CREATE,
                "INIT": APILifecyclePhase.INIT,
                "USE": APILifecyclePhase.USE,
                "CLEANUP": APILifecyclePhase.CLEANUP,
                "UNKNOWN": APILifecyclePhase.UNKNOWN,
            }

            return APILifecycleInfo(
                api_name=api.function_name,
                phase=phase_map.get(result.get("phase", "UNKNOWN"), APILifecyclePhase.UNKNOWN),
                resource_type=result.get("resource_type"),
                reasoning=result.get("reasoning", "")
            )
        except Exception as e:
            logger.warning(f"LLM classification failed for {api.function_name}: {e}")
            return APILifecycleInfo(
                api_name=api.function_name,
                phase=APILifecyclePhase.UNKNOWN,
                reasoning=f"LLM error: {e}"
            )

    def _llm_classify_batch(self, apis: List[Api]) -> List[APILifecycleInfo]:
        """Use LLM to batch classify APIs"""
        # Build API list description
        api_descriptions = []
        for i, api in enumerate(apis):
            params = ", ".join([f"{arg.type} {arg.name}" for arg in api.arguments_info]) or "void"
            sig = f"{api.return_info.type} {api.function_name}({params})"
            api_descriptions.append(f"{i+1}. {sig}")

        # Use prompt_loader to get prompt
        pm = get_prompt_manager()
        prompt = pm.get_lifecycle_batch_classify_prompt(
            api_list="\n".join(api_descriptions)
        )

        try:
            response = self.llm_client.query(prompt)  # type: ignore
            result = self._parse_json_response(response)

            phase_map = {
                "CREATE": APILifecyclePhase.CREATE,
                "INIT": APILifecyclePhase.INIT,
                "USE": APILifecyclePhase.USE,
                "CLEANUP": APILifecyclePhase.CLEANUP,
                "UNKNOWN": APILifecyclePhase.UNKNOWN,
            }

            infos = []
            classifications = result.get("classifications", [])

            # Match results by API name
            api_name_to_api = {api.function_name: api for api in apis}

            for cls in classifications:
                api_name = cls.get("api_name", "")
                if api_name in api_name_to_api:
                    infos.append(APILifecycleInfo(
                        api_name=api_name,
                        phase=phase_map.get(cls.get("phase", "UNKNOWN"), APILifecyclePhase.UNKNOWN),
                        resource_type=cls.get("resource_type"),
                        reasoning=""
                    ))

            # Supplement unclassified APIs
            classified_names = {info.api_name for info in infos}
            for api in apis:
                if api.function_name not in classified_names:
                    infos.append(APILifecycleInfo(
                        api_name=api.function_name,
                        phase=APILifecyclePhase.UNKNOWN,
                        reasoning="Not in LLM response"
                    ))

            return infos

        except Exception as e:
            logger.warning(f"Batch LLM classification failed: {e}")
            return [
                APILifecycleInfo(api.function_name, APILifecyclePhase.UNKNOWN)
                for api in apis
            ]

    def _llm_validate_sequence(self, sequence: List[Api],
                                lifecycle_infos: List[APILifecycleInfo]) -> LifecycleValidationResult:
        """Use LLM to validate sequence"""
        # Build sequence description
        api_descriptions = []
        for i, (api, info) in enumerate(zip(sequence, lifecycle_infos)):
            params = ", ".join([f"{arg.type} {arg.name}" for arg in api.arguments_info]) or "void"
            sig = f"{api.return_info.type} {api.function_name}({params})"
            phase_str = f"[{info.phase.value}]" if info.phase != APILifecyclePhase.UNKNOWN else ""
            api_descriptions.append(f"{i+1}. {sig} {phase_str}")

        # Use prompt_loader to get prompt
        pm = get_prompt_manager()
        prompt = pm.get_lifecycle_validate_prompt(
            api_sequence="\n".join(api_descriptions)
        )

        try:
            response = self.llm_client.query(prompt)  # type: ignore
            result = self._parse_json_response(response)

            return LifecycleValidationResult(
                is_valid=result.get("is_valid", True),
                violations=result.get("violations", []),
                lifecycle_info=lifecycle_infos,
                reasoning=result.get("reasoning", "")
            )

        except Exception as e:
            logger.warning(f"LLM sequence validation failed: {e}")
            return LifecycleValidationResult(
                is_valid=True,  # Default to pass on error, avoid false positives
                reasoning=f"LLM error: {e}",
                lifecycle_info=lifecycle_infos
            )

    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM's JSON response"""
        import json
        import re

        # Try direct parsing
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # Try extracting JSON block
        json_patterns = [
            r'```json\s*([\s\S]*?)\s*```',
            r'```\s*([\s\S]*?)\s*```',
            r'\{[\s\S]*\}',
        ]

        for pattern in json_patterns:
            match = re.search(pattern, response)
            if match:
                try:
                    json_str = match.group(1) if '```' in pattern else match.group(0)
                    return json.loads(json_str)
                except (json.JSONDecodeError, IndexError):
                    continue

        # Parsing failed, return empty dictionary
        logger.warning(f"Failed to parse JSON from response: {response[:200]}...")
        return {}

    def clear_cache(self):
        """Clear classification cache"""
        self._cache.clear()


# =============================================================================
# Sequence Filter (Simplified version, mainly relies on LLM)
# =============================================================================

class SequenceFilter:
    """
    API sequence filter

    Simplified version, only performs basic checks, main filtering logic delegated to LLM.
    """

    def __init__(self, conditions: Optional[FunctionConditionsSet] = None):
        """
        Args:
            conditions: Function condition information (optional, reserved interface)
        """
        self.conditions = conditions
        self._stats = {
            "total": 0,
            "passed": 0,
            "filtered": 0,
        }

    def filter_sequence(self, sequence: List[Api]) -> FilterResult:
        """
        Basic filtering check

        Only performs basic checks, does not use complex heuristic rules.
        """
        self._stats["total"] += 1

        # Basic check: empty sequence
        if not sequence:
            self._stats["filtered"] += 1
            return FilterResult.invalid("Empty sequence")

        # Basic check: sequence too long (may be invalid path)
        if len(sequence) > 20:
            self._stats["filtered"] += 1
            return FilterResult.invalid(f"Sequence too long: {len(sequence)} APIs")

        self._stats["passed"] += 1
        return FilterResult.valid()

    def filter_sequences(self, sequences: List[List[Api]]) -> List[List[Api]]:
        """Batch filter"""
        return [seq for seq in sequences if self.filter_sequence(seq).is_valid]

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics"""
        return self._stats.copy()

    def reset_stats(self):
        """Reset statistics"""
        self._stats = {"total": 0, "passed": 0, "filtered": 0}


# =============================================================================
# Combined Filter
# =============================================================================

class LLMSequenceFilter:
    """
    LLM-based API sequence filter

    Mainly uses LLM for semantic filtering, replacing traditional heuristic rules.
    """

    def __init__(self, llm_client: Optional[LLMClient] = None,
                 conditions: Optional[FunctionConditionsSet] = None):
        """
        Args:
            llm_client: LLM client
            conditions: Function condition information (reserved)
        """
        self.basic_filter = SequenceFilter(conditions)
        # Wrap the LLM model in an adapter to provide query() method
        adapted_client = create_llm_adapter(llm_client)
        self.llm_validator = LLMLifecycleValidator(adapted_client)

        self._stats: Dict[str, Any] = {
            "total": 0,
            "basic_filtered": 0,
            "llm_filtered": 0,
            "passed": 0,
        }

    def set_llm_client(self, llm_client: LLMClient):
        """Set LLM client"""
        # Wrap the LLM model in an adapter to provide query() method
        adapted_client = create_llm_adapter(llm_client)
        self.llm_validator.set_llm_client(adapted_client)

    def filter(self, sequence: List[Api]) -> Tuple[bool, Optional[str]]:
        """
        Filter single sequence

        Returns:
            (is_valid, rejection_reason)
        """
        self._stats["total"] += 1

        # Step 1: Basic check
        basic_result = self.basic_filter.filter_sequence(sequence)
        if not basic_result.is_valid:
            self._stats["basic_filtered"] += 1
            return False, f"[Basic] {basic_result.reason}"

        # Step 2: LLM semantic validation
        llm_result = self.llm_validator.validate_sequence(sequence)
        if not llm_result.is_valid:
            self._stats["llm_filtered"] += 1
            violations_str = "; ".join(llm_result.violations) if llm_result.violations else llm_result.reasoning
            return False, f"[LLM] {violations_str}"

        self._stats["passed"] += 1
        return True, None

    def filter_batch(self, sequences: List[List[Api]]) -> List[List[Api]]:
        """Batch filter"""
        valid = []
        for seq in sequences:
            is_valid, reason = self.filter(seq)
            if is_valid:
                valid.append(seq)
            else:
                logger.debug(f"Filtered sequence: {reason}")
        return valid

    def classify_apis(self, apis: List[Api]) -> List[APILifecycleInfo]:
        """
        Classify API list lifecycle phases

        Can be used independently to understand API semantics.
        """
        return self.llm_validator.classify_batch(apis)

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics"""
        stats = self._stats.copy()
        stats["basic_filter_stats"] = self.basic_filter.get_stats()
        return stats

    def reset_stats(self):
        """Reset statistics"""
        self._stats = {
            "total": 0,
            "basic_filtered": 0,
            "llm_filtered": 0,
            "passed": 0,
        }
        self.basic_filter.reset_stats()

