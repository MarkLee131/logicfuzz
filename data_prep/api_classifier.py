"""
API Role Classifier for fuzzing knowledge extraction.

Classifies APIs into semantic roles to guide fuzz driver generation strategy.
Uses heuristic rules + optional LLM enhancement.
"""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import re


class APIRole(Enum):
    """Semantic roles for API functions."""
    PARSER = "parser"           # Consumes raw external input (JSON parse, file read)
    CREATOR = "creator"         # Creates new objects/resources (malloc, CreateObject)
    ACCESSOR = "accessor"       # Reads data from objects (GetItem, HasKey, IsArray)
    MUTATOR = "mutator"         # Modifies existing objects (SetItem, AddItem, Replace)
    DESTRUCTOR = "destructor"   # Frees resources (free, Delete, Close)
    SERIALIZER = "serializer"   # Converts objects to output format (Print, Encode, Write)
    VALIDATOR = "validator"     # Validates input/state (Validate, Check, Verify)
    UNKNOWN = "unknown"


@dataclass
class ClassifiedAPI:
    """An API with its classified role and confidence."""
    name: str
    role: APIRole
    confidence: float  # 0.0 - 1.0
    reason: str
    signature: Optional[str] = None
    return_type: Optional[str] = None
    params: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class APIClassificationResult:
    """Result of classifying all APIs in a project."""
    project_name: str
    apis: List[ClassifiedAPI]

    # Grouped by role for easy access
    parsers: List[ClassifiedAPI] = field(default_factory=list)
    creators: List[ClassifiedAPI] = field(default_factory=list)
    accessors: List[ClassifiedAPI] = field(default_factory=list)
    mutators: List[ClassifiedAPI] = field(default_factory=list)
    destructors: List[ClassifiedAPI] = field(default_factory=list)
    serializers: List[ClassifiedAPI] = field(default_factory=list)
    validators: List[ClassifiedAPI] = field(default_factory=list)

    def __post_init__(self):
        """Group APIs by role after initialization."""
        for api in self.apis:
            if api.role == APIRole.PARSER:
                self.parsers.append(api)
            elif api.role == APIRole.CREATOR:
                self.creators.append(api)
            elif api.role == APIRole.ACCESSOR:
                self.accessors.append(api)
            elif api.role == APIRole.MUTATOR:
                self.mutators.append(api)
            elif api.role == APIRole.DESTRUCTOR:
                self.destructors.append(api)
            elif api.role == APIRole.SERIALIZER:
                self.serializers.append(api)
            elif api.role == APIRole.VALIDATOR:
                self.validators.append(api)

    def get_priority_apis(self) -> List[ClassifiedAPI]:
        """
        Get APIs in priority order for fuzzing.

        Priority: Parsers > Serializers > Mutators > Accessors > Creators > Validators > Destructors

        Rationale:
        - Parsers consume raw input → highest coverage potential
        - Serializers often have complex logic
        - Mutators/Accessors exercise object manipulation
        - Creators are usually simple
        - Destructors are cleanup only
        """
        return (
            self.parsers +
            self.serializers +
            self.mutators +
            self.accessors +
            self.creators +
            self.validators +
            self.destructors
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "project_name": self.project_name,
            "summary": {
                "total": len(self.apis),
                "parsers": len(self.parsers),
                "creators": len(self.creators),
                "accessors": len(self.accessors),
                "mutators": len(self.mutators),
                "destructors": len(self.destructors),
                "serializers": len(self.serializers),
                "validators": len(self.validators),
            },
            "apis": [
                {
                    "name": api.name,
                    "role": api.role.value,
                    "confidence": api.confidence,
                    "reason": api.reason,
                }
                for api in self.apis
            ]
        }


class APIClassifier:
    """
    Classifies APIs into semantic roles using heuristic rules.

    Heuristics are based on:
    1. Function name patterns
    2. Parameter type patterns
    3. Return type patterns
    """

    # Name patterns for each role (case-insensitive matching)
    NAME_PATTERNS = {
        APIRole.PARSER: [
            r'parse', r'read', r'load', r'decode', r'deserialize',
            r'from_', r'import', r'unmarshal', r'scan', r'lex',
            r'_parse$', r'^parse_', r'_read$', r'^read_',
        ],
        APIRole.CREATOR: [
            r'create', r'new', r'alloc', r'make', r'init', r'open',
            r'_create$', r'^create_', r'_new$', r'^new_', r'_init$',
            r'dup$', r'_dup$', r'clone', r'copy',
        ],
        APIRole.ACCESSOR: [
            r'^get_', r'_get$', r'^has_', r'^is_', r'^can_',
            r'find', r'lookup', r'search', r'query', r'fetch',
            r'peek', r'check', r'count', r'size', r'length',
            r'getobject', r'getarray', r'getstring', r'getnumber',
            r'hasobject', r'hasarray', r'isarray', r'isobject', r'isstring',
        ],
        APIRole.MUTATOR: [
            r'^set_', r'_set$', r'^add_', r'_add$', r'insert',
            r'remove', r'replace', r'update', r'append', r'prepend',
            r'push', r'pop', r'enqueue', r'dequeue',
            r'additem', r'setitem', r'replaceitem', r'deleteitem',
        ],
        APIRole.DESTRUCTOR: [
            r'free', r'delete', r'destroy', r'release', r'close',
            r'cleanup', r'finalize', r'dispose', r'clear',
            r'_free$', r'^free_', r'_delete$', r'^delete_',
        ],
        APIRole.SERIALIZER: [
            r'print', r'write', r'encode', r'serialize', r'dump',
            r'to_', r'export', r'marshal', r'format', r'render',
            r'_print$', r'^print_', r'tostring', r'tojson',
        ],
        APIRole.VALIDATOR: [
            r'valid', r'verify', r'check', r'assert', r'ensure',
            r'sanitize', r'normalize', r'_valid$', r'^valid_',
        ],
    }

    # Parameter patterns that suggest certain roles
    PARAM_PATTERNS = {
        APIRole.PARSER: [
            # (const char*, ...) or (const uint8_t*, size_t) suggests parsing
            (r'const\s+(char|uint8_t|unsigned\s+char)\s*\*', r'size_t|int|unsigned'),
            # FILE* suggests file reading
            (r'FILE\s*\*',),
        ],
        APIRole.DESTRUCTOR: [
            # Single pointer parameter with void return suggests destructor
            (r'^[a-zA-Z_][a-zA-Z0-9_]*\s*\*$',),
        ],
    }

    # Return type patterns
    RETURN_PATTERNS = {
        APIRole.CREATOR: [
            # Returns pointer (likely created object)
            r'^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\*\s*$',
        ],
        APIRole.ACCESSOR: [
            # Returns bool/int for check functions
            r'^(bool|_Bool|int|cJSON_bool)$',
        ],
        APIRole.DESTRUCTOR: [
            # Returns void
            r'^void$',
        ],
    }

    def __init__(self):
        # Compile patterns for efficiency
        self._compiled_name_patterns = {
            role: [re.compile(p, re.IGNORECASE) for p in patterns]
            for role, patterns in self.NAME_PATTERNS.items()
        }

    def classify_api(self, api_info: Dict[str, Any]) -> ClassifiedAPI:
        """
        Classify a single API into a semantic role.

        Args:
            api_info: Dictionary containing:
                - function_name: str
                - return_type: str (optional)
                - arguments: List[Dict] or List[str] (optional)

        Returns:
            ClassifiedAPI with role, confidence, and reason
        """
        name = api_info.get('function_name', '')
        return_type = api_info.get('return_type', '')
        args = api_info.get('arguments', [])

        # Score each role
        scores: Dict[APIRole, float] = {role: 0.0 for role in APIRole}
        reasons: Dict[APIRole, List[str]] = {role: [] for role in APIRole}

        # 1. Check name patterns (highest weight: 0.6)
        for role, patterns in self._compiled_name_patterns.items():
            for pattern in patterns:
                if pattern.search(name):
                    scores[role] += 0.6
                    reasons[role].append(f"name matches '{pattern.pattern}'")
                    break  # Only count once per role

        # 2. Check return type patterns (weight: 0.25)
        if return_type:
            for role, patterns in self.RETURN_PATTERNS.items():
                for pattern in patterns:
                    if re.match(pattern, return_type.strip(), re.IGNORECASE):
                        scores[role] += 0.25
                        reasons[role].append(f"return type '{return_type}' matches")
                        break

        # 3. Check parameter patterns (weight: 0.15)
        args_str = self._format_args(args)
        for role, param_pattern_sets in self.PARAM_PATTERNS.items():
            for param_patterns in param_pattern_sets:
                if all(re.search(p, args_str, re.IGNORECASE) for p in param_patterns):
                    scores[role] += 0.15
                    reasons[role].append(f"params suggest {role.value}")
                    break

        # 4. Special heuristics

        # Destructor: void return + single pointer param + name doesn't match other roles
        if (return_type and return_type.strip().lower() == 'void' and
            len(args) == 1 and
            scores[APIRole.DESTRUCTOR] < 0.5):
            # Check if the single arg is a pointer
            arg_type = self._get_arg_type(args[0])
            if '*' in arg_type:
                scores[APIRole.DESTRUCTOR] += 0.3
                reasons[APIRole.DESTRUCTOR].append("void return + single pointer param")

        # Creator: returns pointer + name doesn't strongly match other roles
        if return_type and '*' in return_type and scores[APIRole.CREATOR] < 0.5:
            # Avoid misclassifying parsers as creators
            if scores[APIRole.PARSER] < 0.3:
                scores[APIRole.CREATOR] += 0.2
                reasons[APIRole.CREATOR].append("returns pointer")

        # Find best role
        best_role = max(scores, key=scores.get)
        best_score = scores[best_role]

        # If no good match, mark as unknown
        if best_score < 0.3:
            best_role = APIRole.UNKNOWN
            reason = "no strong pattern match"
        else:
            reason = "; ".join(reasons[best_role]) if reasons[best_role] else "heuristic match"

        return ClassifiedAPI(
            name=name,
            role=best_role,
            confidence=min(best_score, 1.0),
            reason=reason,
            signature=f"{return_type} {name}({args_str})" if return_type else None,
            return_type=return_type,
            params=args if isinstance(args, list) else []
        )

    def classify_all(self, project_name: str, apis: List[Dict[str, Any]]) -> APIClassificationResult:
        """
        Classify all APIs in a project.

        Args:
            project_name: Name of the project
            apis: List of API info dictionaries

        Returns:
            APIClassificationResult with all classified APIs
        """
        classified = [self.classify_api(api) for api in apis]
        return APIClassificationResult(project_name=project_name, apis=classified)

    def _format_args(self, args: List) -> str:
        """Format arguments list as a string for pattern matching."""
        if not args:
            return ""

        parts = []
        for arg in args:
            if isinstance(arg, dict):
                arg_type = arg.get('type', arg.get('type_clang', ''))
                parts.append(arg_type)
            else:
                parts.append(str(arg))
        return ", ".join(parts)

    def _get_arg_type(self, arg) -> str:
        """Extract type from an argument."""
        if isinstance(arg, dict):
            return arg.get('type', arg.get('type_clang', ''))
        return str(arg)


def classify_project_apis(project_name: str, apis: List[Dict[str, Any]]) -> APIClassificationResult:
    """
    Convenience function to classify all APIs in a project.

    Args:
        project_name: Name of the project
        apis: List of API info dictionaries from FuzzIntrospector or other sources

    Returns:
        APIClassificationResult with classified APIs grouped by role
    """
    classifier = APIClassifier()
    return classifier.classify_all(project_name, apis)


# Example usage
if __name__ == "__main__":
    # Test with cJSON-like APIs
    test_apis = [
        {"function_name": "cJSON_Parse", "return_type": "cJSON *", "arguments": [{"type": "const char *", "name": "value"}]},
        {"function_name": "cJSON_ParseWithOpts", "return_type": "cJSON *", "arguments": [{"type": "const char *", "name": "value"}, {"type": "const char **", "name": "end"}, {"type": "int", "name": "require_null"}]},
        {"function_name": "cJSON_CreateObject", "return_type": "cJSON *", "arguments": []},
        {"function_name": "cJSON_CreateArray", "return_type": "cJSON *", "arguments": []},
        {"function_name": "cJSON_CreateString", "return_type": "cJSON *", "arguments": [{"type": "const char *", "name": "string"}]},
        {"function_name": "cJSON_GetObjectItem", "return_type": "cJSON *", "arguments": [{"type": "const cJSON *", "name": "object"}, {"type": "const char *", "name": "string"}]},
        {"function_name": "cJSON_HasObjectItem", "return_type": "cJSON_bool", "arguments": [{"type": "const cJSON *", "name": "object"}, {"type": "const char *", "name": "string"}]},
        {"function_name": "cJSON_IsArray", "return_type": "cJSON_bool", "arguments": [{"type": "const cJSON *", "name": "item"}]},
        {"function_name": "cJSON_IsObject", "return_type": "cJSON_bool", "arguments": [{"type": "const cJSON *", "name": "item"}]},
        {"function_name": "cJSON_AddItemToObject", "return_type": "cJSON_bool", "arguments": [{"type": "cJSON *", "name": "object"}, {"type": "const char *", "name": "string"}, {"type": "cJSON *", "name": "item"}]},
        {"function_name": "cJSON_AddNullToObject", "return_type": "cJSON *", "arguments": [{"type": "cJSON *", "name": "object"}, {"type": "const char *", "name": "name"}]},
        {"function_name": "cJSON_ReplaceItemInObject", "return_type": "cJSON_bool", "arguments": [{"type": "cJSON *", "name": "object"}, {"type": "const char *", "name": "string"}, {"type": "cJSON *", "name": "newitem"}]},
        {"function_name": "cJSON_Delete", "return_type": "void", "arguments": [{"type": "cJSON *", "name": "item"}]},
        {"function_name": "cJSON_Print", "return_type": "char *", "arguments": [{"type": "const cJSON *", "name": "item"}]},
        {"function_name": "cJSON_PrintUnformatted", "return_type": "char *", "arguments": [{"type": "const cJSON *", "name": "item"}]},
    ]

    result = classify_project_apis("cjson", test_apis)

    print("=== API Classification Results ===\n")
    print(f"Project: {result.project_name}")
    print(f"Total APIs: {len(result.apis)}")
    print(f"  Parsers: {len(result.parsers)}")
    print(f"  Creators: {len(result.creators)}")
    print(f"  Accessors: {len(result.accessors)}")
    print(f"  Mutators: {len(result.mutators)}")
    print(f"  Destructors: {len(result.destructors)}")
    print(f"  Serializers: {len(result.serializers)}")
    print()

    print("=== Detailed Classification ===\n")
    for api in result.apis:
        print(f"{api.name}: {api.role.value} (conf={api.confidence:.2f})")
        print(f"  Reason: {api.reason}")
        print()

    print("=== Priority Order for Fuzzing ===\n")
    for i, api in enumerate(result.get_priority_apis()[:10], 1):
        print(f"{i}. {api.name} ({api.role.value})")
