"""
OrderSet — PromeFuzz OrderSet/OrderSetCollection ported to plain List[str] API names.

Verbatim port of:
  consumer.py:375-421  OrderSet.from_order_list  → OrderSet.from_sequence
  consumer.py:514-566  OrderSetCollection.minimize → minimize_traces

No external dependencies; no LLM calls; pure deterministic logic.
"""
from __future__ import annotations

from functools import cached_property
from typing import List


class OrderSet:
    """A set of API function names (as strings) called in a specific order."""

    MIN_SIZE: int = 3
    MAX_SIZE: int = 10

    def __init__(self, order_list: List[str]) -> None:
        # Store the (possibly repeated) ordered call sequence.
        self.order_list: List[str] = list(order_list)

    @cached_property
    def unique_apis(self) -> set:
        """Unique API names in this order set."""
        return set(self.order_list)

    @cached_property
    def size(self) -> int:
        """Number of *unique* API names — mirrors PromeFuzz .size."""
        return len(self.unique_apis)

    # ------------------------------------------------------------------
    # Verbatim port of OrderSet.from_order_list (consumer.py:375-421)
    # adapted: APIFunction → str, cls.MIN_SIZE/MAX_SIZE unchanged.
    # ------------------------------------------------------------------
    @classmethod
    def from_sequence(
        cls,
        order_list: List[str],
        min_size: int = 3,
        max_size: int = 10,
    ) -> "List[OrderSet]":
        """
        Generate OrderSet objects from a flat API call sequence.

        Mirrors ``OrderSet.from_order_list`` from PromeFuzz consumer.py:

        * sequence too small (unique count < min_size) → []
        * sequence within bounds → [OrderSet(sequence)]
        * sequence larger than max_size → split into balanced chunks,
          each chunk sized so unique-count ≈ split_size;
          last two chunks are merged when split produces one extra.
        """
        # Temporarily override class constants so helper reads them correctly.
        old_min, old_max = cls.MIN_SIZE, cls.MAX_SIZE
        cls.MIN_SIZE = min_size
        cls.MAX_SIZE = max_size
        try:
            return cls._from_sequence_inner(order_list)
        finally:
            cls.MIN_SIZE = old_min
            cls.MAX_SIZE = old_max

    @classmethod
    def _from_sequence_inner(cls, order_list: List[str]) -> "List[OrderSet]":
        new_order_set = cls(order_list)
        if new_order_set.size < cls.MIN_SIZE:
            return []
        elif new_order_set.size <= cls.MAX_SIZE:
            return [new_order_set]
        else:
            # split_number is the average of splits by MIN and MAX
            split_number = (
                (new_order_set.size // cls.MAX_SIZE)
                + (new_order_set.size // cls.MIN_SIZE)
            ) // 2
            # guard: at least 2 splits when > MAX_SIZE
            if split_number < 2:
                split_number = 2
            split_size = new_order_set.size // split_number

            def _get_sub_order_list_of_size(size: int):
                cur_order_list: List[str] = []
                cur_unique: List[str] = []
                for api in order_list:
                    cur_order_list.append(api)
                    if api not in cur_unique:
                        cur_unique.append(api)
                    if len(cur_unique) == size:
                        yield cur_order_list
                        cur_order_list = []
                        cur_unique = []
                if cur_order_list:
                    yield cur_order_list

            split_result = list(_get_sub_order_list_of_size(split_size))
            if len(split_result) > split_number:
                # merge last two when we got one extra chunk
                split_result[-2] = split_result[-2] + split_result[-1]
                split_result.pop()

            return [cls(sl) for sl in split_result]


# ---------------------------------------------------------------------------
# normalize_traces: flatten from_sequence over each raw trace
# ---------------------------------------------------------------------------

def normalize_traces(raw: List[List[str]]) -> List[List[str]]:
    """
    Expand each raw trace via ``OrderSet.from_sequence`` and return the
    flattened list of ``order_list`` sequences.

    Traces shorter than MIN_SIZE are dropped (same as PromeFuzz).
    """
    result: List[List[str]] = []
    for trace in raw:
        for os_ in OrderSet.from_sequence(trace):
            result.append(os_.order_list)
    return result


# ---------------------------------------------------------------------------
# minimize_traces: greedy set-cover
# Verbatim port of OrderSetCollection.minimize (consumer.py:514-566)
# adapted: operate on List[List[str]] (order_lists) instead of OrderSet objects.
# ---------------------------------------------------------------------------

def minimize_traces(order_sets: List[List[str]]) -> List[List[str]]:
    """
    Greedy set-cover minimization over a collection of API call sequences.

    Each sequence is treated as a *set* of unique API names for coverage
    purposes, but the full ordered list is preserved in the output.

    Returns the minimal sub-collection that covers every API name present
    in the input.
    """
    if not order_sets:
        return []

    # Work with (unique_set, original_list) pairs, sorted by coverage descending.
    pairs = [(set(seq), seq) for seq in order_sets]
    pairs.sort(key=lambda p: len(p[0]), reverse=True)

    # Gather all unique API names across the whole collection.
    all_apis: set = set()
    for unique, _ in pairs:
        all_apis.update(unique)

    covered: set = set()
    selected: List[List[str]] = []

    while covered != all_apis:
        # Find the pair that adds the most uncovered APIs.
        best_idx = -1
        best_new: set = set()
        for i, (unique, _) in enumerate(pairs):
            new = unique - covered
            if len(new) > len(best_new):
                best_new = new
                best_idx = i
        if best_idx == -1:
            break  # nothing left to add (should not happen)
        _, best_seq = pairs.pop(best_idx)
        selected.append(best_seq)
        covered.update(best_new)

    return selected
