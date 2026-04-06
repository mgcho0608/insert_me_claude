"""
LLM adapter interface and default no-op implementation.

The LLMAdapter ABC defines the narrow interface through which insert_me
optionally calls an LLM. All methods return typed dataclasses that are
either populated (real adapter) or empty/stub (NoOpAdapter).

Design constraints
------------------
- The adapter is only called by the Auditor, after all deterministic outputs
  are already produced.
- Returning stubs from NoOpAdapter must never break downstream consumers.
- The interface must remain stable across adapter implementations.
- Adding a new adapter requires only: implementing LLMAdapter + registering
  in insert_me.llm.__init__.ADAPTER_REGISTRY.
- No Anthropic-specific types should appear in this module.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class LabelEnrichment:
    """
    Optional semantic label enrichment returned by the LLM adapter.

    All fields are optional. Absent fields are omitted from labels.json.
    """

    description: str = ""
    """Natural-language description of the inserted vulnerability."""

    realism_score: float | None = None
    """
    0.0–1.0 estimate of how realistic the mutation is.
    None if the model did not produce a score.
    """

    tags: list[str] = field(default_factory=list)
    """Freeform semantic tags (e.g. ["use-after-free", "heap", "allocation"])."""

    raw_response: dict[str, Any] = field(default_factory=dict)
    """Raw LLM response payload, for debugging and audit purposes."""


# ---------------------------------------------------------------------------
# Abstract interface
# ---------------------------------------------------------------------------

class LLMAdapter(ABC):
    """
    Abstract interface for optional LLM-assisted enrichment.

    Implementations must be stateless with respect to the pipeline: calling
    the same method twice with the same inputs must produce consistent (though
    not necessarily byte-identical) outputs.
    """

    @abstractmethod
    def enrich_labels(
        self,
        cwe_id: str,
        mutation_type: str,
        original_fragment: str,
        mutated_fragment: str,
    ) -> LabelEnrichment:
        """
        Request semantic label enrichment for a single mutation.

        Parameters
        ----------
        cwe_id:
            CWE identifier for the vulnerability class (e.g. "CWE-122").
        mutation_type:
            String identifier for the mutation strategy.
        original_fragment:
            The original source fragment before mutation.
        mutated_fragment:
            The mutated source fragment (the vulnerability).

        Returns
        -------
        LabelEnrichment
            Populated or stub enrichment record.
        """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this adapter (e.g. 'noop', 'openai_compat')."""


# ---------------------------------------------------------------------------
# Default: no-op adapter
# ---------------------------------------------------------------------------

class NoOpAdapter(LLMAdapter):
    """
    Default adapter that returns empty/stub enrichments without any LLM calls.

    Always available. Used when:
        - [llm].enabled = false in config
        - --no-llm flag is passed on the CLI
        - No adapter is configured
    """

    @property
    def name(self) -> str:
        return "noop"

    def enrich_labels(
        self,
        cwe_id: str,
        mutation_type: str,
        original_fragment: str,
        mutated_fragment: str,
    ) -> LabelEnrichment:
        """Return an empty enrichment record. No network calls."""
        return LabelEnrichment()
