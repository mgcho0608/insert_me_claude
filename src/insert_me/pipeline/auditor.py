"""
Auditor — ground truth and provenance record generation.

Phase 6 minimal slice: a fully deterministic Auditor that writes
``ground_truth.json``, ``audit.json``, and ``audit_result.json``.

All three artifacts are schema-validated before being written.

labels.json enrichment (Phase 7)
---------------------------------
The ``llm_adapter`` parameter is accepted for forward compatibility but
is **not invoked** in this phase.  ``labels.json`` is never written here.
If the caller passes a non-None adapter, the Auditor ignores it and
documents the decision in the audit record.

Design constraints
------------------
- All output is rule-based and fully deterministic.
- No LLM calls, no compiler invocations, no network access.
- ``ground_truth.json`` and ``audit.json`` are written even in dry-run mode.
- ``validation_passed`` reflects the *actual* Validator verdict; it is never
  hard-coded.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from insert_me import ARTIFACT_SCHEMA_VERSION
from insert_me.artifacts import BundlePaths, write_json_artifact
from insert_me.pipeline.patcher import Mutation, PatchResult
from insert_me.pipeline.validator import CheckStatus, ValidationVerdict
from insert_me.schema import (
    SCHEMA_AUDIT_RECORD,
    SCHEMA_AUDIT_RESULT,
    SCHEMA_GROUND_TRUTH,
    validate_artifact,
)


# ---------------------------------------------------------------------------
# Artifact dataclasses
# ---------------------------------------------------------------------------

@dataclass
class MutationRecord:
    """Serialisable record of a single mutation, for ground_truth.json."""

    file: str
    """Relative path from the source tree root."""

    line: int
    mutation_type: str
    original_fragment: str
    mutated_fragment: str
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mutation(cls, m: Mutation) -> "MutationRecord":
        """
        Build from a Patcher Mutation.

        ``m.target.file`` is already relative to the source root (the Seeder
        stores it that way), so no path manipulation is needed here.
        """
        return cls(
            file=str(m.target.file),
            line=m.target.line,
            mutation_type=m.mutation_type,
            original_fragment=m.original_fragment,
            mutated_fragment=m.mutated_fragment,
            extra=m.extra,
        )


@dataclass
class GroundTruthRecord:
    """In-memory representation of ground_truth.json."""

    schema_version: str
    run_id: str
    cwe_id: str
    spec_id: str
    seed: int
    mutations: list[MutationRecord] = field(default_factory=list)
    validation_passed: bool = False


@dataclass
class AuditRecord:
    """In-memory representation of audit.json."""

    schema_version: str
    run_id: str
    seed: int
    spec_path: str
    spec_hash: str
    source_root: str
    source_hash: str
    pipeline_version: str
    timestamp_utc: str
    validation_verdict: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Auditor
# ---------------------------------------------------------------------------

class Auditor:
    """
    Write ground_truth.json, audit.json, and audit_result.json.

    Parameters
    ----------
    patch_result:
        PatchResult from the Patcher, or ``None`` in dry-run mode.
    verdict:
        ValidationVerdict from the Validator.
    bundle:
        BundlePaths for the current run's output directory.
    run_id:
        Deterministic 16-char hex run identifier.
    seed:
        Integer seed used for this run.
    seed_data:
        Parsed seed artifact dict (from ``--seed-file`` or legacy).
    pipeline_version:
        ``insert_me`` package version string.
    spec_path:
        Path to the seed/spec file (``None`` if unknown).
    spec_hash:
        SHA-256 hex of the seed/spec file contents.
    source_root:
        Path to the original source tree root used for scanning.
    source_hash:
        16-char hex SHA-256 of the source file set (from Seeder).
    llm_adapter:
        Reserved for Phase 7 label enrichment.  **Currently unused.**
    """

    def __init__(
        self,
        patch_result: PatchResult | None,
        verdict: ValidationVerdict,
        bundle: BundlePaths,
        run_id: str,
        seed: int,
        seed_data: dict[str, Any],
        pipeline_version: str,
        spec_path: Path | None,
        spec_hash: str,
        source_root: Path,
        source_hash: str,
        *,
        llm_adapter: Any = None,
    ) -> None:
        self.patch_result = patch_result
        self.verdict = verdict
        self.bundle = bundle
        self.run_id = run_id
        self.seed = seed
        self.seed_data = seed_data
        self.pipeline_version = pipeline_version
        self.spec_path = spec_path
        self.spec_hash = spec_hash
        self.source_root = source_root
        self.source_hash = source_hash
        # llm_adapter accepted but not invoked in this phase (labels deferred to Phase 7)
        _ = llm_adapter

    def run(self) -> tuple[GroundTruthRecord, AuditRecord]:
        """
        Write all three audit artifacts and return the structured records.

        Artifact write order: ground_truth → audit → audit_result.
        Each artifact is schema-validated immediately before writing.

        Returns
        -------
        (GroundTruthRecord, AuditRecord)
            Structured records for downstream use or testing.
        """
        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        # ground_truth.json
        gt = self._build_ground_truth()
        gt_dict = _ground_truth_to_dict(gt)
        validate_artifact(gt_dict, SCHEMA_GROUND_TRUTH)
        write_json_artifact(self.bundle.ground_truth, gt_dict)

        # audit.json
        ar = self._build_audit(now_utc)
        ar_dict = _audit_to_dict(ar)
        validate_artifact(ar_dict, SCHEMA_AUDIT_RECORD)
        write_json_artifact(self.bundle.audit, ar_dict)

        # audit_result.json
        audit_result_dict = self._build_audit_result(now_utc)
        validate_artifact(audit_result_dict, SCHEMA_AUDIT_RESULT)
        write_json_artifact(self.bundle.audit_result, audit_result_dict)

        return gt, ar

    # ------------------------------------------------------------------
    # Private builders
    # ------------------------------------------------------------------

    def _build_ground_truth(self) -> GroundTruthRecord:
        mutations = (
            self.patch_result.mutations
            if self.patch_result is not None
            else []
        )
        return GroundTruthRecord(
            schema_version=ARTIFACT_SCHEMA_VERSION,
            run_id=self.run_id,
            cwe_id=self.seed_data.get("cwe_id", "CWE-0"),
            spec_id=self.seed_data.get("seed_id", ""),
            seed=self.seed,
            mutations=[MutationRecord.from_mutation(m) for m in mutations],
            validation_passed=self.verdict.passed,
        )

    def _build_audit(self, timestamp_utc: str) -> AuditRecord:
        return AuditRecord(
            schema_version=ARTIFACT_SCHEMA_VERSION,
            run_id=self.run_id,
            seed=self.seed,
            spec_path=str(self.spec_path) if self.spec_path else "",
            spec_hash=self.spec_hash,
            source_root=str(self.source_root),
            source_hash=self.source_hash,
            pipeline_version=self.pipeline_version,
            timestamp_utc=timestamp_utc,
            validation_verdict={
                "passed": self.verdict.passed,
                "checks": [
                    {
                        "name": c.name,
                        "status": c.status.value,
                        "reason": c.reason,
                    }
                    for c in self.verdict.checks
                ],
            },
        )

    def _build_audit_result(self, timestamp_utc: str) -> dict[str, Any]:
        mutations = (
            self.patch_result.mutations
            if self.patch_result is not None
            else []
        )
        verdict_overall = self.verdict.overall

        if mutations:
            if verdict_overall == "PASS":
                classification = "VALID"
                confidence = "medium"
                evidence: list[dict[str, Any]] = [
                    {
                        "source": "validator",
                        "observation": (
                            f"Validator passed all {len(self.verdict.checks)} "
                            "plausibility checks."
                        ),
                        "weight": "strong",
                    },
                    {
                        "source": "patcher",
                        "observation": (
                            f"Patcher applied {len(mutations)} mutation(s) "
                            f"using strategy '{mutations[0].mutation_type}'."
                        ),
                        "weight": "moderate",
                    },
                ]
            elif verdict_overall == "FAIL":
                classification = "INVALID"
                confidence = "medium"
                fail_names = [
                    c.name
                    for c in self.verdict.checks
                    if c.status in (CheckStatus.FAIL, CheckStatus.ERROR)
                ]
                evidence = [
                    {
                        "source": "validator",
                        "observation": (
                            "Validator rejected the mutation — "
                            f"failed check(s): {', '.join(fail_names)}."
                        ),
                        "weight": "strong",
                    },
                    {
                        "source": "patcher",
                        "observation": (
                            f"Patcher applied {len(mutations)} mutation(s) "
                            f"using strategy '{mutations[0].mutation_type}'."
                        ),
                        "weight": "moderate",
                    },
                ]
            else:  # SKIP (should not normally occur in real mode)
                classification = "AMBIGUOUS"
                confidence = "low"
                evidence = [
                    {
                        "source": "validator",
                        "observation": (
                            "Validator produced no definitive verdict (SKIP). "
                            "Manual review required before corpus inclusion."
                        ),
                        "weight": "neutral",
                    },
                    {
                        "source": "patcher",
                        "observation": (
                            f"Patcher applied {len(mutations)} mutation(s) "
                            f"using strategy '{mutations[0].mutation_type}'."
                        ),
                        "weight": "moderate",
                    },
                ]
        else:
            # No mutations — dry-run, no compatible target, or empty source tree
            classification = "NOOP"
            confidence = "low"
            evidence = [
                {
                    "source": "seeder",
                    "observation": (
                        "No mutations were applied: run is in dry-run mode, "
                        "no compatible target was found for the mutation strategy, "
                        "or the source tree contains no C/C++ files."
                    ),
                    "weight": "neutral",
                }
            ]

        return {
            "schema_version": ARTIFACT_SCHEMA_VERSION,
            "audit_id": f"ar-{self.run_id}",
            "run_id": self.run_id,
            "classification": classification,
            "confidence": confidence,
            "evidence": evidence,
            "reviewer": {
                "type": "deterministic",
                "name": "auditor_phase6_v1",
            },
            "audited_at": timestamp_utc,
        }


# ---------------------------------------------------------------------------
# Serializers
# ---------------------------------------------------------------------------

def _ground_truth_to_dict(gt: GroundTruthRecord) -> dict[str, Any]:
    """Serialise a GroundTruthRecord to a schema-compliant dict."""
    return {
        "schema_version": gt.schema_version,
        "run_id": gt.run_id,
        "cwe_id": gt.cwe_id,
        "spec_id": gt.spec_id,
        "seed": gt.seed,
        "mutations": [
            {
                "file": m.file,
                "line": m.line,
                "mutation_type": m.mutation_type,
                "original_fragment": m.original_fragment,
                "mutated_fragment": m.mutated_fragment,
                "extra": m.extra,
            }
            for m in gt.mutations
        ],
        "validation_passed": gt.validation_passed,
    }


def _audit_to_dict(ar: AuditRecord) -> dict[str, Any]:
    """Serialise an AuditRecord to a schema-compliant dict."""
    return {
        "schema_version": ar.schema_version,
        "run_id": ar.run_id,
        "seed": ar.seed,
        "spec_path": ar.spec_path,
        "spec_hash": ar.spec_hash,
        "source_root": ar.source_root,
        "source_hash": ar.source_hash,
        "pipeline_version": ar.pipeline_version,
        "timestamp_utc": ar.timestamp_utc,
        "validation_verdict": ar.validation_verdict,
    }
