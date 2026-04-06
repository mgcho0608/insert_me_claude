"""
Auditor — ground truth and provenance record generation.

The Auditor is the final deterministic pipeline stage. It writes:
    - ground_truth.json: full annotation of the inserted vulnerability
    - audit.json: full provenance record for this run

Both files are validated against their respective JSON schemas before writing.

The Auditor may optionally invoke the LLM adapter to enrich the audit output
with semantic labels, written to labels.json. This is a side-channel: it does
not alter ground_truth.json or audit.json in any way.

Design constraints
------------------
- ground_truth.json and audit.json are always deterministic.
- labels.json is optional and does not affect any downstream artifacts.
- All output is schema-validated before writing.
"""

from __future__ import annotations

import datetime
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from insert_me import ARTIFACT_SCHEMA_VERSION
from insert_me.artifacts import BundlePaths, write_json_artifact
from insert_me.pipeline.patcher import PatchResult, Mutation
from insert_me.pipeline.validator import ValidationVerdict


# ---------------------------------------------------------------------------
# Artifact dataclasses (mirrors JSON schema structure)
# ---------------------------------------------------------------------------

@dataclass
class MutationRecord:
    """Serialisable record of a single mutation, for ground_truth.json."""

    file: str
    line: int
    mutation_type: str
    original_fragment: str
    mutated_fragment: str
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mutation(cls, m: Mutation, source_root: Path) -> "MutationRecord":
        rel_file = str(m.target.file.relative_to(source_root))
        return cls(
            file=rel_file,
            line=m.target.line,
            mutation_type=m.mutation_type,
            original_fragment=m.original_fragment,
            mutated_fragment=m.mutated_fragment,
            extra=m.extra,
        )


@dataclass
class GroundTruthRecord:
    """Contents of ground_truth.json."""

    schema_version: str
    run_id: str
    cwe_id: str
    spec_id: str
    seed: int
    mutations: list[MutationRecord] = field(default_factory=list)
    validation_passed: bool = False


@dataclass
class AuditRecord:
    """Contents of audit.json."""

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
    Write ground_truth.json, audit.json, and optionally labels.json.

    Parameters
    ----------
    patch_result:
        PatchResult from the Patcher.
    verdict:
        ValidationVerdict from the Validator.
    bundle:
        BundlePaths pointing to the output directory.
    run_id:
        Deterministic run ID for this pipeline execution.
    seed:
        Seed used for this run.
    spec:
        Parsed spec dict.
    pipeline_version:
        insert_me package version string.
    llm_adapter:
        Optional LLM adapter for label enrichment. Defaults to NoOpAdapter.
    """

    def __init__(
        self,
        patch_result: PatchResult,
        verdict: ValidationVerdict,
        bundle: BundlePaths,
        run_id: str,
        seed: int,
        spec: dict[str, Any],
        pipeline_version: str,
        llm_adapter: Optional[Any] = None,
    ) -> None:
        self.patch_result = patch_result
        self.verdict = verdict
        self.bundle = bundle
        self.run_id = run_id
        self.seed = seed
        self.spec = spec
        self.pipeline_version = pipeline_version
        self.llm_adapter = llm_adapter

    def run(self) -> tuple[GroundTruthRecord, AuditRecord]:
        """
        Write all artifacts and return the ground truth and audit records.

        Raises
        ------
        NotImplementedError
            Until Phase 6 implementation.
        """
        # TODO(phase6): build GroundTruthRecord from patch_result and spec
        # TODO(phase6): build AuditRecord from pipeline provenance
        # TODO(phase6): validate both records against schemas before writing
        # TODO(phase6): write ground_truth.json and audit.json via write_json_artifact
        # TODO(phase7): if llm_adapter is not NoOp, invoke for label enrichment
        # TODO(phase7): write labels.json if enrichment is enabled and succeeded
        raise NotImplementedError(
            "Auditor.run() is not yet implemented. See ROADMAP.md Phase 6."
        )

    def _build_ground_truth(self) -> GroundTruthRecord:
        source_root = self.patch_result.good_root.parent
        return GroundTruthRecord(
            schema_version=ARTIFACT_SCHEMA_VERSION,
            run_id=self.run_id,
            cwe_id=self.spec.get("cwe_id", ""),
            spec_id=self.spec.get("id", ""),
            seed=self.seed,
            mutations=[
                MutationRecord.from_mutation(m, source_root)
                for m in self.patch_result.mutations
            ],
            validation_passed=self.verdict.passed,
        )

    def _build_audit(self, spec_hash: str, source_hash: str) -> AuditRecord:
        return AuditRecord(
            schema_version=ARTIFACT_SCHEMA_VERSION,
            run_id=self.run_id,
            seed=self.seed,
            spec_path=self.spec.get("_path", ""),
            spec_hash=spec_hash,
            source_root=str(self.patch_result.good_root),
            source_hash=source_hash,
            pipeline_version=self.pipeline_version,
            timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            validation_verdict={
                "passed": self.verdict.passed,
                "checks": [
                    {"name": c.name, "status": c.status.value, "reason": c.reason}
                    for c in self.verdict.checks
                ],
            },
        )
