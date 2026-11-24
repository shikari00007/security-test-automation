# Catalog model

Three tiers, kept distinct everywhere (CLI, reports, skills):

1. **Raw inventory** - verbatim imported checklist lines with source file, hash, line and heading. *Internal; not part of this repository* because redistribution rights for the supplied checklists have not been confirmed.
2. **Canonical catalog** - de-duplicated, normalized entries with heuristic classification (testing mode, applicability tags, high-impact/disruptive flags, standards hints). *Internal and unreviewed; not published.* Entries are marked `review_state: normalized`, and heuristic standards mappings `mapping_confidence: heuristic`.
3. **Reviewed checks** (`security_runner/data/checks/*.json`) - the only tier that can execute. Original wording, hand-mapped standards, explicit `maturity` (`preview`, `experimental`, `unimplemented`).

Maintainer measurements (internal import, 2026-11-20): 8,193 raw entries from 8 sources; 8,174 canonical; 18 exact-duplicate groups; 296 semantic-duplicate candidate clusters; 31 unresolved import anomalies. Raw entries are source lines, not tests; none of these counts imply coverage.
