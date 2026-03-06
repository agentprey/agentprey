# Artifact Contracts

`agentprey` currently emits one versioned artifact intended for downstream
automation and private internal tooling:

- `agentprey.scan.v1`

## `agentprey.scan.v1`

Downstream consumers may rely on these top-level fields:

- `schema_version`
- `generated_at_ms`
- `scan`

Within `scan`, downstream consumers may rely on:

- `target`
- `total_vectors`
- `vulnerable_count`
- `resistant_count`
- `error_count`
- `duration_ms`
- `score.score`
- `score.grade`
- `findings`

Within each finding, downstream consumers may rely on:

- `vector_id`
- `vector_name`
- `category`
- `subcategory`
- `severity`
- `status`
- `status_code`
- `response`
- `duration_ms`

## Compatibility

- Any breaking structural change must ship as a new schema version.
- Additive fields are allowed within the existing schema version.
- Internal/private tooling should validate `schema_version` before consuming the artifact.
