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
- `target_type`
- `total_vectors`
- `vulnerable_count`
- `resistant_count`
- `error_count`
- `duration_ms`
- `score.score`
- `score.grade`
- `findings`
- `mcp` for MCP descriptor scans, including `scan.mcp.inventory` and `scan.mcp.tools`

Within each finding, downstream consumers may rely on:

- `rule_id`
- `vector_id`
- `vector_name`
- `category`
- `subcategory`
- `severity`
- `status`
- `status_code`
- `response`
- `duration_ms`

Current MCP findings in `agentprey.scan.v1` also retain these legacy fields for
compatibility in this schema version:

- `tool_name`
- `capabilities`
- `approval_sensitive`

The following additive evidence fields may appear on findings without changing
`schema_version`:

- `attack_surface`
- `observed_capabilities`
- `evidence_kind`
- `repro_steps`
- `mitigation_tags`
- `source_spans`

## Compatibility

- Any breaking structural change must ship as a new schema version.
- Additive fields are allowed within the existing schema version.
- Existing finding fields and stable MCP rule IDs must not be removed or
  renamed within `agentprey.scan.v1`.
- Internal/private tooling should validate `schema_version` before consuming the artifact.
