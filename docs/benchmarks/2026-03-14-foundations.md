# Foundation Benchmarks

This milestone adds the first benchmark harness under `cli/benches/foundations.rs`.

Current benchmark surfaces:

- builtin vector catalog loading
- scan JSON rendering
- scan HTML report writing

Run locally from the workspace root:

```bash
cargo bench -p agentprey foundations
```

The goal of this first slice is repeatable measurement scaffolding, not polished dashboards. Expand this note with recorded numbers after each milestone that changes scan throughput or report generation cost.
