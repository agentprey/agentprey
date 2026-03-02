use std::path::Path;

use anyhow::Result;

use crate::vectors::{loader::load_vectors_from_dir, model::Vector};

pub fn list_vectors(root: &Path, category: Option<&str>) -> Result<Vec<Vector>> {
    let mut vectors: Vec<Vector> = load_vectors_from_dir(root)?
        .into_iter()
        .map(|loaded| loaded.vector)
        .collect();

    if let Some(category) = category {
        vectors.retain(|vector| vector.category == category);
    }

    vectors.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(vectors)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use crate::vectors::catalog::list_vectors;

    #[test]
    fn filters_vectors_by_category() {
        let temp = tempdir().expect("tempdir should be created");
        let root = temp.path().join("vectors");
        fs::create_dir_all(root.join("prompt-injection/direct")).expect("directories should exist");
        fs::create_dir_all(root.join("guardrail-bypass/direct")).expect("directories should exist");

        fs::write(
            root.join("prompt-injection/direct/one.yaml"),
            r#"
id: "pi-direct-001"
name: "One"
description: "Prompt injection"
category: "prompt-injection"
subcategory: "direct"
severity: "high"
payloads:
  - name: "p"
    prompt: "Ignore"
detection:
  indicators:
    - type: "contains_any"
      values: ["system prompt"]
      weight: 0.8
  threshold: 0.6
"#,
        )
        .expect("write should succeed");

        fs::write(
            root.join("guardrail-bypass/direct/two.yaml"),
            r#"
id: "gb-direct-001"
name: "Two"
description: "Guardrail bypass"
category: "guardrail-bypass"
subcategory: "direct"
severity: "medium"
payloads:
  - name: "p"
    prompt: "Bypass"
detection:
  indicators:
    - type: "contains_any"
      values: ["ok"]
      weight: 0.5
  threshold: 0.5
"#,
        )
        .expect("write should succeed");

        let filtered = list_vectors(&root, Some("prompt-injection")).expect("list should succeed");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "pi-direct-001");
    }
}
