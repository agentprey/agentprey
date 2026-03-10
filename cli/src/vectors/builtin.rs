use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use include_dir::{include_dir, Dir};

use crate::vectors::{
    loader::LoadedVector, model::Vector, parser::parse_vector_from_yaml, validator::validate_vector,
};

static BUILTIN_VECTORS_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/vectors");

pub fn load_builtin_vectors() -> Result<Vec<LoadedVector>> {
    let mut loaded = Vec::new();
    collect_from_dir(
        BUILTIN_VECTORS_DIR.path().to_path_buf(),
        &BUILTIN_VECTORS_DIR,
        &mut loaded,
    )?;
    loaded.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(loaded)
}

fn collect_from_dir(base: PathBuf, dir: &Dir<'_>, loaded: &mut Vec<LoadedVector>) -> Result<()> {
    for file in dir.files() {
        let Some(extension) = file.path().extension().and_then(|ext| ext.to_str()) else {
            continue;
        };

        if extension != "yaml" && extension != "yml" {
            continue;
        }

        let content = file.contents_utf8().ok_or_else(|| {
            anyhow!(
                "builtin vector file '{}' is not valid UTF-8",
                file.path().display()
            )
        })?;

        let vector: Vector = parse_vector_from_yaml(content).with_context(|| {
            format!("invalid builtin vector YAML in '{}'", file.path().display())
        })?;

        validate_vector(&vector).with_context(|| {
            format!(
                "invalid builtin vector semantics in '{}'",
                file.path().display()
            )
        })?;

        let relative = file
            .path()
            .strip_prefix(&base)
            .map(PathBuf::from)
            .unwrap_or_else(|_| file.path().to_path_buf());

        loaded.push(LoadedVector {
            path: PathBuf::from("builtin").join(relative),
            vector,
        });
    }

    for child in dir.dirs() {
        collect_from_dir(base.clone(), child, loaded)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::vectors::builtin::load_builtin_vectors;

    #[test]
    fn loads_embedded_vector_catalog() {
        let loaded = load_builtin_vectors().expect("embedded vectors should load");
        assert!(!loaded.is_empty());
        assert!(loaded
            .iter()
            .any(|vector| vector.vector.id == "pi-direct-001"));
        assert!(loaded
            .iter()
            .any(|vector| vector.vector.id == "tm-openclaw-001"));
        assert!(loaded
            .iter()
            .any(|vector| vector.vector.id == "tm-openclaw-002"));
    }
}
