use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

use crate::auth;

pub fn sync_pro_vectors() -> Result<usize> {
    let _api_key = auth::require_stored_api_key()?;
    let destination = pro_vectors_dir()?;

    sync_pro_vectors_to_path(&destination)
}

fn sync_pro_vectors_to_path(destination: &Path) -> Result<usize> {
    fs::create_dir_all(&destination).with_context(|| {
        format!(
            "failed to create Pro vectors directory '{}'",
            destination.display()
        )
    })?;

    Ok(0)
}

fn pro_vectors_dir() -> Result<PathBuf> {
    Ok(auth::default_agentprey_dir()?.join("vectors").join("pro"))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::sync_pro_vectors_to_path;

    #[test]
    fn creates_destination_directory() {
        let temp = tempdir().expect("tempdir should be created");
        let destination = temp.path().join("vectors/pro");

        let synced = sync_pro_vectors_to_path(&destination).expect("sync should succeed");
        assert_eq!(synced, 0);
        assert!(destination.exists());
        assert!(destination.is_dir());
    }

    #[test]
    fn succeeds_when_directory_already_exists() {
        let temp = tempdir().expect("tempdir should be created");
        let destination = temp.path().join("vectors/pro");
        fs::create_dir_all(&destination).expect("fixture directory should exist");

        let synced = sync_pro_vectors_to_path(&destination).expect("sync should succeed");
        assert_eq!(synced, 0);
    }
}
