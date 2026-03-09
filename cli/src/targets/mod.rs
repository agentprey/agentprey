use std::{path::Path, sync::Arc};

use anyhow::{anyhow, Result};

use crate::{
    cli::TargetType,
    scan::{FindingOutcome, ResolvedScanSettings},
    vectors::model::Vector,
};

pub mod http;
pub mod openclaw;

#[derive(Clone)]
pub enum ResolvedTarget {
    Http(Arc<http::HttpTarget>),
    OpenClaw(Arc<openclaw::OpenClawTarget>),
}

impl ResolvedTarget {
    pub fn from_settings(settings: &ResolvedScanSettings) -> Result<Self> {
        match settings.target_type {
            TargetType::Http => Ok(Self::Http(Arc::new(http::HttpTarget::from_settings(
                settings,
            )?))),
            TargetType::Openclaw => {
                if looks_like_url(&settings.target) {
                    return Err(anyhow!(
                        "openclaw targets must be local file system paths, not URLs: '{}'",
                        settings.target
                    ));
                }

                Ok(Self::OpenClaw(Arc::new(
                    openclaw::OpenClawTarget::from_path(Path::new(&settings.target))?,
                )))
            }
            TargetType::Mcp => Err(anyhow!(
                "mcp targets use a dedicated scan path and should not resolve through the generic target executor"
            )),
        }
    }

    pub async fn execute_vector(
        &self,
        vector: Vector,
        settings: &ResolvedScanSettings,
    ) -> FindingOutcome {
        match self {
            Self::Http(target) => target.execute_vector(vector, settings).await,
            Self::OpenClaw(target) => target.execute_vector(vector, settings).await,
        }
    }
}

fn looks_like_url(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.starts_with("http://") || normalized.starts_with("https://")
}
