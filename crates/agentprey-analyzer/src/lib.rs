pub mod heuristic;
pub mod structured;

pub use agentprey_core::{Analysis, SourceSpan, Verdict};
pub use heuristic::analyze_response_for_vector;
pub use structured::{
    analyze_openclaw_project, StructuredFinding, StructuredFindingKind, StructuredOpenClawReport,
};

pub mod analyzer {
    pub use crate::{analyze_response_for_vector, Analysis, Verdict};
}

pub mod vectors {
    pub mod model {
        pub use agentprey_vectors::model::*;
    }
}
