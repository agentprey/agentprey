pub mod compare;
pub mod compare_html;
pub mod compare_json;
pub mod html;
pub mod json;

pub mod cli {
    pub use agentprey_core::TargetType;
}

pub mod mcp {
    pub mod model {
        pub use agentprey_core::mcp::*;
    }
}

pub mod scan {
    pub use agentprey_core::{
        FindingEvidence, FindingOutcome, FindingOutcomeInput, FindingStatus, ScanOutcome,
        SourceSpan,
    };
}

pub mod scorer {
    pub use agentprey_core::{Grade, ScoreSummary, SeverityCounts};
}

pub mod vectors {
    pub mod model {
        pub use agentprey_core::Severity;
    }
}

pub mod output {
    pub use crate::compare_html;
    pub use crate::compare_json;
    pub use crate::html;
    pub use crate::json;
}
