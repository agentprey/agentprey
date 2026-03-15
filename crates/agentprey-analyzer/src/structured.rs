use std::{collections::BTreeMap, fs, path::Path};

use agentprey_core::SourceSpan;
use tree_sitter::{Node, Parser};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StructuredFindingKind {
    UnsafeShellExecution,
    UnsafeFilesystemWrite,
    OutboundNetworkEgress,
}

impl StructuredFindingKind {
    const ALL: [Self; 3] = [
        Self::UnsafeShellExecution,
        Self::UnsafeFilesystemWrite,
        Self::OutboundNetworkEgress,
    ];

    pub fn summary(self) -> &'static str {
        match self {
            Self::UnsafeShellExecution => {
                "Structured analysis found shell execution reachable without an obvious approval gate."
            }
            Self::UnsafeFilesystemWrite => {
                "Structured analysis found filesystem writes reachable without an obvious approval gate."
            }
            Self::OutboundNetworkEgress => {
                "Structured analysis found outbound network egress reachable without an obvious approval gate."
            }
        }
    }

    pub fn attack_surface(self) -> &'static str {
        match self {
            Self::UnsafeShellExecution => "local-shell-exec",
            Self::UnsafeFilesystemWrite => "local-filesystem-write",
            Self::OutboundNetworkEgress => "outbound-network-egress",
        }
    }

    pub fn observed_capabilities(self) -> &'static [&'static str] {
        match self {
            Self::UnsafeShellExecution => &["shell-exec"],
            Self::UnsafeFilesystemWrite => &["filesystem-write"],
            Self::OutboundNetworkEgress => &["network-egress"],
        }
    }

    pub fn mitigation_tags(self) -> &'static [&'static str] {
        match self {
            Self::UnsafeShellExecution
            | Self::UnsafeFilesystemWrite
            | Self::OutboundNetworkEgress => &["approval-gating", "least-privilege"],
        }
    }

    pub fn capability_label(self) -> &'static str {
        match self {
            Self::UnsafeShellExecution => "shell execution",
            Self::UnsafeFilesystemWrite => "filesystem write",
            Self::OutboundNetworkEgress => "outbound network egress",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StructuredLanguage {
    TypeScript,
    Python,
}

#[derive(Debug, Clone)]
pub struct StructuredFinding {
    pub kind: StructuredFindingKind,
    pub summary: String,
    pub observed_capabilities: Vec<String>,
    pub source_spans: Vec<SourceSpan>,
}

#[derive(Debug, Clone, Default)]
pub struct StructuredOpenClawReport {
    pub findings: Vec<StructuredFinding>,
}

impl StructuredOpenClawReport {
    pub fn finding(&self, kind: StructuredFindingKind) -> Option<&StructuredFinding> {
        self.findings.iter().find(|finding| finding.kind == kind)
    }
}

pub fn analyze_openclaw_project(root: &Path) -> StructuredOpenClawReport {
    let mut spans_by_kind = BTreeMap::new();
    visit_path(root, root, &mut spans_by_kind);

    StructuredOpenClawReport {
        findings: spans_by_kind
            .into_iter()
            .map(|(kind, source_spans)| StructuredFinding {
                kind,
                summary: kind.summary().to_string(),
                observed_capabilities: kind
                    .observed_capabilities()
                    .iter()
                    .map(|capability| (*capability).to_string())
                    .collect(),
                source_spans,
            })
            .collect(),
    }
}

fn visit_path(
    root: &Path,
    path: &Path,
    spans_by_kind: &mut BTreeMap<StructuredFindingKind, Vec<SourceSpan>>,
) {
    if path.is_dir() {
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };

        for entry in entries.flatten() {
            visit_path(root, &entry.path(), spans_by_kind);
        }

        return;
    }

    let Some(language) = language_for_path(path) else {
        return;
    };

    let Ok(source) = fs::read_to_string(path) else {
        return;
    };

    let Some(tree) = parse_source(language, &source) else {
        return;
    };

    let mut file_matches = BTreeMap::new();
    collect_matches(
        root,
        path,
        language,
        &source,
        tree.root_node(),
        &mut file_matches,
    );

    for (kind, spans) in file_matches {
        let entry = spans_by_kind.entry(kind).or_default();
        for span in spans {
            if !entry.contains(&span) {
                entry.push(span);
            }
        }
    }
}

fn language_for_path(path: &Path) -> Option<StructuredLanguage> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("ts") | Some("tsx") | Some("js") | Some("jsx") => Some(StructuredLanguage::TypeScript),
        Some("py") => Some(StructuredLanguage::Python),
        _ => None,
    }
}

fn parse_source(language: StructuredLanguage, source: &str) -> Option<tree_sitter::Tree> {
    let mut parser = Parser::new();
    match language {
        StructuredLanguage::TypeScript => parser
            .set_language(tree_sitter_typescript::language_typescript())
            .ok()?,
        StructuredLanguage::Python => parser.set_language(tree_sitter_python::language()).ok()?,
    }

    parser.parse(source, None)
}

fn collect_matches(
    root: &Path,
    path: &Path,
    language: StructuredLanguage,
    source: &str,
    node: Node<'_>,
    matches: &mut BTreeMap<StructuredFindingKind, Vec<SourceSpan>>,
) {
    for kind in StructuredFindingKind::ALL {
        if is_match(kind, language, node, source) {
            let span = to_source_span(root, path, source, node);
            let entry = matches.entry(kind).or_default();
            if !entry.contains(&span) {
                entry.push(span);
            }
        }
    }

    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_matches(root, path, language, source, child, matches);
        }
    }
}

fn is_match(
    kind: StructuredFindingKind,
    language: StructuredLanguage,
    node: Node<'_>,
    source: &str,
) -> bool {
    if !node_matches_kind_shape(language, node) {
        return false;
    }

    let text = node.utf8_text(source.as_bytes()).unwrap_or_default();
    if contains_approval_gate(text) || ancestor_has_approval_gate(node, source) {
        return false;
    }

    match (kind, language) {
        (StructuredFindingKind::UnsafeShellExecution, StructuredLanguage::TypeScript) => {
            text.contains("child_process.exec")
                || text.contains("child_process.spawn")
                || text.contains("child_process.execFile")
                || text.contains("exec(")
                || text.contains("spawn(")
                || text.contains("execFile(")
        }
        (StructuredFindingKind::UnsafeShellExecution, StructuredLanguage::Python) => {
            text.contains("subprocess.run")
                || text.contains("subprocess.Popen")
                || text.contains("subprocess.call")
                || text.contains("subprocess.check_output")
                || (text.contains("shell=True")
                    && (text.contains("subprocess.") || text.contains("os.system(")))
                || text.contains("os.system(")
        }
        (StructuredFindingKind::UnsafeFilesystemWrite, StructuredLanguage::TypeScript) => {
            text.contains("fs.writeFile")
                || text.contains("fs.writeFileSync")
                || text.contains("fs.appendFile")
                || text.contains("fs.appendFileSync")
                || text.contains("createWriteStream(")
        }
        (StructuredFindingKind::UnsafeFilesystemWrite, StructuredLanguage::Python) => {
            is_python_write_open(text)
                || text.contains(".write_text(")
                || text.contains(".write_bytes(")
        }
        (StructuredFindingKind::OutboundNetworkEgress, StructuredLanguage::TypeScript) => {
            text.contains("fetch(")
                || text.contains("axios.")
                || text.contains("http.request")
                || text.contains("https.request")
        }
        (StructuredFindingKind::OutboundNetworkEgress, StructuredLanguage::Python) => {
            text.contains("requests.get")
                || text.contains("requests.post")
                || text.contains("requests.put")
                || text.contains("httpx.")
                || text.contains("urllib.request.urlopen")
        }
    }
}

fn node_matches_kind_shape(language: StructuredLanguage, node: Node<'_>) -> bool {
    match language {
        StructuredLanguage::TypeScript => matches!(
            node.kind(),
            "call_expression" | "assignment_expression" | "member_expression"
        ),
        StructuredLanguage::Python => {
            matches!(
                node.kind(),
                "call" | "attribute" | "assignment" | "named_expression"
            )
        }
    }
}

fn is_python_write_open(text: &str) -> bool {
    if !text.contains("open(") {
        return false;
    }

    [
        "\"w\"",
        "'w'",
        "\"a\"",
        "'a'",
        "\"wb\"",
        "'wb'",
        "\"ab\"",
        "'ab'",
        "mode=\"w\"",
        "mode='w'",
        "mode=\"a\"",
        "mode='a'",
        "mode=\"wb\"",
        "mode='wb'",
        "mode=\"ab\"",
        "mode='ab'",
    ]
    .iter()
    .any(|mode| text.contains(mode))
}

fn contains_approval_gate(text: &str) -> bool {
    let normalized = text.to_ascii_lowercase();
    normalized.contains("approval_required")
        || normalized.contains("requires_approval")
        || normalized.contains("ask_for_approval")
        || normalized.contains("confirm_before_exec")
}

fn ancestor_has_approval_gate(node: Node<'_>, source: &str) -> bool {
    let mut current = node.parent();
    let mut depth = 0usize;
    while let Some(ancestor) = current {
        if let Ok(text) = ancestor.utf8_text(source.as_bytes()) {
            if contains_approval_gate(text) {
                return true;
            }
        }
        current = ancestor.parent();
        depth += 1;
        if depth >= 4 {
            break;
        }
    }

    false
}

fn to_source_span(root: &Path, path: &Path, source: &str, node: Node<'_>) -> SourceSpan {
    let start = node.start_byte();
    let prefix = &source[..start.min(source.len())];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit('\n')
        .next()
        .map(|segment| segment.chars().count() + 1);

    SourceSpan {
        file: path
            .strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string(),
        line,
        column,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use crate::structured::{analyze_openclaw_project, StructuredFindingKind};

    fn write_fixture(root: &std::path::Path, relative_path: &str, content: &str) {
        let file = root.join(relative_path);
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent).expect("fixture parent should exist");
        }
        fs::write(file, content).expect("fixture should be written");
    }

    #[test]
    fn finds_typescript_shell_exec_with_source_span() {
        let temp = tempdir().expect("tempdir should be created");
        write_fixture(
            temp.path(),
            "src/agent.ts",
            r#"
import child_process from "child_process";

export function runDangerous(input: string) {
  return child_process.exec(input);
}
"#,
        );

        let report = analyze_openclaw_project(temp.path());
        let finding = report
            .finding(StructuredFindingKind::UnsafeShellExecution)
            .expect("structured finding should exist");
        assert_eq!(finding.source_spans[0].file, "src/agent.ts");
    }

    #[test]
    fn finds_typescript_filesystem_write_with_source_span() {
        let temp = tempdir().expect("tempdir should be created");
        write_fixture(
            temp.path(),
            "src/writer.ts",
            r#"
import fs from "fs";

export function persistAuditLog(contents: string) {
  return fs.writeFile("audit.log", contents, () => undefined);
}
"#,
        );

        let report = analyze_openclaw_project(temp.path());
        let finding = report
            .finding(StructuredFindingKind::UnsafeFilesystemWrite)
            .expect("filesystem write finding should exist");
        assert_eq!(finding.source_spans[0].file, "src/writer.ts");
    }

    #[test]
    fn ignores_python_filesystem_write_when_inline_approval_gate_exists() {
        let temp = tempdir().expect("tempdir should be created");
        write_fixture(
            temp.path(),
            "agent.py",
            r#"
from pathlib import Path

def write_safe(contents):
    approval_required = True
    return Path("audit.log").write_text(contents)
"#,
        );

        let report = analyze_openclaw_project(temp.path());
        assert!(report
            .finding(StructuredFindingKind::UnsafeFilesystemWrite)
            .is_none());
    }

    #[test]
    fn finds_typescript_network_egress_with_source_span() {
        let temp = tempdir().expect("tempdir should be created");
        write_fixture(
            temp.path(),
            "src/egress.ts",
            r#"
export async function sendAudit(contents: string) {
  return fetch("https://example.com/audit", {
    method: "POST",
    body: contents,
  });
}
"#,
        );

        let report = analyze_openclaw_project(temp.path());
        let finding = report
            .finding(StructuredFindingKind::OutboundNetworkEgress)
            .expect("network egress finding should exist");
        assert_eq!(finding.source_spans[0].file, "src/egress.ts");
    }
    #[test]
    fn finds_python_network_egress_with_source_span() {
        let temp = tempdir().expect("tempdir should be created");
        write_fixture(
            temp.path(),
            "agent.py",
            r#"
import requests


def send_risky(payload):
    return requests.post("https://example.com/audit", json=payload)
"#,
        );

        let report = analyze_openclaw_project(temp.path());
        let finding = report
            .finding(StructuredFindingKind::OutboundNetworkEgress)
            .expect("python network egress finding should exist");
        assert_eq!(finding.source_spans[0].file, "agent.py");
    }

    #[test]
    fn ignores_python_network_egress_when_inline_approval_gate_exists() {
        let temp = tempdir().expect("tempdir should be created");
        write_fixture(
            temp.path(),
            "agent.py",
            r#"
import requests


def send_safe(payload):
    approval_required = True
    return requests.post("https://example.com/audit", json=payload)
"#,
        );

        let report = analyze_openclaw_project(temp.path());
        assert!(report
            .finding(StructuredFindingKind::OutboundNetworkEgress)
            .is_none());
    }

    #[test]
    fn mixed_project_returns_multiple_finding_kinds() {
        let temp = tempdir().expect("tempdir should be created");
        write_fixture(
            temp.path(),
            "src/agent.ts",
            r#"
import child_process from "child_process";

export function runDangerous(input: string) {
  return child_process.exec(input);
}
"#,
        );
        write_fixture(
            temp.path(),
            "src/writer.py",
            r#"
from pathlib import Path

def persist(contents):
    return Path("audit.log").write_text(contents)
"#,
        );
        write_fixture(
            temp.path(),
            "src/egress.ts",
            r#"
import axios from "axios";

export function notify(payload: unknown) {
  return axios.post("https://example.com/notify", payload);
}
"#,
        );

        let report = analyze_openclaw_project(temp.path());

        assert!(report
            .finding(StructuredFindingKind::UnsafeShellExecution)
            .is_some());
        assert!(report
            .finding(StructuredFindingKind::UnsafeFilesystemWrite)
            .is_some());
        assert!(report
            .finding(StructuredFindingKind::OutboundNetworkEgress)
            .is_some());
    }
}
