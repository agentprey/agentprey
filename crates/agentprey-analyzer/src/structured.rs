use std::{fs, path::Path};

use agentprey_core::SourceSpan;
use tree_sitter::{Node, Parser};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuredFindingKind {
    UnsafeShellExecution,
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
    let mut report = StructuredOpenClawReport::default();
    visit_path(root, root, &mut report);
    report
}

fn visit_path(root: &Path, path: &Path, report: &mut StructuredOpenClawReport) {
    if path.is_dir() {
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };

        for entry in entries.flatten() {
            visit_path(root, &entry.path(), report);
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

    let mut matches = Vec::new();
    collect_matches(
        root,
        path,
        language,
        &source,
        tree.root_node(),
        &mut matches,
    );

    if matches.is_empty() {
        return;
    }

    report.findings.push(StructuredFinding {
        kind: StructuredFindingKind::UnsafeShellExecution,
        summary:
            "Structured analysis found shell execution reachable without an obvious approval gate."
                .to_string(),
        observed_capabilities: vec!["shell-exec".to_string()],
        source_spans: matches,
    });
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
    matches: &mut Vec<SourceSpan>,
) {
    if is_shell_exec_match(language, node, source) {
        matches.push(to_source_span(root, path, source, node));
    }

    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_matches(root, path, language, source, child, matches);
        }
    }
}

fn is_shell_exec_match(language: StructuredLanguage, node: Node<'_>, source: &str) -> bool {
    if !matches!(
        node.kind(),
        "call_expression" | "assignment_expression" | "member_expression"
    ) {
        return false;
    }

    let text = node.utf8_text(source.as_bytes()).unwrap_or_default();
    if contains_approval_gate(text) || ancestor_has_approval_gate(node, source) {
        return false;
    }

    match language {
        StructuredLanguage::TypeScript => {
            text.contains("child_process.exec")
                || text.contains("child_process.spawn")
                || text.contains("child_process.execFile")
                || text.contains("exec(")
                || text.contains("spawn(")
                || text.contains("execFile(")
        }
        StructuredLanguage::Python => {
            text.contains("subprocess.run")
                || text.contains("subprocess.Popen")
                || text.contains("subprocess.call")
                || text.contains("subprocess.check_output")
                || (text.contains("shell=True")
                    && (text.contains("subprocess.") || text.contains("os.system(")))
                || text.contains("os.system(")
        }
    }
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

    #[test]
    fn finds_typescript_shell_exec_with_source_span() {
        let temp = tempdir().expect("tempdir should be created");
        let file = temp.path().join("src/agent.ts");
        fs::create_dir_all(file.parent().expect("ts file should have parent"))
            .expect("parent directory should exist");
        fs::write(
            &file,
            r#"
import child_process from "child_process";

export function runDangerous(input: string) {
  return child_process.exec(input);
}
"#,
        )
        .expect("fixture should be written");

        let report = analyze_openclaw_project(temp.path());
        let finding = report
            .finding(StructuredFindingKind::UnsafeShellExecution)
            .expect("structured finding should exist");
        assert_eq!(finding.source_spans[0].file, "src/agent.ts");
    }

    #[test]
    fn ignores_python_exec_when_inline_approval_gate_exists() {
        let temp = tempdir().expect("tempdir should be created");
        let file = temp.path().join("agent.py");
        fs::write(
            &file,
            r#"
import subprocess

def run_safe(cmd):
    approval_required = True
    return subprocess.run(cmd, shell=True)
"#,
        )
        .expect("fixture should be written");

        let report = analyze_openclaw_project(temp.path());
        assert!(report.findings.is_empty());
    }
}
