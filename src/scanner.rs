use regex::Regex;
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};
use walkdir::{DirEntry, WalkDir};

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub repository: String,
    pub score: u8,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub checked_files: usize,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub critical: usize,
    pub warning: usize,
    pub info: usize,
    pub passed: usize,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub id: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub details: String,
    pub recommendation: String,
    pub file: Option<String>,
    pub line: Option<usize>,
}

fn secret_patterns() -> &'static [( &'static str, Regex)] {
    static PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATTERNS.get_or_init(|| vec![
        ("Private key material", Regex::new(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap()),
        ("Possible AWS access key", Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap()),
        ("Possible GitHub token", Regex::new(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b").unwrap()),
        ("Credential assignment", Regex::new(r#"(?i)\b(api[_-]?key|secret|password|access[_-]?token)\b\s*[:=]\s*["'][^"'\s]{8,}["']"#).unwrap()),
    ])
}

fn ignored(entry: &DirEntry) -> bool {
    if entry.depth() == 0 { return false; }
    let name = entry.file_name().to_string_lossy();
    if entry.file_type().is_dir() {
        return matches!(name.as_ref(), ".git" | "target" | "node_modules" | "vendor" | ".next" | "dist" | "build" | ".venv" | "venv" | "__pycache__");
    }
    false
}

pub fn scan_repository(root: &Path, max_files: usize) -> Result<ScanReport, String> {
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let repo_name = root.file_name().unwrap_or_default().to_string_lossy().to_string();
    let mut findings = Vec::new();
    let mut files = Vec::<PathBuf>::new();
    let mut truncated = false;

    for entry in WalkDir::new(&root).follow_links(false).into_iter().filter_entry(|e| !ignored(e)) {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.file_type().is_file() { continue; }
        if files.len() >= max_files { truncated = true; break; }
        files.push(entry.path().to_path_buf());
    }

    let relative: BTreeSet<String> = files.iter()
        .filter_map(|p| p.strip_prefix(&root).ok())
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .collect();

    let checks = [
        ("README.md", "Documentation", "README is missing", "Add a README with purpose, setup, usage, configuration, and troubleshooting.", "warning"),
        ("LICENSE", "Legal", "License file is missing", "Choose a license that matches your intended use and add its full text.", "warning"),
        (".gitignore", "Git hygiene", ".gitignore is missing", "Ignore build outputs, local environment files, secrets, and editor artifacts.", "warning"),
        (".github/workflows", "CI", "GitHub Actions workflow is missing", "Add CI for formatting, linting, tests, and security checks.", "info"),
    ];
    for (needle, category, title, recommendation, severity) in checks {
        let exists = if needle.ends_with('/') {
            relative.iter().any(|p| p.starts_with(needle))
        } else {
            relative.contains(needle)
        };
        if !exists {
            findings.push(finding(
                format!("missing-{}", needle.replace('/', "-").replace('.', "-")),
                severity, category, title,
                format!("Expected `{needle}` was not found at the repository root."),
                recommendation, None, None,
            ));
        }
    }

    let lockfile_exists = relative.contains("Cargo.lock") || relative.contains("package-lock.json")
        || relative.contains("pnpm-lock.yaml") || relative.contains("yarn.lock")
        || relative.contains("poetry.lock") || relative.contains("uv.lock");
    if !lockfile_exists {
        findings.push(finding("missing-lockfile", "warning", "Reproducible builds",
            "No common dependency lockfile found",
            "For application repositories, a committed lockfile usually improves reproducibility.",
            "Commit the lockfile for your package manager when appropriate. Libraries may intentionally differ.",
            None, None));
    }

    for rel in &relative {
        let lower = rel.to_lowercase();
        if lower == ".env" || lower.ends_with("/.env") || lower == ".env.local" || lower.ends_with("/.env.local") {
            findings.push(finding("env-file", "warning", "Secrets hygiene",
                "Environment file may contain local secrets",
                "A real `.env` file is present in the repository tree. The scanner does not know whether it contains credentials.",
                "Ensure it is ignored by Git; use `.env.example` with placeholders for documentation.",
                Some(rel.clone()), None));
        }
        if lower.contains("id_rsa") || lower.ends_with(".pem") || lower.ends_with(".p12") || lower.ends_with(".pfx") {
            findings.push(finding("private-key-file", "critical", "Secrets hygiene",
                "Potential private-key file detected",
                "A file extension or name commonly associated with private keys was found.",
                "Remove it from version control, rotate exposed credentials, and review repository history.",
                Some(rel.clone()), None));
        }

        let path = root.join(rel);
        let metadata = match fs::metadata(&path) { Ok(m) => m, Err(_) => continue };
        if metadata.len() > 2 * 1024 * 1024 { continue; }
        if is_binary_or_ignored_text(&lower) { continue; }
        let content = match fs::read_to_string(&path) { Ok(c) => c, Err(_) => continue };
        for (line_idx, line) in content.lines().enumerate() {
            for (pattern_name, regex) in secret_patterns() {
                if regex.is_match(line) {
                    findings.push(finding(
                        format!("secret-{}-{}", slug(pattern_name), line_idx + 1),
                        "critical", "Secrets hygiene",
                        format!("{pattern_name} pattern found"),
                        "A line matches a heuristic pattern that can indicate a credential. False positives are possible; matched content is never included in the report.",
                        "If this is a real secret, revoke/rotate it immediately and remove it from repository history. Store secrets in environment variables or a secret manager.",
                        Some(rel.clone()), Some(line_idx + 1),
                    ));
                    break;
                }
            }
        }
    }

    if truncated {
        findings.push(finding("scan-truncated", "info", "Scan coverage",
            "File scan limit reached",
            format!("The scan stopped after {max_files} files; results may be incomplete."),
            "Increase MAX_FILES for large monorepos or scan a smaller project directory.",
            None, None));
    }

    if findings.is_empty() {
        findings.push(finding("baseline-clean", "info", "Repository hygiene",
            "No baseline issues detected",
            "The checks completed without finding common repository hygiene issues. This is not a security certification.",
            "Keep CI and dependency audits current; use dedicated secret scanning and code analysis for deeper coverage.",
            None, None));
    }

    findings.sort_by(|a, b| severity_rank(&a.severity).cmp(&severity_rank(&b.severity))
        .then_with(|| a.category.cmp(&b.category))
        .then_with(|| a.title.cmp(&b.title)));

    let summary = Summary {
        critical: findings.iter().filter(|f| f.severity == "critical").count(),
        warning: findings.iter().filter(|f| f.severity == "warning").count(),
        info: findings.iter().filter(|f| f.severity == "info").count(),
        passed: 4usize.saturating_sub(findings.iter().filter(|f| f.id.starts_with("missing-")).count()),
    };
    let penalty = summary.critical * 25 + summary.warning * 10 + summary.info * 2;
    let score = (100usize.saturating_sub(penalty)).min(100) as u8;

    Ok(ScanReport { repository: repo_name, score, summary, findings, checked_files: files.len(), truncated })
}

fn is_binary_or_ignored_text(path: &str) -> bool {
    let ext = path.rsplit('.').next().unwrap_or("");
    matches!(ext, "png" | "jpg" | "jpeg" | "gif" | "webp" | "ico" | "pdf" | "zip" | "gz" | "lock" | "sum" | "svg" | "woff" | "woff2" | "ttf" | "mp4" | "mov" | "exe" | "dll" | "so" | "dylib")
}

fn severity_rank(s: &str) -> u8 {
    match s { "critical" => 0, "warning" => 1, _ => 2 }
}

fn slug(s: &str) -> String {
    s.to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect()
}

fn finding(id: impl Into<String>, severity: &str, category: &str, title: impl Into<String>,
    details: impl Into<String>, recommendation: impl Into<String>, file: Option<String>, line: Option<usize>) -> Finding {
    Finding { id: id.into(), severity: severity.into(), category: category.into(),
        title: title.into(), details: details.into(), recommendation: recommendation.into(), file, line }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn detects_common_missing_project_files() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
        let report = scan_repository(dir.path(), 100).unwrap();
        assert!(report.findings.iter().any(|f| f.id == "missing-README-md"));
        assert!(report.findings.iter().any(|f| f.id == "missing-LICENSE"));
    }

    #[test]
    fn detects_secret_pattern_without_returning_secret_value() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("README.md"), "# Example").unwrap();
        fs::write(dir.path().join("LICENSE"), "MIT").unwrap();
        fs::write(dir.path().join(".gitignore"), ".env").unwrap();
        fs::write(dir.path().join("config.txt"), "api_key = \"supersecretvalue123\"").unwrap();
        let report = scan_repository(dir.path(), 100).unwrap();
        let hit = report.findings.iter().find(|f| f.category == "Secrets hygiene").unwrap();
        assert_eq!(hit.severity, "critical");
        assert!(!hit.details.contains("supersecretvalue123"));
    }
}
