use std::path::{Component, Path};
use crate::{Category, Finding};

/// Lexical filtering is not an authorization mechanism. The platform module
/// separately opens every component relative to a trusted directory handle.
pub fn valid_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path.components().all(|p| matches!(p, Component::Normal(_)))
}
pub fn protected_file(path: &str) -> bool {
    let p = path.to_lowercase();
    let name = p.rsplit('/').next().unwrap_or("");
    [".env", "index.php", "artisan", "composer.json", "composer.lock", "pom.xml",
        "build.gradle", "build.gradle.kts", "php.ini", "php-fpm.conf", "nginx.conf"].contains(&name)
        || p.ends_with(".jar") || p.ends_with(".war")
        || name.starts_with("application.") || name.starts_with("application-")
        || name.starts_with("bootstrap.") || name.starts_with("bootstrap-")
        || p.starts_with("config/") || p.starts_with("bootstrap/")
        || p.starts_with("vendor/") || p.starts_with("node_modules/")
        || p.contains("/.git/") || p.starts_with(".git/")
}
pub fn recyclable(f: &Finding) -> bool {
    f.category == Category::File && !f.protected && f.file_id.is_some()
        && (f.state == "pending" || f.state == "restored")
}
pub fn safe_display(bytes: &[u8]) -> String {
    let mut out = String::new();
    for c in String::from_utf8_lossy(bytes).chars() {
        if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
            out.push_str(&format!("\\u{{{:04x}}}", c as u32));
        } else { out.push(c); }
    }
    out
}
pub fn csv_cell(s: &str) -> String {
    let trimmed = s.trim_start();
    let dangerous = trimmed.starts_with(['=', '+', '-', '@']) || s.starts_with(['\t', '\r', '\n']);
    let text = if dangerous { format!("'{s}") } else { s.to_owned() };
    format!("\"{}\"", text.replace('"', "\"\""))
}
pub fn html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
        .replace('"', "&quot;").replace('\'', "&#39;")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn denies_traversal() { for s in ["", "../a", "/etc/a", "a/../../b"] { assert!(!valid_relative(Path::new(s))); } }
    #[test] fn accepts_regular_relative() { assert!(valid_relative(Path::new("public/file.zip"))); }
    #[test] fn protects_deployments() { assert!(protected_file("services/app.jar")); assert!(protected_file("public/index.php")); assert!(!protected_file("app.jar.bak")); }
    #[test] fn csv_injection() { assert!(csv_cell(" =SUM(1,2)").starts_with("\"'")); }
    #[test] fn html_injection() { assert_eq!(html("<script>"), "&lt;script&gt;"); }
    #[test] fn escapes_controls() { assert_eq!(safe_display(b"a\nb"), "a\\u{000a}b"); }
}
