//! Heuristics are leads, not an assertion that a file is malicious.
use crate::{Category, Component, Draft, Evidence, Severity};
use serde_json::Value;

fn draft(category: Category, severity: Severity, title: &str, rule: &str, summary: &str, path: &str, advice: &str) -> Draft {
    Draft { category, severity, title: title.into(), evidence: vec![Evidence {
        rule_id: rule.into(), summary: summary.into(), source: path.into(), line: None,
        observed: None, runtime_value: None }], advice: advice.into(), verification: "static_observation".into() }
}
pub fn analyze(path: &str, bytes: &[u8], mode: u32) -> Vec<Draft> {
    let p = path.to_lowercase();
    let name = p.rsplit('/').next().unwrap_or("");
    let public = p.starts_with("public/") || p.starts_with("static/") || p.starts_with("wwwroot/");
    let upload = p.contains("upload/") || p.contains("uploads/");
    let archive = [".zip", ".tar", ".tgz", ".tar.gz", ".7z", ".rar"].iter().any(|x| p.ends_with(x));
    let backup = [".bak", ".old", ".sql", ".sql.gz", ".dump", ".hprof", ".swp", "~"].iter().any(|x| p.ends_with(x));
    let mut out = Vec::new();
    if archive || backup {
        out.push(draft(Category::File, if public { Severity::High } else { Severity::Medium },
            if archive { "归档文件需要核对用途" } else { "备份或调试残留" }, "FILE-ARCHIVE-001",
            if public { "位于声明风格的公开目录，尚未验证 HTTP 可下载" } else { "可能是正常交付材料，也可能包含源码、配置或数据" }, path,
            "核对业务用途与 Web 根配置；不需要的文件可在批准范围内移入回收站。"));
    }
    if name.starts_with(".env.") || name.ends_with(".pem") || name.ends_with(".key") {
        out.push(draft(Category::File, Severity::High, "敏感配置副本或密钥文件", "FILE-SECRET-001",
            "只记录文件类型线索，不读取或展示秘密值", path, "确认该文件的部署用途、访问范围与权限；必要时轮换泄露的凭据。"));
    }
    if upload && [".php", ".phtml", ".jsp", ".jspx"].iter().any(|x| p.ends_with(x)) {
        out.push(draft(Category::File, Severity::High, "上传目录存在服务端脚本", "FILE-UPLOAD-001",
            "路径与扩展名形成风险线索，不代表已证明可以执行", path, "核查上传策略与服务器脚本执行规则，确认业务用途后处置。"));
    }
    if bytes.starts_with(b"\x7fELF") || bytes.starts_with(b"MZ") {
        out.push(draft(Category::File, Severity::Medium, "应用目录存在二进制程序", "FILE-BINARY-001",
            "文件头识别为可执行格式，合法部署工具也可能命中", path, "核对发布清单和哈希来源，不以文件格式直接判定恶意。"));
    }
    if mode & 0o002 != 0 {
        out.push(draft(Category::File, Severity::Medium, "文件允许其他用户写入", "FILE-MODE-001",
            "Unix other-write 位已设置", path, "先核对业务写入身份，再调整最小权限；不要自动 chmod 业务目录。"));
    }
    if p.ends_with(".php") || p.ends_with(".phtml") {
        let text = String::from_utf8_lossy(bytes).to_lowercase();
        let exec = ["eval(", "eval (", "shell_exec(", "system(", "passthru(", "assert("].iter().any(|x| text.contains(x));
        let input = ["$_post", "$_get", "$_request", "base64_decode(", "gzinflate("].iter().any(|x| text.contains(x));
        if exec && input {
            out.push(draft(Category::File, Severity::High, "脚本组合特征需要复核", "FILE-SCRIPT-002",
                "同文件出现动态执行与输入/解码特征；未进行数据流证明", path,
                "人工核对执行链与业务用途。此规则会命中合法代码，不能直接认定 WebShell。"));
        }
    }
    if name == ".ds_store" || name == "thumbs.db" {
        out.push(draft(Category::File, Severity::Low, "开发环境附带文件", "FILE-NOISE-001", "非应用运行必需的桌面元数据", path, "确认无业务用途后移入回收站。"));
    }
    if name == ".env" || name.ends_with(".ini") || name.ends_with(".conf") || name.ends_with(".properties") || name.ends_with(".yml") || name.ends_with(".yaml") {
        out.extend(config_observations(path, bytes));
    }
    out
}
/// A conservative key/value observer. It intentionally does not claim to
/// resolve YAML nesting, includes, environment interpolation or FPM overrides.
pub fn config_observations(path: &str, bytes: &[u8]) -> Vec<Draft> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    for (line, raw) in text.lines().take(20_000).enumerate() {
        let raw = raw.trim();
        if raw.starts_with(['#', ';']) { continue; }
        let Some((key, val)) = raw.split_once('=').or_else(|| raw.split_once(':')) else { continue; };
        let k = key.trim().to_lowercase();
        let val = val.split(';').next().unwrap_or("").trim().trim_matches(['"', '\'']);
        let low = val.to_lowercase();
        let on = ["1", "on", "true", "yes"].contains(&low.as_str());
        let item = match k.as_str() {
            "app_debug" if on => Some((Severity::High, "生产调试配置线索", "CONF-DEBUG-001", "静态文件出现 APP_DEBUG 开启；配置缓存和运行时值未核验。")),
            "allow_url_include" if on => Some((Severity::High, "允许远程包含的配置线索", "CONF-PHP-001", "仅观察文件；需核查指定 PHP-FPM 实例与覆盖来源。")),
            "display_errors" if on => Some((Severity::Medium, "错误输出可能暴露内部信息", "CONF-PHP-002", "生产环境建议核对关闭错误展示并保留日志。")),
            "auto_prepend_file" | "auto_append_file" if !low.is_empty() && low != "none" => Some((Severity::Medium, "自动加载文件需要核实", "CONF-PHP-003", "可能是正常组件，也可能是非预期持久化；不执行目标文件。")),
            "disable_functions" => {
                let disabled: Vec<_> = low.split(',').map(str::trim).collect();
                if ["exec", "system", "shell_exec", "proc_open"].iter().any(|x| !disabled.contains(x)) {
                    Some((Severity::Info, "命令/进程能力未全部限制", "CONF-PHP-004", "加固建议，不等于可利用漏洞；CLI/队列可能正常依赖这些能力。"))
                } else { None }
            },
            "management.endpoints.web.exposure.include" if val.contains('*') => Some((Severity::Medium, "管理端点暴露配置需要核查", "CONF-JAVA-001", "未验证认证、网络可达性和运行时配置。")),
            "spring.h2.console.enabled" if on => Some((Severity::Medium, "数据库控制台配置开启", "CONF-JAVA-002", "需核对环境、访问限制和真实运行状态。")),
            "server.error.include-stacktrace" if low == "always" => Some((Severity::Medium, "错误响应包含堆栈", "CONF-JAVA-003", "生产环境需审查内部信息披露。")),
            _ => None,
        };
        if let Some((sev, title, rule, advice)) = item {
            let mut d = draft(Category::Config, sev, title, rule, "静态键值观察；未执行项目、未解析全部覆盖链", path, advice);
            d.evidence[0].line = Some(line + 1);
            // Only persist nonsecret allowlisted boolean/config keys. File paths
            // in prepend/append can reveal sensitive material, so redact them.
            d.evidence[0].observed = Some(if k.contains("_file") { format!("{k} = [已设置，路径不导出]") } else { format!("{k} = {}", val.chars().take(180).collect::<String>()) });
            out.push(d);
        }
    }
    out
}
pub fn identify_from_text(path: &str, bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes).to_lowercase();
    let mut p = Vec::new();
    if path.ends_with("composer.json") && text.contains("laravel/framework") { p.push("Laravel".into()); }
    if text.contains("org.springframework.boot") || text.contains("spring-boot") || text.contains("spring-boot-version:") { p.push("Spring Boot".into()); }
    if text.contains("org.springframework.cloud") || text.contains("spring-cloud") { p.push("Spring Cloud".into()); }
    if text.contains("org.springblade") || text.contains("bladex") { p.push("BladeX".into()); }
    p
}
pub fn components(path: &str, bytes: &[u8]) -> Vec<Component> {
    let mut out = Vec::new();
    if path.ends_with("composer.lock") {
        if let Ok(root) = serde_json::from_slice::<Value>(bytes) {
            // packages-dev is deliberately separate; deployment applicability
            // is unknown and dev packages are not silently counted as runtime.
            if let Some(packages) = root.get("packages").and_then(Value::as_array) {
                for p in packages.iter().take(20_000) {
                    if let (Some(n), Some(v)) = (p.get("name").and_then(Value::as_str), p.get("version").and_then(Value::as_str)) {
                        out.push(Component { ecosystem: "Packagist".into(), name: n.into(), version: v.trim_start_matches('v').into(), source: path.into() });
                    }
                }
            }
        }
    }
    if path.ends_with("pom.properties") {
        let text = String::from_utf8_lossy(bytes);
        let kv: std::collections::HashMap<_, _> = text.lines().filter(|l| !l.trim_start().starts_with('#')).filter_map(|l| l.split_once('=')).map(|(k,v)| (k.trim(),v.trim())).collect();
        if let (Some(g), Some(a), Some(v)) = (kv.get("groupId"), kv.get("artifactId"), kv.get("version")) {
            out.push(Component { ecosystem: "Maven".into(), name: format!("{g}:{a}"), version: (*v).into(), source: path.into() });
        }
    }
    out
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn jar_not_archive_alarm() { assert!(analyze("app.jar", b"PK", 0o644).is_empty()); }
    #[test] fn upload_script() { assert!(analyze("public/uploads/test.php", b"<?php echo 1;", 0o644).iter().any(|x| x.severity == Severity::High)); }
    #[test] fn innocent_php() { assert!(analyze("app/Foo.php", b"<?php echo 'ok';", 0o644).is_empty()); }
    #[test] fn backup_not_critical() { assert!(analyze("release.zip", b"", 0o644).iter().all(|x| x.severity != Severity::Critical)); }
    #[test] fn config_no_runtime_claim() { let d = config_observations(".env", b"APP_DEBUG=true\nDB_PASSWORD=secret"); assert_eq!(d.len(),1); assert!(d[0].evidence[0].runtime_value.is_none()); assert!(!serde_json::to_string(&d).expect("serialize").contains("secret")); }
    #[test] fn disable_functions_is_guidance() { assert_eq!(config_observations("php.ini", b"disable_functions=exec")[0].severity, Severity::Info); }
    #[test] fn comments_ignored() { assert!(config_observations("php.ini", b"; display_errors=On").is_empty()); }
    #[test] fn boot_cloud_overlay() { let p=identify_from_text("pom.xml", b"org.springframework.boot org.springframework.cloud org.springblade"); assert_eq!(p.len(),3); }
    #[test] fn composer_inventory() { let c=components("composer.lock", br#"{"packages":[{"name":"test/pkg","version":"v1.2.3"}]}"#); assert_eq!(c[0].version,"1.2.3"); }
}
