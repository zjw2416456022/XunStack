use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity { Info, Low, Medium, High, Critical }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Category { File, Config, Vulnerability }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Fingerprint {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub mtime_ns: i128,
    pub mode: u32,
    pub links: u64,
    pub sha256: Option<String>,
    pub hash_complete: bool,
}
impl Fingerprint {
    /// Rename can change ctime. Do not confuse an expected rename with a
    /// content change; compare identity, size, mtime and complete SHA-256.
    pub fn same_object(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode
            && self.size == other.size && self.mtime_ns == other.mtime_ns
            && self.links == 1 && other.links == 1
            && self.hash_complete && other.hash_complete
            && self.sha256.is_some() && self.sha256 == other.sha256
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub root: String,
    pub profiles: Vec<String>,
    pub created_at: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub rule_id: String,
    pub summary: String,
    pub source: String,
    pub line: Option<usize>,
    pub observed: Option<String>,
    pub runtime_value: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub scan_id: String,
    pub project_id: String,
    pub file_id: Option<String>,
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    pub path: String,
    pub size: u64,
    pub rule_version: String,
    pub evidence: Vec<Evidence>,
    pub advice: String,
    pub verification: String,
    pub protected: bool,
    pub state: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub id: String,
    pub scan_id: String,
    pub project_id: String,
    /// Lossless Unix path bytes, never the escaped display path.
    pub relative_b64: String,
    pub display_path: String,
    pub fingerprint: Fingerprint,
    pub protected: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coverage {
    pub path: String,
    pub code: String,
    pub message: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    pub id: String,
    pub project_id: String,
    pub root: String,
    pub status: String,
    pub created_at: String,
    pub finished_at: Option<String>,
    pub checked: usize,
    pub issues: usize,
    pub coverage_count: usize,
    pub profiles: Vec<String>,
    pub rule_version: String,
    pub advisory_snapshot: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecycleItem {
    pub id: String,
    pub finding_id: String,
    pub file: FileRecord,
    pub project: Project,
    pub private_name: String,
    pub captured: Option<Fingerprint>,
    pub state: String,
    pub recycled_at: String,
    pub updated_at: String,
    pub error: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Draft {
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    pub evidence: Vec<Evidence>,
    pub advice: String,
    pub verification: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_files: usize,
    pub max_depth: usize,
    pub content_bytes: u64,
    pub hash_bytes: u64,
    pub archive_bytes: u64,
    pub archive_members: usize,
    pub max_seconds: u64,
}
impl Default for Limits {
    fn default() -> Self { Self { max_files: 100_000, max_depth: 48,
        content_bytes: 2 * 1024 * 1024, hash_bytes: 64 * 1024 * 1024,
        archive_bytes: 32 * 1024 * 1024, archive_members: 2000, max_seconds: 1800 } }
}
