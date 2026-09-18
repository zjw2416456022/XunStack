//! Content-baseline comparison. Uses lossless path identities, never the UI path.
//! An incomplete traversal must not turn an unseen path into a deletion.
use anyhow::{ensure, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use crate::FileRecord;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind { Added, Modified, Removed, Unverified }

#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub path: String,
    pub kind: ChangeKind,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Comparison {
    pub summary: BTreeMap<String, usize>,
    pub items: Vec<Change>,
    pub total_changes: usize,
}

/// `before` must be a previously approved complete enumeration. The API is
/// responsible for verifying project, root and scope before calling this.
/// `complete_enumeration` describes the CURRENT task, not its success badge.
pub fn compare(before: &[FileRecord], after: &[FileRecord], complete_enumeration: bool) -> Result<Comparison> {
    let mut old = BTreeMap::new();
    let mut new = BTreeMap::new();
    for file in before {
        ensure!(old.insert(&file.relative_b64, file).is_none(), "duplicate baseline path identity");
    }
    for file in after {
        ensure!(new.insert(&file.relative_b64, file).is_none(), "duplicate scan path identity");
    }
    let mut result = Comparison::default();
    for name in ["added", "modified", "removed", "unverified", "unchanged"] {
        result.summary.insert(name.into(), 0);
    }
    let mut push = |name: &str, path: &str, kind: ChangeKind, reason: &str| {
        *result.summary.entry(name.into()).or_default() += 1;
        result.items.push(Change { path: path.into(), kind, reason: reason.into() });
    };
    let mut unchanged = 0;
    for (key, old_file) in &old {
        let Some(new_file) = new.get(key) else {
            if complete_enumeration {
                push("removed", &old_file.display_path, ChangeKind::Removed, "完整枚举中未再出现该路径；不推断是谁删除了它。");
            } else {
                push("unverified", &old_file.display_path, ChangeKind::Unverified, "本次枚举不完整，不能将未出现的路径认定为已删除。");
            }
            continue;
        };
        let a = &old_file.fingerprint;
        let b = &new_file.fingerprint;
        if !(a.hash_complete && b.hash_complete && a.sha256.is_some() && b.sha256.is_some()) {
            push("unverified", &new_file.display_path, ChangeKind::Unverified, "至少一侧没有取得完整内容哈希，不能认定内容未变化。");
        } else if a.sha256 != b.sha256 || a.size != b.size || (a.mode & 0o7777) != (b.mode & 0o7777) {
            push("modified", &new_file.display_path, ChangeKind::Modified, "完整内容哈希、大小或权限与已批准快照不同；变化不直接等同恶意。");
        } else {
            unchanged += 1;
        }
    }
    for (key, file) in &new {
        if !old.contains_key(key) {
            push("added", &file.display_path, ChangeKind::Added, "相较于已批准的完整基线新增；仍需结合业务发布核对。");
        }
    }
    result.summary.insert("unchanged".into(), unchanged);
    result.total_changes = result.items.len();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Fingerprint;
    fn file(key: &str, hash: &str) -> FileRecord {
        FileRecord { id: key.into(), scan_id: "scan".into(), project_id: "p".into(),
            relative_b64: key.into(), display_path: format!("public/{key}"), protected: false,
            fingerprint: Fingerprint { device: 1, inode: 2, size: 3, mtime_ns: 0,
                mode: 0o100640, links: 1, sha256: Some(hash.repeat(64)), hash_complete: true } }
    }
    #[test] fn same_content_is_unchanged() {
        let f = file("a", "a");
        let mut next = f.clone(); next.fingerprint.inode = 99;
        let c = compare(&[f], &[next], true).expect("comparison");
        assert_eq!(c.summary["unchanged"], 1); assert!(c.items.is_empty());
    }
    #[test] fn content_change_is_not_ignored() {
        let c = compare(&[file("a", "a")], &[file("a", "b")], true).expect("comparison");
        assert_eq!(c.items[0].kind, ChangeKind::Modified);
    }
    #[test] fn incomplete_scan_does_not_claim_deletion() {
        let c = compare(&[file("a", "a")], &[], false).expect("comparison");
        assert_eq!(c.summary["removed"], 0); assert_eq!(c.summary["unverified"], 1);
    }
    #[test] fn complete_scan_can_report_missing_path() {
        let c = compare(&[file("a", "a")], &[], true).expect("comparison");
        assert_eq!(c.summary["removed"], 1);
    }
    #[test] fn missing_hash_cannot_mean_unchanged() {
        let mut f = file("a", "a"); f.fingerprint.hash_complete = false;
        let c = compare(&[file("a", "a")], &[f], true).expect("comparison");
        assert_eq!(c.summary["unverified"], 1);
    }
    #[test] fn detects_addition() {
        let c = compare(&[], &[file("b", "b")], true).expect("comparison");
        assert_eq!(c.summary["added"], 1);
    }
    #[test] fn permission_changes_are_visible() {
        let mut next = file("a", "a"); next.fingerprint.mode = 0o100777;
        assert_eq!(compare(&[file("a", "a")], &[next], true).expect("comparison").summary["modified"], 1);
    }
    #[test] fn duplicate_lossless_identity_is_rejected() {
        assert!(compare(&[file("a", "a"), file("a", "b")], &[], true).is_err());
    }
    #[test] fn display_path_collision_does_not_merge_objects() {
        let a = file("raw-a", "a"); let mut b = file("raw-b", "b"); b.display_path = a.display_path.clone();
        let c = compare(&[a], &[b], true).expect("comparison");
        assert_eq!(c.summary["removed"], 1); assert_eq!(c.summary["added"], 1);
    }
}
