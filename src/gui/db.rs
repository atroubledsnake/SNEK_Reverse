use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectDb {
    pub function_names: HashMap<u64, String>,
    pub labels: HashMap<u64, String>,
    pub comments: HashMap<u64, String>,
    pub bookmarks: BTreeSet<u64>,
}

impl ProjectDb {
    pub fn load(path: &Path) -> Option<Self> {
        let data = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&data).ok()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let data = serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string());
        std::fs::write(path, data)
    }
}
