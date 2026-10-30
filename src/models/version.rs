use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct VersionInfo {
    pub managed_by: Option<String>,
    pub current: String,
    pub sing_box_version: String,
    pub sing_box_revision: String,
    pub sing_box_tags: String,
    pub commit_short: Option<String>,
    pub commit_full: Option<String>,
    pub commit_url: Option<String>,
    pub latest: Option<String>,
    pub has_update: bool,
    pub download_url: Option<String>,
}

#[derive(Clone, Deserialize)]
pub struct GitHubRelease {
    pub tag_name: String,
    #[serde(default)]
    pub target_commitish: Option<String>,
    pub assets: Vec<GitHubAsset>,
}

#[derive(Clone, Deserialize)]
pub struct GitHubAsset {
    pub name: String,
    #[allow(dead_code)]
    pub browser_download_url: String,
    pub size: u64,
}

#[derive(Clone, Deserialize)]
pub struct GitHubCommit {
    pub sha: String,
}
