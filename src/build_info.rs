pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GIT_COMMIT_FULL: &str = env!("MIAO_GIT_COMMIT_FULL");
pub const GIT_COMMIT_SHORT: &str = env!("MIAO_GIT_COMMIT_SHORT");
pub const GIT_COMMIT_URL: &str = env!("MIAO_GIT_COMMIT_URL");

pub fn current_version() -> String {
    format!("v{}", VERSION)
}

pub fn git_commit_full() -> Option<String> {
    known_value(GIT_COMMIT_FULL)
}

pub fn git_commit_short() -> Option<String> {
    known_value(GIT_COMMIT_SHORT)
}

pub fn git_commit_url() -> Option<String> {
    known_value(GIT_COMMIT_URL)
}

fn known_value(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "unknown" {
        None
    } else {
        Some(trimmed.to_string())
    }
}
