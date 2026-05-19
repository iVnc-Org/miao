use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    println!("cargo:rerun-if-env-changed=GITHUB_REPOSITORY");
    println!("cargo:rerun-if-env-changed=GITHUB_SERVER_URL");
    emit_git_rerun_paths();

    let commit_full = env_value("GITHUB_SHA").or_else(|| git_output(&["rev-parse", "HEAD"]));
    let commit_short = commit_full
        .as_deref()
        .and_then(|commit| commit.get(..commit.len().min(7)))
        .map(str::to_string)
        .or_else(|| git_output(&["rev-parse", "--short", "HEAD"]));
    let commit_url = commit_full.as_deref().and_then(commit_url);

    emit("MIAO_GIT_COMMIT_FULL", commit_full.as_deref());
    emit("MIAO_GIT_COMMIT_SHORT", commit_short.as_deref());
    emit("MIAO_GIT_COMMIT_URL", commit_url.as_deref());
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn emit_git_rerun_paths() {
    println!("cargo:rerun-if-changed=.git/HEAD");

    let head = match std::fs::read_to_string(".git/HEAD") {
        Ok(head) => head,
        Err(_) => return,
    };
    let Some(reference) = head.trim().strip_prefix("ref: ") else {
        return;
    };

    println!("cargo:rerun-if-changed=.git/{}", reference);
}

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn commit_url(commit: &str) -> Option<String> {
    let repository = env_value("GITHUB_REPOSITORY").or_else(github_repository_from_origin)?;
    let server = env_value("GITHUB_SERVER_URL").unwrap_or_else(|| "https://github.com".to_string());
    Some(format!(
        "{}/{}/commit/{}",
        server.trim_end_matches('/'),
        repository,
        commit
    ))
}

fn github_repository_from_origin() -> Option<String> {
    let origin = git_output(&["remote", "get-url", "origin"])?;
    let slug = if let Some((_, slug)) = origin.split_once("github.com/") {
        slug
    } else if let Some((_, slug)) = origin.split_once("github.com:") {
        slug
    } else {
        return None;
    };

    Some(slug.trim_end_matches(".git").trim_matches('/').to_string())
        .filter(|slug| !slug.is_empty() && slug.contains('/'))
}

fn emit(name: &str, value: Option<&str>) {
    println!("cargo:rustc-env={}={}", name, value.unwrap_or("unknown"));
}
