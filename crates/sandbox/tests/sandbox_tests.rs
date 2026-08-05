use sandbox::{parse_command_str, sanitize_env, SandboxConfig};

#[test]
fn test_sanitize_env_strips_sensitive_credentials() {
    let config = SandboxConfig::default();

    let raw_env = vec![
        ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ("HOME".to_string(), "/home/user".to_string()),
        ("AWS_SECRET_ACCESS_KEY".to_string(), "AKIAIOSFODNN7EXAMPLE".to_string()),
        ("GITHUB_TOKEN".to_string(), "ghp_1234567890abcdef".to_string()),
        ("SLACK_API_KEY".to_string(), "xoxb-12345".to_string()),
        ("DATABASE_PASSWORD".to_string(), "secret123".to_string()),
        ("ID_RSA".to_string(), "-----BEGIN RSA PRIVATE KEY-----".to_string()),
        ("CUSTOM_SAFE_VAR".to_string(), "safe_value".to_string()),
    ];

    let sanitized = sanitize_env(raw_env, &config);
    let keys: Vec<String> = sanitized.into_iter().map(|(k, _)| k).collect();

    assert!(keys.contains(&"PATH".to_string()), "PATH must be preserved");
    assert!(keys.contains(&"HOME".to_string()), "HOME must be preserved");
    assert!(keys.contains(&"CUSTOM_SAFE_VAR".to_string()), "General safe env vars must be preserved");

    assert!(!keys.contains(&"AWS_SECRET_ACCESS_KEY".to_string()), "AWS secret key must be stripped");
    assert!(!keys.contains(&"GITHUB_TOKEN".to_string()), "GitHub token must be stripped");
    assert!(!keys.contains(&"SLACK_API_KEY".to_string()), "Slack API key must be stripped");
    assert!(!keys.contains(&"DATABASE_PASSWORD".to_string()), "Database password must be stripped");
    assert!(!keys.contains(&"ID_RSA".to_string()), "ID_RSA key must be stripped");
}

#[test]
fn test_sanitize_env_honors_allowlist() {
    let mut config = SandboxConfig::default();
    config.env_allowlist.push("AWS_SECRET_ACCESS_KEY".to_string());

    let raw_env = vec![
        ("AWS_SECRET_ACCESS_KEY".to_string(), "explicitly_allowed".to_string()),
        ("GITHUB_TOKEN".to_string(), "ghp_secret".to_string()),
    ];

    let sanitized = sanitize_env(raw_env, &config);
    let keys: Vec<String> = sanitized.into_iter().map(|(k, _)| k).collect();

    assert!(keys.contains(&"AWS_SECRET_ACCESS_KEY".to_string()), "Explicitly allowlisted sensitive env var must be preserved");
    assert!(!keys.contains(&"GITHUB_TOKEN".to_string()), "Non-allowlisted sensitive token must be stripped");
}

#[test]
fn test_parse_command_str() {
    let (cmd, args) = parse_command_str("cargo build --release").unwrap();
    assert_eq!(cmd, "cargo");
    assert_eq!(args, vec!["build", "--release"]);

    let (cmd_quoted, args_quoted) = parse_command_str("sh -c \"echo hello\"").unwrap();
    assert_eq!(cmd_quoted, "sh");
    assert_eq!(args_quoted, vec!["-c", "echo hello"]);

    assert!(parse_command_str("   ").is_err(), "Empty command string must error");
    assert!(parse_command_str("echo \"unclosed quote").is_err(), "Unclosed quote must error");
}

#[test]
fn test_execute_sandboxed_simple_command() {
    let config = SandboxConfig::default();

    #[cfg(target_os = "windows")]
    let cmd = "cmd /c echo sandbox_test_ok";

    #[cfg(target_os = "linux")]
    let cmd = "echo sandbox_test_ok";

    #[cfg(any(target_os = "windows", target_os = "linux"))]
    {
        let res = sandbox::execute_sandboxed(cmd, &config);
        assert!(res.is_ok(), "Sandboxed command execution should succeed: {:?}", res);
        assert_eq!(res.unwrap(), 0, "Command should exit with status 0");
    }
}
