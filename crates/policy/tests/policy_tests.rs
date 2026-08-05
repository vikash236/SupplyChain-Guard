use policy::GuardPolicy;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_default_policy() {
    let policy = GuardPolicy::default();
    assert!(!policy.sandbox.allow_network);
    assert_eq!(policy.sandbox.memory_limit_mb, None);
    assert!(policy.rules.block_obfuscated_code);
    assert!(policy.rules.block_network_calls);
    assert!(!policy.rules.block_subprocesses);
}

#[test]
fn test_parse_valid_guard_toml() {
    let toml_content = r#"
[scanner]
ignored_rules = ["Command Execution"]
ignored_paths = ["tests/fixtures/benign_build.rs"]

[scanner.severity_overrides]
"Sensitive File Read" = "WARN"

[sandbox]
allow_network = false
env_allowlist = ["CUSTOM_ENV_VAR"]
env_denylist = ["LEAK_VAR"]
memory_limit_mb = 1024

[rules]
block_obfuscated_code = true
block_subprocesses = true
block_network_calls = true
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(toml_content.as_bytes()).unwrap();

    let policy = GuardPolicy::load_from_file(temp_file.path()).unwrap();

    assert!(policy.is_rule_ignored("Command Execution"));
    assert!(!policy.is_rule_ignored("Network Access"));

    assert_eq!(policy.sandbox.memory_limit_mb, Some(1024));
    assert!(policy.sandbox.env_allowlist.contains(&"CUSTOM_ENV_VAR".to_string()));
    assert!(policy.sandbox.env_denylist.contains(&"LEAK_VAR".to_string()));

    assert_eq!(
        policy.get_severity_override("Sensitive File Read"),
        Some("WARN")
    );
    assert!(policy.rules.block_subprocesses);
}
