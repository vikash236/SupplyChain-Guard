use scanner::{scan_rust_file, FindingKind};
use std::path::Path;

#[test]
fn test_detect_ffi_execution() {
    let code = r#"
        fn main() {
            unsafe {
                let handle = libc::dlopen(std::ffi::CString::new("libevil.so").unwrap().as_ptr(), 1);
                let sym = libc::dlsym(handle, std::ffi::CString::new("payload").unwrap().as_ptr());
            }
        }
    "#;

    let report = scan_rust_file(Path::new("build.rs"), code);
    assert!(report.has_critical());
    assert!(
        report.findings.iter().any(|f| f.kind == FindingKind::FfiExecution),
        "Should detect dlsym / dlopen FFI execution"
    );
}

#[test]
fn test_detect_raw_socket_import() {
    let code = r#"
        use socket2::{Socket, Domain, Type};
        use reqwest::blocking::get;

        fn main() {
            let res = get("https://evil.example").unwrap();
        }
    "#;

    let report = scan_rust_file(Path::new("build.rs"), code);
    assert!(report.has_critical());
    assert!(
        report.findings.iter().any(|f| f.kind == FindingKind::RawSocketUsage),
        "Should detect socket2 or reqwest crate import"
    );
}

#[test]
fn test_detect_obfuscated_byte_sequence() {
    let code = r#"
        fn main() {
            let payload: [u8; 8] = [0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x00, 0x0a];
        }
    "#;

    let report = scan_rust_file(Path::new("build.rs"), code);
    assert!(report.has_critical());
    assert!(
        report.findings.iter().any(|f| f.kind == FindingKind::ObfuscatedByteSequence),
        "Should detect 6+ byte array literal payload"
    );
}
