use policy::GuardPolicy;
use scanner::{compute_file_sha256, ScanReport};
use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SbomFormat {
    CycloneDx,
    Spdx,
}

#[derive(Debug, Serialize, Deserialize)]
struct CycloneDxBom {
    #[serde(rename = "bomFormat")]
    bom_format: String,
    #[serde(rename = "specVersion")]
    spec_version: String,
    serial_number: String,
    version: u32,
    components: Vec<CycloneDxComponent>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CycloneDxComponent {
    name: String,
    version: String,
    #[serde(rename = "type")]
    component_type: String,
    hashes: Vec<HashObject>,
    properties: Vec<PropertyObject>,
}

#[derive(Debug, Serialize, Deserialize)]
struct HashObject {
    alg: String,
    content: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PropertyObject {
    name: String,
    value: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SpdxDocument {
    #[serde(rename = "spdxVersion")]
    spdx_version: String,
    #[serde(rename = "dataLicense")]
    data_license: String,
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    files: Vec<SpdxFile>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SpdxFile {
    #[serde(rename = "fileName")]
    file_name: String,
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    checksums: Vec<HashObject>,
    comment: String,
}

pub fn generate_sbom(report: &ScanReport, policy: &GuardPolicy, format: SbomFormat) -> Result<String, String> {
    match format {
        SbomFormat::CycloneDx => generate_cyclonedx(report, policy),
        SbomFormat::Spdx => generate_spdx(report, policy),
    }
}

fn generate_cyclonedx(report: &ScanReport, policy: &GuardPolicy) -> Result<String, String> {
    let mut components = Vec::new();

    for finding in &report.findings {
        let sha256_hash = compute_file_sha256(&finding.file).unwrap_or_else(|_| "unknown".to_string());
        components.push(CycloneDxComponent {
            name: finding.file.display().to_string(),
            version: "0.1.0".to_string(),
            component_type: "file".to_string(),
            hashes: vec![HashObject {
                alg: "SHA-256".to_string(),
                content: sha256_hash,
            }],
            properties: vec![
                PropertyObject {
                    name: "supplychain-guard:severity".to_string(),
                    value: finding.severity.to_string(),
                },
                PropertyObject {
                    name: "supplychain-guard:kind".to_string(),
                    value: finding.kind.to_string(),
                },
                PropertyObject {
                    name: "supplychain-guard:network_allowed".to_string(),
                    value: policy.sandbox.allow_network.to_string(),
                },
            ],
        });
    }

    let bom = CycloneDxBom {
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.4".to_string(),
        serial_number: "urn:uuid:supplychain-guard-attestation".to_string(),
        version: 1,
        components,
    };

    serde_json::to_string_pretty(&bom).map_err(|e| format!("Serialization error: {}", e))
}

fn generate_spdx(report: &ScanReport, policy: &GuardPolicy) -> Result<String, String> {
    let mut files = Vec::new();

    for (idx, finding) in report.findings.iter().enumerate() {
        let sha256_hash = compute_file_sha256(&finding.file).unwrap_or_else(|_| "unknown".to_string());
        files.push(SpdxFile {
            file_name: finding.file.display().to_string(),
            spdx_id: format!("SPDXRef-File-{}", idx + 1),
            checksums: vec![HashObject {
                alg: "SHA256".to_string(),
                content: sha256_hash,
            }],
            comment: format!(
                "Security Status: [{}] {} (Sandbox Network Allowed: {})",
                finding.severity.to_string(),
                finding.message,
                policy.sandbox.allow_network
            ),
        });
    }

    let doc = SpdxDocument {
        spdx_version: "SPDX-2.3".to_string(),
        data_license: "CC0-1.0".to_string(),
        spdx_id: "SPDXRef-DOCUMENT".to_string(),
        name: "SupplyChain-Guard Security Attestation".to_string(),
        files,
    };

    serde_json::to_string_pretty(&doc).map_err(|e| format!("Serialization error: {}", e))
}
