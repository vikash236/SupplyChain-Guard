//! SARIF v2.1.0 (Static Analysis Results Interchange Format) Exporter for SupplyChain-Guard.

use crate::findings::{ScanReport, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;


#[derive(Debug, Serialize, Deserialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMultiformatMessage,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifReportingConfiguration,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifReportingConfiguration {
    pub level: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifMultiformatMessage {
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: usize,
}

/// Convert a `ScanReport` to SARIF v2.1.0 JSON representation.
pub fn report_to_sarif(report: &ScanReport) -> String {
    let mut rules_map = HashSet::new();
    let mut rules = Vec::new();

    for finding in &report.findings {
        let rule_id = format!("{:?}", finding.kind);
        if rules_map.insert(rule_id.clone()) {
            rules.push(SarifRule {
                id: rule_id,
                name: finding.kind.to_string(),
                short_description: SarifMultiformatMessage {
                    text: finding.kind.to_string(),
                },
                default_configuration: SarifReportingConfiguration {
                    level: severity_to_sarif_level(finding.severity).to_string(),
                },
            });
        }
    }

    let results = report
        .findings
        .iter()
        .map(|finding| {
            let rule_id = format!("{:?}", finding.kind);
            let uri = finding.file.to_string_lossy().replace('\\', "/");

            let region = finding.line.map(|line| SarifRegion { start_line: line });

            SarifResult {
                rule_id,
                level: severity_to_sarif_level(finding.severity).to_string(),
                message: SarifMessage {
                    text: finding.message.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation { uri },
                        region,
                    },
                }],
            }
        })
        .collect();

    let log = SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "SupplyChain-Guard".to_string(),
                    version: "0.1.0".to_string(),
                    information_uri: "https://github.com/vikash236/SupplyChain-Guard".to_string(),
                    rules,
                },
            },
            results,
        }],
    };

    serde_json::to_string_pretty(&log).unwrap_or_else(|_| "{}".to_string())
}

fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "error",
        Severity::Warn => "warning",
        Severity::Info => "note",
    }
}
