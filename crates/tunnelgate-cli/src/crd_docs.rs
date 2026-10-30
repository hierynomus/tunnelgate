//! Markdown reference for the CRDs, generated from their OpenAPI schemas (`docs/crds.md`).

use std::fmt::Write;

use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use serde_json::Value;

pub fn render(crds: &[CustomResourceDefinition]) -> String {
    let mut out = String::from(
        "# CRD reference\n\n\
         Generated from the Rust types by `tunnelgate crdgen --markdown` (`mise run crds`); do not edit.\n\
         Conditions, reasons and their meaning are in [conditions.md](conditions.md).\n",
    );
    out.push('\n');
    for crd in crds {
        let kind = &crd.spec.names.kind;
        let _ = writeln!(out, "- [{kind}](#{})", kind.to_lowercase());
    }
    for crd in crds {
        let names = &crd.spec.names;
        for v in crd.spec.versions.iter().filter(|v| v.served) {
            let _ = writeln!(out, "\n## {}\n", names.kind);
            let short = names.short_names.as_deref().unwrap_or_default();
            let _ = write!(out, "`{}/{}`, {}", crd.spec.group, v.name, crd.spec.scope.to_lowercase());
            if !short.is_empty() {
                let _ = write!(
                    out,
                    ", short names: {}",
                    short.iter().map(|s| format!("`{s}`")).collect::<Vec<_>>().join(", ")
                );
            }
            out.push_str(".\n");
            let Some(schema) = v.schema.as_ref().and_then(|s| s.open_api_v3_schema.as_ref()) else { continue };
            let schema = serde_json::to_value(schema).unwrap_or_default();
            for part in ["spec", "status"] {
                let Some(props) = schema.pointer(&format!("/properties/{part}")) else { continue };
                let _ = writeln!(out, "\n### {part}\n");
                if let Some(d) = props.get("description").and_then(Value::as_str) {
                    let _ = writeln!(out, "{}\n", d.trim());
                }
                out.push_str("| Field | Type | Description |\n|---|---|---|\n");
                fields(&mut out, "", props);
            }
        }
    }
    out
}

fn fields(out: &mut String, prefix: &str, schema: &Value) {
    let Some(props) = schema.get("properties").and_then(Value::as_object) else { return };
    let required: Vec<&str> =
        schema.get("required").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).collect();
    for (name, prop) in props {
        let path = format!("{prefix}{name}");
        let mut desc = prop.get("description").and_then(Value::as_str).unwrap_or_default().trim().to_owned();
        if let Some(values) = prop.get("enum").and_then(Value::as_array) {
            let values: Vec<String> = values.iter().map(|v| format!("`{}`", plain(v))).collect();
            append(&mut desc, &format!("One of {}.", values.join(", ")));
        }
        if let Some(default) = prop.get("default").filter(|d| !is_empty(d)) {
            append(&mut desc, &format!("Default `{}`.", plain(default)));
        }
        let mut ty = type_of(prop);
        if required.contains(&name.as_str()) {
            ty.push_str(", required");
        }
        let _ = writeln!(out, "| `{path}` | {ty} | {} |", cell(&desc));
        if name == "conditions" {
            continue; // standard metav1.Condition
        }
        match prop.get("type").and_then(Value::as_str) {
            Some("object") => fields(out, &format!("{path}."), prop),
            Some("array") => {
                if let Some(items) = prop.get("items") {
                    fields(out, &format!("{path}[]."), items);
                }
            }
            _ => {}
        }
    }
}

fn type_of(prop: &Value) -> String {
    match prop.get("type").and_then(Value::as_str) {
        Some("array") => {
            let item = prop.get("items").map(type_of).unwrap_or_else(|| "any".into());
            format!("[]{item}")
        }
        Some("object") if prop.get("properties").is_none() && prop.get("additionalProperties").is_some() => {
            let value = prop.get("additionalProperties").map(type_of).unwrap_or_else(|| "any".into());
            format!("map[string]{value}")
        }
        Some(t) => t.to_owned(),
        None if prop.get("x-kubernetes-int-or-string").is_some() => "int-or-string".into(),
        None => "any".into(),
    }
}

fn plain(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn is_empty(v: &Value) -> bool {
    match v {
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        Value::Null => true,
        _ => false,
    }
}

fn append(desc: &mut String, more: &str) {
    if !desc.is_empty() {
        desc.push_str(if desc.ends_with('.') { " " } else { ". " });
    }
    desc.push_str(more);
}

/// One table cell: no line breaks, escaped pipes.
fn cell(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documents_nested_fields_enums_and_defaults() {
        let doc = render(&tunnelgate_api::crds());
        assert!(doc.contains("## TunnelRoute\n"), "{doc}");
        assert!(doc.contains("| `hostname` | string, required |"), "{doc}");
        assert!(doc.contains("| `access.applicationRefs[].name` | string, required |"), "{doc}");
        assert!(doc.contains("| `dns.adopt` | boolean | Take over an existing record"), "{doc}");
        assert!(doc.contains("| `origin.protocol` |"), "{doc}");
        assert!(!doc.contains("conditions[]."), "conditions aren't expanded");
    }
}
