use schemars::{Schema, SchemaGenerator, json_schema};

/// A free-form object kept verbatim by the API server.
pub(crate) fn preserve_unknown_object(_: &mut SchemaGenerator) -> Schema {
    json_schema!({
        "type": "object",
        "x-kubernetes-preserve-unknown-fields": true,
    })
}
