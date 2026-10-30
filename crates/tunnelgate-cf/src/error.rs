use crate::types::ApiMessage;

/// Cloudflare API error. Messages never include the API token or other credentials.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Cloudflare answered with an error status or `success: false`.
    #[error("cloudflare {method} {path}: HTTP {status}: {}", format_messages(.errors))]
    Api { method: &'static str, path: String, status: u16, errors: Vec<ApiMessage> },
    /// The request didn't complete (connection, TLS, timeout).
    #[error("cloudflare {method} {path}: {message}")]
    Transport { method: &'static str, path: String, message: String },
    /// The response body wasn't what we expected.
    #[error("cloudflare {method} {path}: unexpected response: {message}")]
    Decode { method: &'static str, path: String, message: String },
}

impl Error {
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Api { status, .. } => Some(*status),
            _ => None,
        }
    }

    pub fn is_not_found(&self) -> bool {
        self.status() == Some(404)
    }

    pub fn is_conflict(&self) -> bool {
        self.status() == Some(409)
    }

    /// The token is invalid or lacks a permission.
    pub fn is_unauthorized(&self) -> bool {
        matches!(self.status(), Some(401 | 403))
    }

    /// Worth retrying later without any change on our side.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Api { status, .. } => *status == 429 || *status >= 500,
            Self::Transport { .. } => true,
            Self::Decode { .. } => false,
        }
    }

    /// Whether Cloudflare reported one of the given error codes.
    pub fn has_code(&self, code: i64) -> bool {
        matches!(self, Self::Api { errors, .. } if errors.iter().any(|e| e.code == code))
    }
}

fn format_messages(errors: &[ApiMessage]) -> String {
    if errors.is_empty() {
        return "no error details".to_owned();
    }
    errors.iter().map(|e| format!("{} ({})", e.message, e.code)).collect::<Vec<_>>().join("; ")
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
