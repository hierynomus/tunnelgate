#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("kubernetes: {0}")]
    Kube(#[from] kube::Error),
    #[error(transparent)]
    Cloudflare(#[from] tunnelgate_cf::Error),
    #[error("{0}")]
    Invalid(String),
    #[error("finalizer: {0}")]
    Finalizer(#[source] Box<kube::runtime::finalizer::Error<Error>>),
    /// Expected, retryable state (e.g. waiting for connections to drain).
    #[error("{0}")]
    Pending(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Unwraps the finalizer helper's error. A cleanup that ran on a stale cached object after the
/// finalizer was already removed fails with 404 on the removal; that is success.
pub fn finalizer_result(e: kube::runtime::finalizer::Error<Error>) -> Result<kube::runtime::controller::Action> {
    use kube::runtime::finalizer::Error as F;
    match e {
        F::ApplyFailed(e) | F::CleanupFailed(e) => Err(e),
        F::RemoveFinalizer(kube::Error::Api(s)) if s.code == 404 => {
            Ok(kube::runtime::controller::Action::await_change())
        }
        e => Err(Error::Finalizer(Box::new(e))),
    }
}
