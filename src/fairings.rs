#[derive(Clone)]
pub struct BackendConfiguration {
    /// The pre-shared-key which is used to sign and validate the generated token.
    pub token_signature_psk: String,
    /// The token-lifetime in seconds.
    pub token_lifetime_in_seconds: usize,
}
