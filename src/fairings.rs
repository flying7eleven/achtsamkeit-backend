use diesel::r2d2::{ConnectionManager, Pool};
use diesel::PgConnection;

/// TODO
pub struct AchtsamkeitDatabaseConnection(Pool<ConnectionManager<PgConnection>>);

/// TODO
impl From<Pool<ConnectionManager<PgConnection>>> for AchtsamkeitDatabaseConnection {
    /// TODO
    fn from(pool: Pool<ConnectionManager<PgConnection>>) -> Self {
        AchtsamkeitDatabaseConnection(pool)
    }
}

#[derive(Clone)]
pub struct BackendConfiguration {
    /// The pre-shared-key which is used to sign and validate the generated token.
    pub token_signature_psk: String,
    /// The token-lifetime in seconds.
    pub token_lifetime_in_seconds: usize,
}
