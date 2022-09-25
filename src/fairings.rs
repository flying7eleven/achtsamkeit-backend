use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use diesel::PgConnection;

/// TODO
pub struct AchtsamkeitDatabaseConnection(Pool<ConnectionManager<PgConnection>>);

/// TODO
impl AchtsamkeitDatabaseConnection {
    /// TODO
    #[inline(always)]
    pub fn get(&self) -> Result<PooledConnection<ConnectionManager<PgConnection>>, r2d2::Error> {
        self.0.get()
    }
}

/// TODO
impl From<Pool<ConnectionManager<PgConnection>>> for AchtsamkeitDatabaseConnection {
    /// TODO
    #[inline(always)]
    fn from(pool: Pool<ConnectionManager<PgConnection>>) -> Self {
        AchtsamkeitDatabaseConnection(pool)
    }
}

#[derive(Clone)]
pub struct BackendConfiguration {
    /// The pre-shared-key which is used to sign and validate the generated token.
    pub token_signature_psk: String,
    /// The access token-lifetime in seconds.
    pub access_token_lifetime_in_seconds: usize,
    /// The refresh token-lifetime in seconds.
    pub refresh_token_lifetime_in_seconds: usize,
}
