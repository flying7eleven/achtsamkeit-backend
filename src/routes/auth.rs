use crate::fairings::BackendConfiguration;
use crate::AchtsamkeitDatabaseConnection;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{post, State};
use serde::{Deserialize, Serialize};

/// The struct containing the information for requesting an authentication token.
#[derive(Serialize, Deserialize)]
pub struct LoginInformation {
    /// The username of the user.
    username: String,
    /// The password for the login request.
    password: String,
}

/// The struct which describes the token claims for the JWT to generate.
#[derive(Serialize, Deserialize)]
struct Claims {
    /// The unix timestamp when the token expires.
    exp: usize,
    /// The unix timestamp when the token was issued.
    iat: usize,
    /// The unix timestamp at which the token begins to be valid.
    nbf: usize,
    /// The subject for whom the token was issued.
    sub: String,
}

/// The response object which is used when the user requested a token.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenResponse {
    /// The access token to use for API requests.
    access_token: String,
}

fn get_token_for_user(subject: &String, signature_psk: &String, lifetime: usize) -> Option<String> {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use log::error;
    use std::time::{SystemTime, UNIX_EPOCH};

    // get the issuing time for the token
    let token_issued_at = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as usize,
        Err(error) => {
            error!("Could not get the issuing time for the token. The error was: {}", error);
            return None;
        }
    };

    // calculate the time when the token expires
    let token_expires_at = token_issued_at + 1 + lifetime;

    // define the content of the actual token
    let token_claims = Claims {
        exp: token_expires_at,
        iat: token_issued_at,
        nbf: token_issued_at + 1,
        sub: subject.clone(),
    };

    // get the signing key for the token
    let encoding_key = EncodingKey::from_secret(signature_psk.as_ref());

    // generate a new JWT for the supplied header and token claims. if we were successful, return
    // the token
    let header = Header::new(Algorithm::HS512);
    if let Ok(token) = encode(&header, &token_claims, &encoding_key) {
        return Some(token);
    }

    // if we fail, return None
    None
}

#[post("/auth/login", data = "<login_information>")]
pub async fn get_login_token(
    db_connection_pool: &State<AchtsamkeitDatabaseConnection>,
    login_information: Json<LoginInformation>,
    config: &State<BackendConfiguration>,
) -> Result<Json<TokenResponse>, Status> {
    use crate::models::User;
    use crate::schema::users::dsl::{username, users};
    use bcrypt::verify;
    use diesel::result::Error;
    use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
    use log::error;

    // get a database connection from the connection pool
    let mut db_transaction_builder = db_connection_pool.get().unwrap();

    // try to get the user record for the supplied username
    let supplied_username = login_information.username.clone();
    let maybe_user_result = db_transaction_builder
        .build_transaction()
        .read_only()
        .run::<User, diesel::result::Error, _>(move |connection| match users.filter(username.eq(supplied_username)).load::<User>(connection) {
            Ok(found_users) => {
                if found_users.len() != 1 {
                    return Err(Error::NotFound);
                }
                Ok(found_users[0].clone())
            }
            Err(error) => Err(error),
        });

    // try to get the actual user object or delay a bit and then return with the corresponding error
    let user = match maybe_user_result {
        Ok(user) => user,
        Err(_) => {
            // ensure that we know what happened
            error!("Could not get the user record for '{}'", login_information.username);

            // just slow down the process to prevent easy checking if a user name exists or not by verifying a random
            // bcrypt password
            let _ = verify("some_password", "$2y$12$7xMzqvnHyizkumZYpIRXheGMAqDKVo8HKtpmQSn51JUfY0N2VN4ua");

            // finally we can tell teh user that he/she is not authorized
            return Err(Status::Unauthorized);
        }
    };

    // check if the supplied password matches the one we stored in the database using the same bcrypt
    // parameters
    match verify(&login_information.password, user.password_hash.as_str()) {
        Ok(is_password_correct) => {
            if !is_password_correct {
                return Err(Status::Unauthorized);
            }
        }
        Err(error) => {
            error!(
                "Could not verify the supplied password with the one stored in the database. The error was: {}",
                error
            );
            return Err(Status::InternalServerError);
        }
    }

    // if we get here, the we ensured that the user is known and that the supplied password
    // was valid, we can generate a new access token and return it to the calling party
    if let Some(token) = get_token_for_user(&login_information.username, &config.token_signature_psk, config.token_lifetime_in_seconds) {
        return Ok(Json(TokenResponse { access_token: token }));
    }

    // it seems that we failed to generate a valid token, this should never happen, something
    // seems to be REALLY wrong
    Err(Status::InternalServerError)
}
