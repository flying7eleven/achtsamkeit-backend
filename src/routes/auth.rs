use crate::fairings::BackendConfiguration;
use crate::AchtsamkeitDatabaseConnection;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome};
use rocket::serde::json::Json;
use rocket::{error, post, Request, State};
use serde::{Deserialize, Serialize};

/// The representation of an authenticated user. As soon as this is included in the parameters
/// of a route, the call can be just made with an valid token in the header.
pub struct AuthenticatedUser {
    pub email_address: String,
}

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
    /// The type of the token (access or refresh).
    token_type: String,
}

/// The response object which is used when the user requested a token.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenResponse {
    /// The access token to use for API requests.
    access_token: String,
    /// The refresh token to use for requesting a new access token.
    refresh_token: String,
}

/// The error types which can occur during request authentication.
#[derive(Debug)]
pub enum AuthorizationError {
    /// No authorization header was found although it is required.
    MissingAuthorizationHeader,
    /// The authorization header seems to be malformed and cannot be interpreted.
    MalformedAuthorizationHeader,
    /// The supplied authentication token is not valid.
    InvalidToken,
    /// The backend has no secret key which can validate the access token.
    NoDecodingKey,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = AuthorizationError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<AuthenticatedUser, AuthorizationError> {
        use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
        use log::error;

        //
        let maybe_authorization_header = request.headers().get_one("Authorization");
        match maybe_authorization_header {
            Some(maybe_authorization) => {
                // split the token type from the actual token... there have to be two parts
                let authorization_information = maybe_authorization.split(' ').collect::<Vec<&str>>();
                if authorization_information.len() != 2 {
                    error!(
                        "It seems that the authorization header is malformed. There were 2 parts expected but we got {}",
                        authorization_information.len()
                    );
                    return Outcome::Failure((Status::Forbidden, AuthorizationError::MalformedAuthorizationHeader));
                }

                // ensure that the token type is marked as 'bearer' token
                if authorization_information[0].to_lowercase() != "bearer" {
                    error!(
                        "It seems that the authorization header is malformed. We expected as token type 'bearer' but got '{}'",
                        authorization_information[0].to_lowercase()
                    );
                    return Outcome::Failure((Status::Forbidden, AuthorizationError::MalformedAuthorizationHeader));
                }

                // specify the parameter for the validation of the token
                let mut validation_parameter = Validation::new(Algorithm::HS512);
                validation_parameter.leeway = 5; // allow a time difference of max. 5 seconds
                validation_parameter.validate_exp = true;
                validation_parameter.validate_nbf = true;

                // get the current backend configuration (for the public key)
                let backend_configuration = match request.guard::<&'r State<BackendConfiguration>>().await {
                    Outcome::Success(state) => state,
                    Outcome::Failure(_) => {
                        error!("Could not get the current configuration for extracting the toking signing key");
                        return Outcome::Failure((Status::Forbidden, AuthorizationError::NoDecodingKey));
                    }
                    Outcome::Forward(forward) => return Outcome::Forward(forward),
                };

                // get the 'validation' key for the token
                let decoding_key = DecodingKey::from_secret(backend_configuration.token_signature_psk.as_bytes());

                // verify the validity of the token supplied in the header
                let decoded_token = match decode::<Claims>(authorization_information[1], &decoding_key, &validation_parameter) {
                    Ok(token) => token,
                    Err(error) => {
                        error!("The supplied token seems to be invalid. The error was: {}", error);
                        return Outcome::Failure((Status::Forbidden, AuthorizationError::InvalidToken));
                    }
                };

                // ensure that we'll just accept access tokens and nothing else
                if decoded_token.claims.token_type != "access" {
                    error!("The caller tried to use an other token than an access token");
                    return Outcome::Failure((Status::Forbidden, AuthorizationError::InvalidToken));
                }

                // if we reach this step, the validation was successful, and we can allow the user to
                // call the route
                return Outcome::Success(AuthenticatedUser {
                    email_address: decoded_token.claims.sub,
                });
            }
            _ => {
                error!("No authorization header could be found for an authenticated route!");
                Outcome::Failure((Status::Forbidden, AuthorizationError::MissingAuthorizationHeader))
            }
        }
    }
}

fn get_refresh_token_for_user(subject: &str, signature_psk: &str, lifetime: usize) -> Option<String> {
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
        sub: subject.to_string(),
        token_type: "refresh".to_string(),
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

fn get_access_token_for_user(subject: &str, signature_psk: &str, lifetime: usize) -> Option<String> {
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
        sub: subject.to_string(),
        token_type: "access".to_string(),
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
    let mut db_transaction_builder = match db_connection_pool.get() {
        Ok(connection) => connection,
        Err(error) => {
            error!("Could not get a connection from the database connection pool. The error was: {}", error);
            return Err(Status::InternalServerError);
        }
    };

    // try to get the user record for the supplied username
    let supplied_username = login_information.username.clone();
    let maybe_user_result = db_transaction_builder.build_transaction().read_only().run::<User, Error, _>(move |connection| {
        match users.filter(username.eq(supplied_username)).load::<User>(connection) {
            Ok(found_users) => {
                if found_users.len() != 1 {
                    return Err(Error::NotFound);
                }
                Ok(found_users[0].clone())
            }
            Err(error) => Err(error),
        }
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
    if let Some(access_token) = get_access_token_for_user(
        &login_information.username,
        &config.token_signature_psk,
        config.access_token_lifetime_in_seconds,
    ) {
        if let Some(refresh_token) = get_refresh_token_for_user(
            &login_information.username,
            &config.token_signature_psk,
            config.refresh_token_lifetime_in_seconds,
        ) {
            return Ok(Json(TokenResponse { access_token, refresh_token }));
        }
    }

    // it seems that we failed to generate a valid token, this should never happen, something
    // seems to be REALLY wrong
    Err(Status::InternalServerError)
}
