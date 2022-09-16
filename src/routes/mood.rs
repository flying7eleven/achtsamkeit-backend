use crate::fairings::BackendConfiguration;
use crate::routes::auth::AuthenticatedUser;
use crate::AchtsamkeitDatabaseConnection;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{post, State};
use serde::{Deserialize, Serialize};

/// A record which represents a mood and an optional comment on the mood by a user.
#[derive(Serialize, Deserialize)]
pub struct MoodInformation {
    /// The current mood which should be stored.
    mood: u8,
    /// An optional note provided by the user providing more information to the selected mood.
    note: Option<String>,
}

#[post("/mood", data = "<mood_information>")]
pub async fn store_mood(
    db_connection_pool: &State<AchtsamkeitDatabaseConnection>,
    mood_information: Json<MoodInformation>,
    config: &State<BackendConfiguration>,
    authenticated_user: AuthenticatedUser,
) -> Status {
    Status::NotImplemented
}
