use crate::models::NewMood;
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
    mood: i32,
    /// An optional note provided by the user providing more information to the selected mood.
    note: Option<String>,
}

#[post("/mood", data = "<mood_information>")]
pub async fn store_mood(
    db_connection_pool: &State<AchtsamkeitDatabaseConnection>,
    mood_information: Json<MoodInformation>,
    authenticated_user: AuthenticatedUser,
) -> Status {
    use crate::models::User;
    use crate::schema::moods::dsl::moods;
    use crate::schema::users::dsl::{username, users};
    use diesel::{insert_into, ExpressionMethods, QueryDsl, RunQueryDsl};
    use log::error;

    // get a connection to the database for dealing with the request
    let db_connection = &mut match db_connection_pool.get() {
        Ok(connection) => connection,
        Err(error) => {
            error!("Could not get a connection from the database connection pool. The error was: {}", error);
            return Status::InternalServerError;
        }
    };

    // try to get the user record for the supplied username
    let calling_user = match db_connection
        .build_transaction()
        .read_only()
        .run::<User, diesel::result::Error, _>(
            move |connection| match users.filter(username.eq(authenticated_user.email_address)).load::<User>(connection) {
                Ok(found_users) => {
                    // if we did not get exactly one user, return an 'error'
                    if found_users.len() != 1 {
                        return Err(diesel::result::Error::NotFound);
                    }

                    // return the found user
                    Ok(found_users[0].clone())
                }
                Err(error) => Err(error),
            },
        ) {
        Ok(user) => user,
        Err(error) => {
            error!("{}", error);
            return Status::InternalServerError;
        }
    };

    // prepare the new mood record
    let mood_to_store = NewMood::default().user(calling_user).mood(mood_information.mood).note(&mood_information.note);

    // try to store the new mood record in the database
    match insert_into(moods).values(&mood_to_store).execute(db_connection) {
        Ok(_) => Status::NoContent,
        Err(error) => {
            error!("Could not add new mood record to the database. The error was: {}", error);
            Status::InternalServerError
        }
    }
}
