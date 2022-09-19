// @generated automatically by Diesel CLI.

diesel::table! {
    moods (id) {
        id -> Int4,
        user -> Int4,
        time -> Timestamp,
        mood -> Int4,
        note -> Nullable<Text>,
    }
}

diesel::table! {
    users (id) {
        id -> Int4,
        username -> Varchar,
        password_hash -> Varchar,
    }
}

diesel::joinable!(moods -> users (user));

diesel::allow_tables_to_appear_in_same_query!(moods, users,);
