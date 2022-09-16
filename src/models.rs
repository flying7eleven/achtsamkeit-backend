use diesel::Queryable;

#[derive(Queryable, Clone)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password_hash: String,
}
