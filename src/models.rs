use crate::schema::moods;
use diesel::{Insertable, Queryable};

#[derive(Queryable, Clone)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password_hash: String,
}

#[derive(Insertable)]
#[diesel(table_name = moods)]
pub struct NewMood {
    user: i32,
    mood: i32,
    note: Option<String>,
}

impl Default for NewMood {
    fn default() -> Self {
        Self {
            user: -1,
            mood: -1,
            note: None,
        }
    }
}

impl NewMood {
    pub fn user(&mut self, user: User) -> NewMood {
        Self {
            user: user.id,
            mood: self.mood,
            note: self.note.clone(),
        }
    }

    pub fn mood(&mut self, mood: i32) -> NewMood {
        Self {
            user: self.user,
            mood,
            note: self.note.clone(),
        }
    }

    pub fn note(&mut self, note: &Option<String>) -> NewMood {
        Self {
            user: self.user,
            mood: self.mood,
            note: note.clone(),
        }
    }
}
