CREATE TABLE moods
(
    id     SERIAL PRIMARY KEY,
    "user" INTEGER   NOT NULL,
    time   TIMESTAMP NOT NULL DEFAULT now(),
    mood   INTEGER   NOT NULL,
    note   TEXT      NULL,
    CONSTRAINT fk_moods_users FOREIGN KEY ("user") REFERENCES users (id)
);