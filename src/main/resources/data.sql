-- BCrypt encoded password for "1234"
-- Note: You may need to update these passwords with actual BCrypt hashes
INSERT INTO member (username, password, role)
VALUES ('user', '$2a$10$Ll3MeNroHve3jxB9UZglt.AdpZ/wIe1sY.s8fEHYzZa63Uzj9Vt0y', 'USER');
INSERT INTO member (username, password, role)
VALUES ('admin', '$2a$10$Ll3MeNroHve3jxB9UZglt.AdpZ/wIe1sY.s8fEHYzZa63Uzj9Vt0y', 'ADMIN');
