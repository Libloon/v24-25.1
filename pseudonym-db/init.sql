-- start: Kryptert init-data med konsistente demo-passord for pseudonym-databasen i steg 9 - oppfyller F1 (identitet og flyt), F3 (persistens) og NF7 (kryptering av data at rest) (person 4 og person 5)
CREATE TABLE Pseudonym (
  epost       VARCHAR(200) PRIMARY KEY,
  pseudonym   VARCHAR(200),
  salt        VARCHAR(11),
  passordhash VARCHAR(44)
);

INSERT INTO Pseudonym (epost, pseudonym, salt, passordhash) VALUES
  ('Ante@example.com', 'osiedahs', '1712167670', 'Aw16YyLRWTS0BOoOb7DpvBMeYb444g.kl1a542GYpJA'),
  ('Bjart@example.com', 'uozaixav', '1712167671', '5lQnfx89dpJpeaVR3CqCqy3pQPhdN8Nf0Nt9H9psgQ4'),
  ('Cecilie@example.com', 'olaebaev', '1712167672', '9tkRE7Q8yBj.ydZTxSCR3ZW8vzHtNOoSpWSK/ZepxUA'),
  ('mikke@gmail.com', 'admin', '12345678901', '3pxeb/.Vk9IUi/DI91E1PlBuFwIPNgoLbtVnG2sZIX7'),
  ('test_admin@usn.com', 'admin', '12345678902', 'AV9OFOhfc0S6JerALmNMDAP7fntEwFZul7HkJ5BWlp2');
-- slutt: Kryptert init-data med konsistente demo-passord for pseudonym-databasen i steg 9 - oppfyller F1 (identitet og flyt), F3 (persistens) og NF7 (kryptering av data at rest) (person 4 og person 5)
