-- sample-mall 백업 (2026-10-01) — 설치 시 임시로 만든 파일이 그대로 남아 있음
CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT);
INSERT INTO users VALUES(1,'admin','S3cretPass!','owner@sample-mall.kr','admin');
INSERT INTO users VALUES(2,'shopadmin','admin','ops@sample-mall.kr','admin');
INSERT INTO users VALUES(3,'guest','guest','guest@example.com','user');
