SET SESSION FOREIGN_KEY_CHECKS=0;

/* Drop Tables */

DROP TABLE IF EXISTS board;
DROP TABLE IF EXISTS reply;
DROP TABLE IF EXISTS user;




/* Create Tables */

CREATE TABLE board
(
	boardid int NOT NULL AUTO_INCREMENT,
	title varchar(100) NOT NULL,
	content blob,
	count int DEFAULT 0,
	createDate timestamp DEFAULT now(),
	reupdateDate timestamp DEFAULT now(),
	userid int NOT NULL,
	repid int NOT NULL,
	PRIMARY KEY (boardid),
	UNIQUE (boardid),
	UNIQUE (userid),
	UNIQUE (repid)
);


CREATE TABLE reply
(
	repid int NOT NULL AUTO_INCREMENT,
	RepContent blob,
	reCreateDate timestamp DEFAULT now(),
	reupdateDate timestamp DEFAULT now(),
	userid int NOT NULL,
	PRIMARY KEY (repid),
	UNIQUE (repid),
	UNIQUE (userid)
);


CREATE TABLE user
(
	userid int NOT NULL AUTO_INCREMENT,
	username varchar(30) NOT NULL,
	password varchar(100) NOT NULL,
	email varchar(50) NOT NULL,
	createDate timestamp DEFAULT now() NOT NULL,
	updateDate timestamp DEFAULT now() NOT NULL,
	role varchar(10) DEFAULT 'user' NOT NULL,
	PRIMARY KEY (userid),
	UNIQUE (userid),
	UNIQUE (username)
);



/* Create Foreign Keys */

ALTER TABLE board
	ADD FOREIGN KEY (repid)
	REFERENCES reply (repid)
	ON UPDATE RESTRICT
	ON DELETE RESTRICT
;


ALTER TABLE board
	ADD FOREIGN KEY (userid)
	REFERENCES user (userid)
	ON UPDATE RESTRICT
	ON DELETE RESTRICT
;


ALTER TABLE reply
	ADD FOREIGN KEY (userid)
	REFERENCES user (userid)
	ON UPDATE RESTRICT
	ON DELETE RESTRICT
;



