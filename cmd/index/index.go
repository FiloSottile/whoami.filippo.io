package main

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"os"

	"crawshaw.io/sqlite"
)

func main() {
	log.Println("Opening database...")
	conn, err := sqlite.OpenConn(os.Args[1], 0)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	createQuery := "CREATE TABLE IF NOT EXISTS key_userid (keyHash BLOB PRIMARY KEY, userID INTEGER) WITHOUT ROWID;" // keyHash is SHA-256(key)[:16]
	if _, err := conn.Prep(createQuery).Step(); err != nil {
		log.Fatal(err)
	}

	insStmt, err := conn.Prepare("INSERT INTO key_userid (keyHash, userID) VALUES ($1, $2);")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Inserting keys...")
	d := json.NewDecoder(os.Stdin)
	for {
		var line struct {
			ID  int64  `json:"id"`
			Key string `json:"key"`
		}
		if err := d.Decode(&line); err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}
		keyHash := sha256.Sum256([]byte(line.Key))

		if err := insStmt.Reset(); err != nil {
			log.Fatal(err)
		}
		insStmt.SetBytes("$1", keyHash[:16])
		insStmt.SetInt64("$2", line.ID)
		_, err = insStmt.Step()
		if err, ok := err.(sqlite.Error); ok && err.Code == sqlite.SQLITE_CONSTRAINT_PRIMARYKEY {
			// Key already in the database.
			continue
		}
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Println("Closing database...")
	if _, err := conn.Prep("VACUUM;").Step(); err != nil {
		log.Fatal(err)
	}
}
