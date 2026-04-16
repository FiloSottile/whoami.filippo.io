package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh"
	"zombiezen.com/go/sqlite/sqlitex"
)

func main() {
	dbPath := flag.String("db", "whoami.sqlite3", "Path to the SQLite database")
	publicKey := flag.String("key", "", "Public key to lookup (required)")
	flag.Parse()

	if *publicKey == "" {
		log.Fatal("Public key is required. Use -key flag.")
	}

	// Parse the public key to strip comments and normalize format
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(*publicKey))
	if err != nil {
		log.Fatal("Failed to parse public key:", err)
	}

	// Open database
	db, err := sqlitex.Open(*dbPath, 0, 1)
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
	defer db.Close()

	// Get database connection
	conn := db.Get(context.TODO())
	if conn == nil {
		log.Fatal("Couldn't get db connection")
	}
	defer db.Put(conn)

	// Generate key hash same way as server.go
	key := bytes.TrimSpace(ssh.MarshalAuthorizedKey(pk))
	keyHash := sha256.Sum256(key)

	// Check if table exists
	checkStmt := conn.Prep("SELECT name FROM sqlite_master WHERE type='table' AND name='key_userid';")
	if hasTable, err := checkStmt.Step(); err != nil {
		log.Fatal("Failed to check if table exists:", err)
	} else if !hasTable {
		log.Fatal("Database does not contain the key_userid table. Make sure you're using a properly indexed database.")
	}
	checkStmt.Reset()

	// Query database
	stmt := conn.Prep("SELECT userID FROM key_userid WHERE keyHash = $kh;")
	stmt.SetBytes("$kh", keyHash[:16])
	if hasRow, err := stmt.Step(); err != nil {
		log.Fatal("Database query failed:", err)
	} else if !hasRow {
		fmt.Println("Key not found in database")
		os.Exit(1)
	}
	defer stmt.Reset()

	userID := stmt.GetInt64("userID")
	fmt.Printf("User ID: %d\n", userID)
}
