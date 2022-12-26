//go:build ignore

package main

import (
	"context"
	"database/sql"
	"expvar"
	"io/ioutil"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"crawshaw.io/sqlite"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/go-github/v42/github"
	"golang.org/x/oauth2"
)

func main() {
	var (
		fetchedUsers = expvar.NewInt("users")
		fetchedKeys  = expvar.NewInt("keys")
		fetchErrors  = expvar.NewInt("fetcherr")
		fetch404     = expvar.NewInt("fetch404")
		listErrors   = expvar.NewInt("listerr")
		insertErrors = expvar.NewInt("inserterr")
		rateLimited  = expvar.NewInt("ratelimited")
		currentUser  = expvar.NewString("currentUser")
		skippedOrgs  = expvar.NewInt("orgs")
	)

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	tc := oauth2.NewClient(context.Background(), ts)
	githubClient := github.NewClient(tc)

	db, err := sql.Open("mysql", os.Getenv("MYSQL_DSN"))
	fatalIfErr(err)
	_, err = db.Exec("SET NAMES UTF8")
	fatalIfErr(err)
	insert, err := db.Prepare("INSERT INTO `keys` (`userid`, `username`, `key`, `first_seen`) SELECT ?, ?, ?, NOW() WHERE NOT EXISTS (SELECT * FROM `keys` WHERE `key` = ? AND `userid` = ?);")
	fatalIfErr(err)

	http.HandleFunc("/dump", func(rw http.ResponseWriter, r *http.Request) {
		defer os.Remove("/tmp/dump.sqlite")
		conn, err := sqlite.OpenConn("/tmp/dump.sqlite", 0)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		defer conn.Close()
		stmt, err := conn.Prepare("CREATE TABLE key_userid (keyHash BLOB PRIMARY KEY, userID INTEGER) WITHOUT ROWID;")
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		_, err = stmt.Step()
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		insStmt, err := conn.Prepare("INSERT INTO key_userid (keyHash, userID) VALUES ($1, $2);")
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		rows, err := db.Query("SELECT UNHEX(SUBSTRING(SHA2(`key`, 256),1,32)), `userid` FROM `keys` WHERE `key` != ''")
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var keyHash []byte
			var userID int64
			if err := rows.Scan(&keyHash, &userID); err != nil {
				http.Error(rw, err.Error(), 500)
				return
			}
			err = insStmt.Reset()
			if err != nil {
				http.Error(rw, err.Error(), 500)
				return
			}
			insStmt.SetBytes("$1", keyHash)
			insStmt.SetInt64("$2", userID)
			_, err = insStmt.Step()
			if err, ok := err.(sqlite.Error); ok && err.Code == sqlite.SQLITE_CONSTRAINT_PRIMARYKEY {
				// The same key was used by different users at different times.
				continue
			}
			if err != nil {
				http.Error(rw, err.Error(), 500)
				return
			}
		}
		if err := rows.Err(); err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		stmt, err = conn.Prepare("VACUUM;")
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		_, err = stmt.Step()
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		if err := conn.Close(); err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		http.ServeFile(rw, r, "/tmp/dump.sqlite")
	})

	go func() {
		log.Println(http.ListenAndServe("0.0.0.0:6000", nil))
	}()

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	rate := time.NewTicker(time.Second)

	checkpoint, err := ioutil.ReadFile(os.Getenv("CHECKPOINT_FILE"))
	fatalIfErr(err)
	_since, err := strconv.ParseInt(string(checkpoint), 10, 64)
	fatalIfErr(err)
	since := func() int64 { return atomic.LoadInt64(&_since) }
	expvar.Publish("since", expvar.Func(func() interface{} { return since() }))

	for {
		fatalIfErr(ioutil.WriteFile(os.Getenv("CHECKPOINT_FILE"),
			[]byte(strconv.FormatInt(since(), 10)), 0644))

		users, _, err := githubClient.Users.ListAll(context.Background(), &github.UserListOptions{
			Since: since(),
			ListOptions: github.ListOptions{
				PerPage: 100,
			},
		})
		if err, ok := err.(*github.RateLimitError); ok {
			log.Printf("Hit rate limit, sleeping until %v...", err.Rate.Reset)
			rateLimited.Add(1)
			time.Sleep(time.Until(err.Rate.Reset.Time))
			continue
		}
		if err != nil {
			log.Printf("Failed to list users: %v", err)
			listErrors.Add(1)
			<-rate.C
			continue
		}

		if len(users) == 0 {
			// Reached the end of the list.
			log.Printf("Reached the end of the list at ID %d; restarting...", since())
			atomic.StoreInt64(&_since, 0)
			continue
		}

		for _, u := range users {
			if u.GetID() <= since() {
				log.Fatalf("Got user with ID lower than since parameter (%v): %v", since(), u)
			}
			atomic.StoreInt64(&_since, u.GetID()) // Link headers would be better.

			if u.GetType() == "Organization" {
				skippedOrgs.Add(1)
				continue
			}

			currentUser.Set(u.GetLogin())

			<-rate.C
			resp, err := httpClient.Get("https://github.com/" + u.GetLogin() + ".keys")
			if err != nil {
				log.Printf("Failed to fetch %v's keys: %v", u.GetLogin(), err)
				fetchErrors.Add(1)
				continue
			}
			keys, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Printf("Failed to read %v's keys: %v", u.GetLogin(), err)
				fetchErrors.Add(1)
				continue
			}
			resp.Body.Close()
			// Some users show up in the /users endpoint, but can't be looked up
			// by ID, name, or keys. Support confirmed they are banned. For example:
			// https://api.github.com/users?since=40601479&per_page=1
			// https://api.github.com/users/cannabiscode
			// https://api.github.com/user/40601480
			if resp.StatusCode == http.StatusNotFound {
				fetch404.Add(1)
				continue
			}
			if resp.StatusCode != http.StatusOK {
				log.Printf("Failed to fetch %v's keys: HTTP status %q", u.GetLogin(), resp.Status)
				fetchErrors.Add(1)
				continue
			}

			for _, key := range strings.Split(strings.TrimSpace(string(keys)), "\n") {
				key = strings.TrimSpace(key)
				if key == "" {
					continue
				}
				_, err := insert.Exec(u.GetID(), u.GetLogin(), key, key, u.GetID())
				if err != nil {
					log.Printf("Failed to insert %v's keys: %v", u.GetLogin(), err)
					insertErrors.Add(1)
					continue
				}

				fetchedKeys.Add(1)
			}

			fetchedUsers.Add(1)
		}
	}
}

func fatalIfErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
