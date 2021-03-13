package main

import (
	"context"
	"database/sql"
	"expvar"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/go-github/v29/github"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
)

func fatalIfErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	go func() {
		log.Println(http.ListenAndServe(os.Getenv("LISTEN_DEBUG"), nil))
	}()

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	tc := oauth2.NewClient(context.Background(), ts)
	GitHubClient := github.NewClient(tc)

	db, err := sql.Open("mysql", os.Getenv("MYSQL_DSN"))
	fatalIfErr(err)
	fatalIfErr(db.Ping())
	_, err = db.Exec("SET NAMES UTF8")
	fatalIfErr(err)
	legacyQuery, err := db.Prepare("SELECT `username` FROM `keystore` WHERE `N` = ? LIMIT 1")
	fatalIfErr(err)
	newQuery, err := db.Prepare("SELECT `username` FROM `keys` WHERE `key` = ? LIMIT 1")
	fatalIfErr(err)

	server := &Server{
		githubClient: GitHubClient,
		legacyQuery:  legacyQuery,
		newQuery:     newQuery,
		sessionInfo:  make(map[string]sessionInfo),

		hsErrs:     expvar.NewInt("handshake_errors"),
		errors:     expvar.NewInt("errors"),
		agent:      expvar.NewInt("agent"),
		x11:        expvar.NewInt("x11"),
		roaming:    expvar.NewInt("roaming"),
		conns:      expvar.NewInt("conns"),
		withKeys:   expvar.NewInt("with_keys"),
		identified: expvar.NewInt("identified"),
	}
	server.sshConfig = &ssh.ServerConfig{
		KeyboardInteractiveCallback: server.KeyboardInteractiveCallback,
		PublicKeyCallback:           server.PublicKeyCallback,
	}

	private, err := ssh.ParsePrivateKey([]byte(os.Getenv("SSH_HOST_KEY")))
	fatalIfErr(err)
	server.sshConfig.AddHostKey(private)
	privateEd, err := ssh.ParsePrivateKey([]byte(os.Getenv("SSH_HOST_KEY_ED25519")))
	fatalIfErr(err)
	server.sshConfig.AddHostKey(privateEd)

	listener, err := net.Listen("tcp", os.Getenv("LISTEN_SSH"))
	fatalIfErr(err)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept failed:", err)
			continue
		}

		go server.Handle(conn)
	}
}
