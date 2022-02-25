package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"expvar"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"crawshaw.io/sqlite/sqlitex"
	"github.com/google/go-github/v42/github"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
)

func main() {
	go func() {
		log.Println(http.ListenAndServe(os.Getenv("LISTEN_DEBUG"), nil))
	}()

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	tc := oauth2.NewClient(context.Background(), ts)
	ghClient := github.NewClient(tc)
	_, _, err := ghClient.Users.Get(context.Background(), "")
	fatalIfErr(err)
	log.Println("Connected to GitHub...")

	db, err := sqlitex.Open(os.Getenv("DB_PATH"), 0, 3)
	fatalIfErr(err)
	log.Println("Opened database...")

	server := &Server{
		githubClient: ghClient,
		db:           db,
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
	log.Println("Loaded keys...")

	listener, err := net.Listen("tcp", os.Getenv("LISTEN_SSH"))
	fatalIfErr(err)
	log.Println("Listening...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept failed:", err)
			continue
		}

		go server.Handle(conn)
	}
}

func fatalIfErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

var termTmpl = template.Must(template.New("termTmpl").Parse(strings.Replace(`
    +---------------------------------------------------------------------+
    |                                                                     |
    |             _o/ Hello {{ .Name }}!
    |                                                                     |
    |                                                                     |
    |  Did you know that ssh sends all your public keys to any server     |
    |  it tries to authenticate to?                                       |
    |                                                                     |
    |  That's how we know you are @{{ .User }} on GitHub!
    |                                                                     |
    |  Ah, maybe what you didn't know is that GitHub publishes all users' |
    |  ssh public keys. Myself, I learned it from Ben (benjojo.co.uk).    |
    |                                                                     |
    |  That's pretty handy at times :) for example your key is at         |
    |  https://github.com/{{ .User }}.keys
    |                                                                     |
    |  -- @FiloSottile (https://twitter.com/FiloSottile)                  |
    |                                                                     |
    |                                                                     |
    |  P.S. The source of this server is at                               |
    |  https://github.com/FiloSottile/whoami.filippo.io                   |
    |                                                                     |
    +---------------------------------------------------------------------+

`, "\n", "\n\r", -1)))

var failedMsg = []byte(strings.Replace(`
    +---------------------------------------------------------------------+
    |                                                                     |
    |             _o/ Hello!                                              |
    |                                                                     |
    |                                                                     |
    |  Did you know that ssh sends all your public keys to any server     |
    |  it tries to authenticate to? You can see yours echoed below.       |
    |                                                                     |
    |  We tried to use them to lookup your GitHub account,                |
    |  but got no match :(                                                |
    |                                                                     |
    |  -- @FiloSottile (https://twitter.com/FiloSottile)                  |
    |                                                                     |
    |                                                                     |
    |  P.S. The source of this server is at                               |
    |  https://github.com/FiloSottile/whoami.filippo.io                   |
    |                                                                     |
    +---------------------------------------------------------------------+

`, "\n", "\n\r", -1))

var agentMsg = []byte(strings.Replace(`
                      ***** WARNING ***** WARNING *****

           You have SSH agent forwarding turned (universally?) on.
         That is a VERY BAD idea. For example, right now this server
          has access to your agent and can use your keys however it
                    likes as long as you are connected.

               ANY SERVER YOU LOG IN TO AND ANYONE WITH ROOT ON
                   THOSE SERVERS CAN LOGIN AS YOU ANYWHERE.

                       Read more:  http://git.io/vO2A6
`, "\n", "\n\r", -1))

var x11Msg = []byte(strings.Replace(`
                      ***** WARNING ***** WARNING *****

               You have X11 forwarding turned (universally?) on.
          That is a VERY BAD idea. For example, right now this server
              has access to your desktop, windows, and keystrokes
                         as long as you are connected.

                ANY SERVER YOU LOG IN TO AND ANYONE WITH ROOT ON
         THOSE SERVERS CAN SNIFF YOUR KEYSTROKES AND ACCESS YOUR WINDOWS.

     Read more:  http://www.hackinglinuxexposed.com/articles/20040705.html
`, "\n", "\n\r", -1))

var roamingMsg = []byte(strings.Replace(`
                      ***** WARNING ***** WARNING *****

    You have roaming turned on. If you are using OpenSSH, that most likely
       means you are vulnerable to the CVE-2016-0777 information leak.

   THIS MEANS THAT ANY SERVER YOU CONNECT TO MIGHT OBTAIN YOUR PRIVATE KEYS.

     Add "UseRoaming no" to the "Host *" section of your ~/.ssh/config or
           /etc/ssh/ssh_config file, rotate keys and update ASAP.

Read more:  https://www.qualys.com/2016/01/14/cve-2016-0777-cve-2016-0778/openssh-cve-2016-0777-cve-2016-0778.txt
`, "\n", "\n\r", -1))

type sessionInfo struct {
	User string
	Keys []ssh.PublicKey
}

type Server struct {
	githubClient *github.Client
	sshConfig    *ssh.ServerConfig

	db *sqlitex.Pool

	hsErrs, errors              *expvar.Int
	agent, x11, roaming         *expvar.Int
	conns, withKeys, identified *expvar.Int

	mu          sync.RWMutex
	sessionInfo map[string]sessionInfo
}

func (s *Server) PublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	s.mu.Lock()
	si := s.sessionInfo[string(conn.SessionID())]
	si.User = conn.User()
	si.Keys = append(si.Keys, key)
	s.sessionInfo[string(conn.SessionID())] = si
	s.mu.Unlock()

	// Never accept a key, or we might not see the next.
	return nil, errors.New("")
}

func (s *Server) KeyboardInteractiveCallback(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	// keyboard-interactive is tried when all public keys failed, and
	// since it's server-driven we can just pass without user
	// interaction to let the user in once we got all the public keys.
	return nil, nil
}

type logEntry struct {
	Timestamp     string
	Username      string   `json:",omitempty"`
	RequestTypes  []string `json:",omitempty"`
	Error         string   `json:",omitempty"`
	KeysOffered   []string `json:",omitempty"`
	GitHubID      int64    `json:",omitempty"`
	GitHubName    string   `json:",omitempty"`
	ClientVersion string   `json:",omitempty"`
}

func (s *Server) Handle(nConn net.Conn) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, s.sshConfig)
	if err == io.EOF {
		// Port scan or health check.
		return
	}
	le := &logEntry{Timestamp: time.Now().Format(time.RFC3339)}
	defer json.NewEncoder(os.Stdout).Encode(le)
	if err != nil {
		le.Error = "Handshake failed: " + err.Error()
		s.hsErrs.Add(1)
		return
	}
	defer func() {
		s.conns.Add(1)
		if len(le.KeysOffered) > 0 {
			s.withKeys.Add(1)
		}
		if le.Error != "" {
			s.errors.Add(1)
		}
		if le.GitHubID != 0 {
			s.identified.Add(1)
		}
		s.mu.Lock()
		delete(s.sessionInfo, string(conn.SessionID()))
		s.mu.Unlock()
		time.Sleep(500 * time.Millisecond)
		conn.Close()
	}()
	roaming := false
	go func(in <-chan *ssh.Request) {
		for req := range in {
			le.RequestTypes = append(le.RequestTypes, req.Type)
			if req.Type == "roaming@appgate.com" {
				roaming = true
			}
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}(reqs)

	s.mu.RLock()
	si := s.sessionInfo[string(conn.SessionID())]
	s.mu.RUnlock()

	le.Username = conn.User()
	le.ClientVersion = string(conn.ClientVersion())
	for _, key := range si.Keys {
		le.KeysOffered = append(le.KeysOffered, string(ssh.MarshalAuthorizedKey(key)))
	}

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			le.Error = "Channel accept failed: " + err.Error()
			return
		}
		defer channel.Close()

		agentFwd, x11 := false, false
		reqLock := &sync.Mutex{}
		reqLock.Lock()
		timeout := time.AfterFunc(30*time.Second, func() { reqLock.Unlock() })

		go func(in <-chan *ssh.Request) {
			for req := range in {
				le.RequestTypes = append(le.RequestTypes, req.Type)
				ok := false
				switch req.Type {
				case "shell":
					fallthrough
				case "pty-req":
					ok = true

					// "auth-agent-req@openssh.com" and "x11-req" always arrive
					// before the "pty-req", so we can go ahead now
					if timeout.Stop() {
						reqLock.Unlock()
					}

				case "auth-agent-req@openssh.com":
					agentFwd = true
				case "x11-req":
					x11 = true
				}

				if req.WantReply {
					req.Reply(ok, nil)
				}
			}
		}(requests)

		reqLock.Lock()
		if agentFwd {
			s.agent.Add(1)
			channel.Write(agentMsg)
		}
		if x11 {
			s.x11.Add(1)
			channel.Write(x11Msg)
		}
		if roaming {
			s.roaming.Add(1)
			channel.Write(roamingMsg)
		}

		userID, err := s.findUser(si.Keys)
		if err != nil {
			le.Error = "findUser failed: " + err.Error()
			return
		}

		if userID == 0 {
			channel.Write(failedMsg)
			for _, key := range si.Keys {
				channel.Write(ssh.MarshalAuthorizedKey(key))
				channel.Write([]byte("\r"))
			}
			channel.Write([]byte("\n\r"))
			return
		}

		le.GitHubID = userID
		u, _, err := s.githubClient.Users.GetByID(context.TODO(), userID)
		if err != nil {
			le.Error = "getUserName failed: " + err.Error()
			return
		}

		login := *u.Login
		name := "@" + login
		if u.Name != nil {
			le.GitHubName = *u.Name
			name = *u.Name
		}

		termTmpl.Execute(channel, struct{ Name, User string }{name, login})
		return
	}
}

func (s *Server) findUser(keys []ssh.PublicKey) (int64, error) {
	conn := s.db.Get(context.TODO())
	if conn == nil {
		return 0, errors.New("couldn't get db connection")
	}
	defer s.db.Put(conn)
	for _, pk := range keys {
		key := bytes.TrimSpace(ssh.MarshalAuthorizedKey(pk))
		keyHash := sha256.Sum256(key)
		stmt := conn.Prep("SELECT userID FROM key_userid WHERE keyHash = $kh;")
		stmt.SetBytes("$kh", keyHash[:16])
		if hasRow, err := stmt.Step(); err != nil {
			return 0, err
		} else if !hasRow {
			continue
		}
		defer stmt.Reset()
		return stmt.GetInt64("userID"), nil
	}

	return 0, nil
}
