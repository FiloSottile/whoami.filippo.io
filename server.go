package main

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/google/go-github/v29/github"
	"golang.org/x/crypto/ssh"
)

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
    |  ssh public keys and Ben (benjojo.co.uk) grabbed them all.          |
    |                                                                     |
    |  That's pretty handy at times :) for example your key is at         |
    |  https://github.com/{{ .User }}.keys
    |                                                                     |
    |  If this behavior is problematic for you, you can tell ssh not to   |
    |  present your public keys to the server by default.                 |
    |  Read more: https://git.io/Jv8Vi                                    |
    |                                                                     |
    |  P.S. This whole thingy is Open Source! (And written in Go!)        |
    |  https://github.com/FiloSottile/whoami.filippo.io                   |
    |                                                                     |
    |  -- @FiloSottile (https://twitter.com/FiloSottile)                  |
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
    |  We tried to use that to find your GitHub username, but we          |
    |  couldn't :( maybe you don't even have GitHub ssh keys, do you?     |
    |                                                                     |
    |  By the way, did you know that GitHub publishes all users'          |
    |  ssh public keys and Ben (benjojo.co.uk) grabbed them all?          |
    |                                                                     |
    |  That's pretty handy at times :) But not this time :(               |
    |                                                                     |
    |                                                                     |
    |  P.S. This whole thingy is Open Source! (And written in Go!)        |
    |  https://github.com/FiloSottile/whoami.filippo.io                   |
    |                                                                     |
    |  -- @FiloSottile (https://twitter.com/FiloSottile)                  |
    |                                                                     |
    +---------------------------------------------------------------------+

`, "\n", "\n\r", -1))

var agentMsg = []byte(strings.Replace(`
                      ***** WARNING ***** WARNING *****

         You have SSH agent forwarding turned (universally?) on. That
        is a VERY BAD idea. For example right now I have access to your
        agent and I can use your keys however I want as long as you are
       connected. I'm a good guy and I won't do anything, but ANY SERVER
        YOU LOG IN TO AND ANYONE WITH ROOT ON THOSE SERVERS CAN LOGIN AS
                                 YOU ANYWHERE.

                       Read more:  http://git.io/vO2A6
`, "\n", "\n\r", -1))

var x11Msg = []byte(strings.Replace(`
                      ***** WARNING ***** WARNING *****

            You have X11 forwarding turned (universally?) on. That
        is a VERY BAD idea. For example right now I have access to your
          X11 server and I can access your desktop as long as you are
       connected. I'm a good guy and I won't do anything, but ANY SERVER
         YOU LOG IN TO AND ANYONE WITH ROOT ON THOSE SERVERS CAN SNIFF
                  YOUR KEYSTROKES AND ACCESS YOUR WINDOWS.

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

	newQuery    *sql.Stmt
	legacyQuery *sql.Stmt

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

	// Never succeed a key, or we might not see the next. See KeyboardInteractiveCallback.
	return nil, errors.New("")
}

func (s *Server) KeyboardInteractiveCallback(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	// keyboard-interactive is tried when all public keys failed, and
	// since it's server-driven we can just pass without user
	// interaction to let the user in once we got all the public keys
	return nil, nil
}

type logEntry struct {
	Timestamp     string
	Username      string
	RequestTypes  []string
	Error         string
	KeysOffered   []string
	GitHub        string
	ClientVersion string
}

func (s *Server) Handle(nConn net.Conn) {
	le := &logEntry{Timestamp: time.Now().Format(time.RFC3339)}
	defer json.NewEncoder(os.Stdout).Encode(le)

	conn, chans, reqs, err := ssh.NewServerConn(nConn, s.sshConfig)
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
		if le.GitHub != "" {
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
	le.ClientVersion = fmt.Sprintf("%x", conn.ClientVersion())
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

		user, err := s.findUser(si.Keys)
		if err != nil {
			le.Error = "findUser failed: " + err.Error()
			return
		}

		if user == "" {
			channel.Write(failedMsg)
			for _, key := range si.Keys {
				channel.Write(ssh.MarshalAuthorizedKey(key))
				channel.Write([]byte("\r"))
			}
			channel.Write([]byte("\n\r"))
			return
		}

		le.GitHub = user
		name, err := s.getUserName(user)
		if err != nil {
			le.Error = "getUserName failed: " + err.Error()
			return
		}

		termTmpl.Execute(channel, struct{ Name, User string }{name, user})
		return
	}
}

func (s *Server) findUser(keys []ssh.PublicKey) (string, error) {
	for _, pk := range keys {
		var user string
		key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
		err := s.newQuery.QueryRow(key).Scan(&user)
		if err == sql.ErrNoRows && pk.Type() == ssh.KeyAlgoRSA {
			// Try the legacy database.
			k := pk.(ssh.CryptoPublicKey).CryptoPublicKey().(*rsa.PublicKey)
			err = s.legacyQuery.QueryRow(k.N.String()).Scan(&user)
		}
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return "", err
		}

		return user, nil
	}

	return "", nil
}

func (s *Server) getUserName(user string) (string, error) {
	u, _, err := s.githubClient.Users.Get(context.TODO(), user)
	if err != nil {
		return "", err
	}
	if u.Name == nil {
		return "@" + user, nil
	}
	return *u.Name, nil
}
