package main

import (
	"database/sql"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"text/template"

	"github.com/google/go-github/github"
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
    |  Ah, maybe what you did't know is that GitHub publishes all users'  |
    |  ssh public keys and Ben (benjojo.co.uk) grabbed them all.          |
    |                                                                     |
    |  That's pretty handy at times :) for example your key is at         |
    |  https://github.com/{{ .User }}.keys
    |                                                                     |
    |                                                                     |
    |  P.S. This whole thingy is Open Source! (And written in Go!)        |
    |  https://github.com/FiloSottile/whosthere                           |
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
    |  https://github.com/FiloSottile/whosthere                           |
    |                                                                     |
    |  -- @FiloSottile (https://twitter.com/FiloSottile)                  |
    |                                                                     |
    +---------------------------------------------------------------------+

`, "\n", "\n\r", -1))

type sessionInfo struct {
	User string
	Keys []ssh.PublicKey
}

type Server struct {
	githubClient *github.Client
	sshConfig    *ssh.ServerConfig
	sqlQuery     *sql.Stmt

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

func (s *Server) Handle(nConn net.Conn) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, s.sshConfig)
	if err != nil {
		log.Println("[ERR] Handshake failed:", err)
		return
	}
	defer func() {
		s.mu.Lock()
		delete(s.sessionInfo, string(conn.SessionID()))
		s.mu.Unlock()
		conn.Close()
	}()
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Println("[ERR] Channel accept failed:", err)
			continue
		}

		go func(in <-chan *ssh.Request) {
			for req := range in {
				ok := false
				switch req.Type {
				case "shell":
					ok = true
				case "pty-req":
					ok = true
				}
				req.Reply(ok, nil)
			}
		}(requests)

		s.mu.RLock()
		si := s.sessionInfo[string(conn.SessionID())]
		s.mu.RUnlock()

		user, err := s.findUser(si.Keys)
		if err != nil {
			log.Println("[ERR] findUser failed:", err)
			channel.Close()
			continue
		}

		if user == "" {
			channel.Write(failedMsg)
			for _, key := range si.Keys {
				channel.Write(ssh.MarshalAuthorizedKey(key))
				channel.Write([]byte("\r"))
				log.Print(string(ssh.MarshalAuthorizedKey(key)))
			}
			channel.Write([]byte("\n\r"))
			channel.Close()
			continue
		}

		log.Println(user)

		ui, err := s.getUserInfo(user)
		if err != nil {
			log.Println("[ERR] getUserInfo failed:", err)
			channel.Close()
			continue
		}

		termTmpl.Execute(channel, ui)

		channel.Close()
	}
}
