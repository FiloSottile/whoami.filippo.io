package main

import (
	"errors"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"sync"
	"text/template"

	"github.com/google/go-github/github"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
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
    |  Ah, maybe what you did't know is that GitHub publishes all users   |
    |  ssh public keys and Ben (benjojo.co.uk) grabbed them all.          |
    |                                                                     |
    |  That's pretty handy at times :) for example your key is at         |
    |  https://github.com/{{ .User }}.keys
    |                                                                     |
    |                                                                     |
    |  BTW, this whole thingy is Open Source! (And written in Go!)        |
    |  https://github.com/FiloSottile/whosthere                           |
    |                                                                     |
    |  -- @FiloSottile (https://twitter.com/FiloSottile)                  |
    |                                                                     |
    +---------------------------------------------------------------------+

`, "\n", "\n\r", -1)))

func fatalIfErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

type sessionInfo struct {
	User string
	Keys []ssh.PublicKey
}

type Server struct {
	githubClient *github.Client
	sshConfig    *ssh.ServerConfig

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

func (s *Server) Handle(nConn net.Conn) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, s.sshConfig)
	if err != nil {
		log.Println("Handshake failed:", err)
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
			log.Println("Channel accept failed:", err)
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
		// s.sessionInfo[string(conn.SessionID())]
		ui, err := s.getUserInfo("FiloSottile")
		s.mu.RUnlock()

		if err != nil {
			log.Println("getUserInfo failed:", err)
			channel.Close()
			continue
		}

		termTmpl.Execute(channel, ui)

		channel.Close()
	}
}

type Config struct {
	HostKey string `yaml:"HostKey"`

	UserAgent    string `yaml:"UserAgent"`
	GitHubID     string `yaml:"GitHubID"`
	GitHubSecret string `yaml:"GitHubSecret"`
}

func main() {
	configText, err := ioutil.ReadFile("config.yml")
	fatalIfErr(err)
	var C Config
	fatalIfErr(yaml.Unmarshal(configText, &C))

	t := &github.UnauthenticatedRateLimitedTransport{
		ClientID:     C.GitHubID,
		ClientSecret: C.GitHubSecret,
	}
	GitHubClient := github.NewClient(t.Client())
	GitHubClient.UserAgent = C.UserAgent

	server := &Server{
		githubClient: GitHubClient,
		sessionInfo:  make(map[string]sessionInfo),
	}
	server.sshConfig = &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			// keyboard-interactive is tried when all public keys failed, and
			// since it's server-driven we can just pass without user
			// interaction to let the user in once we got all the public keys
			return nil, nil
		},
		PublicKeyCallback: server.PublicKeyCallback,
	}

	private, err := ssh.ParsePrivateKey([]byte(C.HostKey))
	fatalIfErr(err)
	server.sshConfig.AddHostKey(private)

	listener, err := net.Listen("tcp", "127.0.0.1:2022")
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
