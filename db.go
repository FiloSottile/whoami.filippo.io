package main

import (
	"context"
	"crypto/rsa"
	"database/sql"

	"golang.org/x/crypto/ssh"
)

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

func (s *Server) findUser(keys []ssh.PublicKey) (string, error) {
	for _, pk := range keys {
		if pk.Type() != ssh.KeyAlgoRSA {
			continue
		}

		k := pk.(ssh.CryptoPublicKey).CryptoPublicKey().(*rsa.PublicKey)

		var user string
		err := s.sqlQuery.QueryRow(k.N.String()).Scan(&user)
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
