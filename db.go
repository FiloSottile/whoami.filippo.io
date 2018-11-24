package main

import (
	"context"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"database/sql"
	"reflect"
	"unsafe"

	"golang.org/x/crypto/ssh"
)

func sshToCrypto(pk ssh.PublicKey) crypto.PublicKey {
	// Don't judge me, judge the ssh.PublicKey interface. And me. A bit.
	switch pk.Type() {
	case ssh.KeyAlgoRSA:
		return (*rsa.PublicKey)(unsafe.Pointer(reflect.ValueOf(pk).Elem().UnsafeAddr()))
	case ssh.KeyAlgoDSA:
		return (*dsa.PublicKey)(unsafe.Pointer(reflect.ValueOf(pk).Elem().UnsafeAddr()))
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return (*ecdsa.PublicKey)(unsafe.Pointer(reflect.ValueOf(pk).Elem().UnsafeAddr()))
	default:
		return nil
	}
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

func (s *Server) findUser(keys []ssh.PublicKey) (string, error) {
	for _, pk := range keys {
		if pk.Type() != ssh.KeyAlgoRSA {
			continue
		}

		k := sshToCrypto(pk).(*rsa.PublicKey)

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
