package main

import (
	"crypto/rsa"
	"database/sql"
	"reflect"
	"unsafe"

	"golang.org/x/crypto/ssh"
)

func (s *Server) findUser(keys []ssh.PublicKey) (string, error) {
	for _, pk := range keys {
		if pk.Type() != "ssh-rsa" {
			continue
		}

		// Don't judge me, judge the ssh.PublicKey interface. And me. A bit.
		k := (*rsa.PublicKey)(unsafe.Pointer(reflect.ValueOf(pk).Elem().UnsafeAddr()))

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
