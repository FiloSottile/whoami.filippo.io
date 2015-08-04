package main

import "errors"

type ghInfo struct {
	Name string
	User string
}

func (s *Server) getUserInfo(user string) (*ghInfo, error) {
	u, _, err := s.githubClient.Users.Get(user)
	if err != nil {
		return nil, err
	}

	if u.Name == nil {
		return nil, errors.New("uh?!")
	}

	return &ghInfo{
		Name: *u.Name,
		User: user,
	}, nil
}
