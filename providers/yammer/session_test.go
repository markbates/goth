package yammer_test

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/yammer"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_Implements_Session(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &yammer.Session{}

	a.Implements((*goth.Session)(nil), s)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &yammer.Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/foo"

	url, _ := s.GetAuthURL()
	a.Equal(url, "/foo")
}

func Test_ToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &yammer.Session{}

	data := s.Marshal()
	a.Equal(data, `{"AuthURL":"","AccessToken":""}`)
}

func Test_String(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &yammer.Session{}

	a.Equal(s.String(), s.Marshal())
}
