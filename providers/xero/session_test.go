package xero_test

import (
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/xero"
	"github.com/stretchr/testify/assert"
)

func Test_Implements_Session(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &xero.Session{}

	a.Implements((*goth.Session)(nil), s)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &xero.Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/foo"

	url, _ := s.GetAuthURL()
	a.Equal(url, "/foo")
}

func Test_ToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &xero.Session{}

	data := s.Marshal()
	a.Equal(data, `{"AuthURL":"","AccessToken":null,"RequestToken":null,"AccessTokenExpires":"0001-01-01T00:00:00Z"}`)
}

func Test_String(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &xero.Session{}

	a.Equal(s.String(), s.Marshal())
}
