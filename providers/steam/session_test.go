package steam_test

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/steam"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_Implements_Session(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &steam.Session{}

	a.Implements((*goth.Session)(nil), s)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &steam.Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/foo"

	url, _ := s.GetAuthURL()
	a.Equal(url, "/foo")
}

func Test_ToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &steam.Session{}

	data := s.Marshal()
	a.Equal(data, `{"AuthURL":"","CallbackURL":"","SteamID":"","ResponseNonce":""}`)
}

func Test_String(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &steam.Session{}

	a.Equal(s.String(), s.Marshal())
}
