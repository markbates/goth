package spotify_test

import (
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/spotify"
	"github.com/stretchr/testify/assert"
)

func Test_ImplementsSession(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &spotify.Session{}
	a.Implements((*goth.Session)(nil), s)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &spotify.Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/foo"
	url, _ := s.GetAuthURL()
	a.Equal(url, "/foo")
}

func Test_ToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &spotify.Session{}

	data := s.Marshal()
	a.Equal(data, `{"AuthURL":"","AccessToken":"","RefreshToken":"","ExpiresAt":"0001-01-01T00:00:00Z"}`)
}
