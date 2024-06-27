package bitly_test

import (
	"testing"

	"github.com/Avyukth/goth/providers/bitly"
	"github.com/stretchr/testify/assert"
)

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	s := &bitly.Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/bar"
	url, _ := s.GetAuthURL()
	a.Equal(url, "/bar")
}

func Test_ToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	s := &bitly.Session{
		AuthURL:     "https://bitly.com/oauth/authorize",
		AccessToken: "access_token",
	}
	a.Equal(s.Marshal(), `{"AuthURL":"https://bitly.com/oauth/authorize","AccessToken":"access_token"}`)
}
