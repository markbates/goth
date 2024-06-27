package microsoftonline_test

import (
	"testing"

	"github.com/Avyukth/goth"
	"github.com/Avyukth/goth/providers/microsoftonline"
	"github.com/stretchr/testify/assert"
)

func Test_Implements_Session(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &microsoftonline.Session{}

	a.Implements((*goth.Session)(nil), s)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &microsoftonline.Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/foo"

	url, _ := s.GetAuthURL()
	a.Equal(url, "/foo")
}

func Test_ToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &microsoftonline.Session{
		AuthURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		AccessToken: "1234567890",
	}

	data := s.Marshal()
	a.Equal(`{"AuthURL":"https://login.microsoftonline.com/common/oauth2/v2.0/authorize","AccessToken":"1234567890","ExpiresAt":"0001-01-01T00:00:00Z"}`, data)
}

func Test_String(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &microsoftonline.Session{
		AuthURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		AccessToken: "1234567890",
	}

	a.Equal(s.String(), s.Marshal())
}
