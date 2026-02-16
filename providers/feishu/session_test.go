package feishu_test

import (
	"testing"
	"time"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/feishu"
	"github.com/stretchr/testify/assert"
)

func Test_Implements_Session(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &feishu.Session{}

	a.Implements((*goth.Session)(nil), s)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &feishu.Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/foo"

	url, _ := s.GetAuthURL()
	a.Equal(url, "/foo")
}

func Test_ToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &feishu.Session{}

	data := s.Marshal()
	a.Equal(data, `{"AuthURL":"","AccessToken":"","RefreshToken":"","ExpiresAt":"0001-01-01T00:00:00Z","RefreshTokenExpiresAt":"0001-01-01T00:00:00Z"}`)
}

func Test_GetExpiresAt(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &feishu.Session{}

	a.Equal(s.ExpiresAt, time.Time{})
}
