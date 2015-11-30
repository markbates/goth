package digitalocean_test

import (
	"testing"

	"github.com/smagic39/goth/providers/digitalocean"
	"github.com/stretchr/testify/assert"
)

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &digitalocean.Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/foo"

	url, _ := s.GetAuthURL()
	a.Equal(url, "/foo")
}

func Test_ToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &digitalocean.Session{}

	data := s.Marshal()
	a.Equal(data, `{"AuthURL":"","AccessToken":""}`)
}

func Test_String(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &digitalocean.Session{}

	a.Equal(s.String(), s.Marshal())
}
