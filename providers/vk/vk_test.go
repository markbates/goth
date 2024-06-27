package vk_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/Avyukth/goth"
	"github.com/Avyukth/goth/providers/vk"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := vkProvider()
	a.Equal(provider.ClientKey, os.Getenv("VK_KEY"))
	a.Equal(provider.Secret, os.Getenv("VK_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Name(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := vkProvider()
	a.Equal(provider.Name(), "vk")
}

func Test_SetName(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := vkProvider()
	provider.SetName("foo")
	a.Equal(provider.Name(), "foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), vkProvider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := vkProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*vk.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "oauth.vk.com/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("VK_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=email")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := vkProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"http://vk.com/auth_url","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*vk.Session)
	a.Equal(session.AuthURL, "http://vk.com/auth_url")
	a.Equal(session.AccessToken, "1234567890")
}

func vkProvider() *vk.Provider {
	return vk.New(os.Getenv("VK_KEY"), os.Getenv("VK_SECRET"), "/foo", "user")
}
