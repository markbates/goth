package zoom_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/zoom"
	"github.com/stretchr/testify/assert"
)

func zoomProvider() *zoom.Provider {
	return zoom.New(os.Getenv("ZOOM_KEY"), os.Getenv("ZOOM_SECRET"), "/foo", "basic")
}

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := zoomProvider()
	a.Equal(provider.ClientKey, os.Getenv("ZOOM_KEY"))
	a.Equal(provider.Secret, os.Getenv("ZOOM_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), zoomProvider())
}
func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	provider := zoomProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*zoom.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://zoom.us/oauth/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("ZOOM_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := zoomProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"https://app.zoom.io/oauth","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*zoom.Session)
	a.Equal(session.AuthURL, "https://app.zoom.io/oauth")
	a.Equal(session.AccessToken, "1234567890")
}
