package reddit_test

import (
	"github.com/jarcoal/httpmock"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/reddit"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("REDDIT_CLIENT_ID"))
	a.Equal(p.Secret, os.Getenv("REDDIT_CLIENT_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), provider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()
	session, err := p.BeginAuth("test_state")
	s := session.(*reddit.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://www.reddit.com/api/v1/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://www.reddit.com/api/v1/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*reddit.Session)
	a.Equal(s.AuthURL, "https://www.reddit.com/api/v1/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func Test_FetchUser(t *testing.T) {
	//t.Parallel()
	a := assert.New(t)

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	sampleResp := `{
  "verified": true,
  "id": "333111",
  "icon_img": "https://www.redditstatic.com/avatars/avatar_default_17_008985.png",
  "name": "TestName"
}`

	httpmock.RegisterResponder("GET", "https://oauth.reddit.com/api/v1/me", httpmock.NewStringResponder(200, sampleResp))

	p := provider()
	session, _ := p.BeginAuth("test_state")
	s := session.(*reddit.Session)
	s.AccessToken = "token"
	u, err := p.FetchUser(s)
	a.Nil(err)
	a.Equal(u.UserID, "333111")
	a.Equal(u.NickName, "TestName")
	a.Equal(u.Name, "TestName")
	a.Equal(u.AvatarURL, "https://www.redditstatic.com/avatars/avatar_default_17_008985.png")
	a.Equal("token", u.AccessToken)
}

func provider() *reddit.Provider {
	return reddit.New(os.Getenv("REDDIT_CLIENT_ID"), os.Getenv("REDDIT_CLIENT_SECRET"), "/foo", "test-app by /u/test")
}
