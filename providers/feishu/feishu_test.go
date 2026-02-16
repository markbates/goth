package feishu_test

import (
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/feishu"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("FEISHU_KEY"))
	a.Equal(p.Secret, os.Getenv("FEISHU_SECRET"))
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
	s := session.(*feishu.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "accounts.feishu.cn/open-apis/authen/v1/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://open.larksuite.cn/open-apis/authen/v2/oauth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*feishu.Session)
	a.Equal(s.AuthURL, "https://open.larksuite.cn/open-apis/authen/v2/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *feishu.Provider {
	return feishu.New(os.Getenv("FEISHU_KEY"), os.Getenv("FEISHU_SECRET"), "/foo")
}
