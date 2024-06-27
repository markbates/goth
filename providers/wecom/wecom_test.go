package wecom_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/Avyukth/goth"
	"github.com/Avyukth/goth/providers/wecom"
	"github.com/stretchr/testify/assert"
)

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), wecomProvider())
}

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := wecomProvider()
	a.Equal(provider.ClientKey, os.Getenv("WECOM_CORP_ID"))
	a.Equal(provider.Secret, os.Getenv("WECOM_SECRET"))
	a.Equal(provider.AgentID, os.Getenv("WECOM_AGENT_ID"))
	a.Equal(provider.CallbackURL, "/foo")
}

func TestBeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := wecomProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*wecom.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://open.work.weixin.qq.com/wwopen/sso/qrConnect")
	a.Contains(s.AuthURL, fmt.Sprintf("appid=%s", os.Getenv("WECOM_CORP_ID")))
	a.Contains(s.AuthURL, fmt.Sprintf("agentid=%s", os.Getenv("WECOM_AGENT_ID")))
	a.Contains(s.AuthURL, "state=test_state")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := wecomProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"http://wecom/auth_url","AccessToken":"1234567890","UserID":"1122334455"}`)
	a.NoError(err)
	session := s.(*wecom.Session)
	a.Equal(session.AuthURL, "http://wecom/auth_url")
	a.Equal(session.AccessToken, "1234567890")
	a.Equal(session.UserID, "1122334455")
}

func wecomProvider() *wecom.Provider {
	return wecom.New(os.Getenv("WECOM_CORP_ID"), os.Getenv("WECOM_SECRET"), os.Getenv("WECOM_AGENT_ID"), "/foo")
}
