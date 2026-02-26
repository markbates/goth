package dropbox

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
)

func provider() *Provider {
	return New(os.Getenv("DROPBOX_KEY"), os.Getenv("DROPBOX_SECRET"), "/foo", "email")
}

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("DROPBOX_KEY"))
	a.Equal(p.Secret, os.Getenv("DROPBOX_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), provider())
}

func Test_ImplementsSession(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &Session{}
	a.Implements((*goth.Session)(nil), s)
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()
	session, err := p.BeginAuth("test_state")
	s := session.(*Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "www.dropbox.com/oauth2/authorize")
}

func Test_FetchUser(t *testing.T) {
	accountPath := "/2/users/get_current_account"

	t.Parallel()
	a := assert.New(t)
	p := provider()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.Equal(r.Header.Get("Authorization"), "Bearer 1234567890")
		a.Equal(r.Method, "POST")
		a.Equal(r.URL.Path, accountPath)
		w.Write([]byte(testAccountResponse))
	}))
	p.AccountURL = ts.URL + accountPath

	// AuthURL is superfluous for this test but ok
	session, err := p.UnmarshalSession(`{"AuthURL":"https://www.dropbox.com/oauth2/authorize","Token":"1234567890"}`)
	a.NoError(err)
	user, err := p.FetchUser(session)
	a.NoError(err)
	a.Equal(user.UserID, "dbid:AAH4f99T0taONIb-OurWxbNQ6ywGRopQngc")
	a.Equal(user.FirstName, "Franz")
	a.Equal(user.LastName, "Ferdinand")
	a.Equal(user.Name, "Franz Ferdinand")
	a.Equal(user.Description, "Franz Ferdinand (Personal)")
	a.Equal(user.NickName, "franz@dropbox.com")
	a.Equal(user.Email, "franz@dropbox.com")
	a.Equal(user.Location, "US")
	a.Equal(user.AccessToken, "1234567890")
	a.Equal(user.AccessTokenSecret, "")
	a.Equal(user.AvatarURL, "https://dl-web.dropbox.com/account_photo/get/dbid%3AAAH4f99T0taONIb-OurWxbNQ6ywGRopQngc?vers=1453416673259\u0026size=128x128")
	a.Equal(user.Provider, "dropbox")
	a.Len(user.RawData, 14)
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://www.dropbox.com/oauth2/authorize","Token":"1234567890"}`)
	a.NoError(err)

	s := session.(*Session)
	a.Equal(s.AuthURL, "https://www.dropbox.com/oauth2/authorize")
	a.Equal(s.Token, "1234567890")
}

func Test_SessionToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &Session{}

	data := s.Marshal()
	a.Equal(data, `{"AuthURL":"","Token":""}`)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/foo"
	url, _ := s.GetAuthURL()
	a.Equal(url, "/foo")
}

var testAccountResponse = `
{
    "account_id": "dbid:AAH4f99T0taONIb-OurWxbNQ6ywGRopQngc",
    "name": {
        "given_name": "Franz",
        "surname": "Ferdinand",
        "familiar_name": "Franz",
        "display_name": "Franz Ferdinand (Personal)",
        "abbreviated_name": "FF"
    },
    "email": "franz@dropbox.com",
    "email_verified": true,
    "disabled": false,
    "locale": "en",
    "referral_link": "https://db.tt/ZITNuhtI",
    "is_paired": true,
    "account_type": {
        ".tag": "business"
    },
    "root_info": {
        ".tag": "user",
        "root_namespace_id": "3235641",
        "home_namespace_id": "3235641"
    },
    "country": "US",
    "team": {
        "id": "dbtid:AAFdgehTzw7WlXhZJsbGCLePe8RvQGYDr-I",
        "name": "Acme, Inc.",
        "sharing_policies": {
            "shared_folder_member_policy": {
                ".tag": "team"
            },
            "shared_folder_join_policy": {
                ".tag": "from_anyone"
            },
            "shared_link_create_policy": {
                ".tag": "team_only"
            }
        },
        "office_addin_policy": {
            ".tag": "disabled"
        }
    },
    "profile_photo_url": "https://dl-web.dropbox.com/account_photo/get/dbid%3AAAH4f99T0taONIb-OurWxbNQ6ywGRopQngc?vers=1453416673259\u0026size=128x128",
    "team_member_id": "dbmid:AAHhy7WsR0x-u4ZCqiDl5Fz5zvuL3kmspwU"
}
`
