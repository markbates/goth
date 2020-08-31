package gothic_test

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"html"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	. "github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/faux"
	"github.com/stretchr/testify/assert"
)

type mapKey struct {
	r *http.Request
	n string
}

type ProviderStore struct {
	Store map[mapKey]*sessions.Session
}

func NewProviderStore() *ProviderStore {
	return &ProviderStore{map[mapKey]*sessions.Session{}}
}

func (p ProviderStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	s := p.Store[mapKey{r, name}]
	if s == nil {
		s, err := p.New(r, name)
		return s, err
	}
	return s, nil
}

func (p ProviderStore) New(r *http.Request, name string) (*sessions.Session, error) {
	s := sessions.NewSession(p, name)
	s.Options = &sessions.Options{
		Path:   "/",
		MaxAge: 86400 * 30,
	}
	p.Store[mapKey{r, name}] = s
	return s, nil
}

func (p ProviderStore) Save(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
	p.Store[mapKey{r, s.Name()}] = s
	return nil
}

var fauxProvider goth.Provider

func init() {
	Store = NewProviderStore()
	fauxProvider = &faux.Provider{}
	goth.UseProviders(fauxProvider)
}

func Test_BeginAuthHandler(t *testing.T) {
	a := assert.New(t)

	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth?provider=faux", nil)
	a.NoError(err)

	BeginAuthHandler(res, req)

	sess, err := Store.Get(req, SessionName)
	if err != nil {
		t.Fatalf("error getting faux Gothic session: %v", err)
	}

	sessStr, ok := sess.Values["faux"].(string)
	if !ok {
		t.Fatalf("Gothic session not stored as marshalled string; was %T (value %v)",
			sess.Values["faux"], sess.Values["faux"])
	}
	gothSession, err := fauxProvider.UnmarshalSession(ungzipString(sessStr))
	if err != nil {
		t.Fatalf("error unmarshalling faux Gothic session: %v", err)
	}
	au, _ := gothSession.GetAuthURL()

	a.Equal(http.StatusTemporaryRedirect, res.Code)
	a.Contains(res.Body.String(),
		fmt.Sprintf(`<a href="%s">Temporary Redirect</a>`, html.EscapeString(au)))
}

func Test_GetAuthURL(t *testing.T) {
	a := assert.New(t)

	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth?provider=faux", nil)
	a.NoError(err)

	u, err := GetAuthURL(res, req)
	a.NoError(err)

	// Check that we get the correct auth URL with a state parameter
	parsed, err := url.Parse(u)
	a.NoError(err)
	a.Equal("http", parsed.Scheme)
	a.Equal("example.com", parsed.Host)
	q := parsed.Query()
	a.Contains(q, "client_id")
	a.Equal("code", q.Get("response_type"))
	a.NotZero(q, "state")

	// Check that if we run GetAuthURL on another request, that request's
	// auth URL has a different state from the previous one.
	req2, err := http.NewRequest("GET", "/auth?provider=faux", nil)
	a.NoError(err)
	url2, err := GetAuthURL(httptest.NewRecorder(), req2)
	a.NoError(err)
	parsed2, err := url.Parse(url2)
	a.NoError(err)
	a.NotEqual(parsed.Query().Get("state"), parsed2.Query().Get("state"))
}

func Test_CompleteUserAuth(t *testing.T) {
	a := assert.New(t)

	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth/callback?provider=faux", nil)
	a.NoError(err)

	sess := faux.Session{Name: "Homer Simpson", Email: "homer@example.com"}
	session, _ := Store.Get(req, SessionName)
	session.Values["faux"] = gzipString(sess.Marshal())
	err = session.Save(req, res)
	a.NoError(err)

	user, err := CompleteUserAuth(res, req)
	a.NoError(err)

	a.Equal(user.Name, "Homer Simpson")
	a.Equal(user.Email, "homer@example.com")
}

func Test_CompleteUserAuthWithSessionDeducedProvider(t *testing.T) {
	a := assert.New(t)

	res := httptest.NewRecorder()
	// Inteintionally omit a provider argument, force looking in session.
	req, err := http.NewRequest("GET", "/auth/callback", nil)
	a.NoError(err)

	sess := faux.Session{Name: "Homer Simpson", Email: "homer@example.com"}
	session, _ := Store.Get(req, SessionName)
	session.Values["faux"] = gzipString(sess.Marshal())
	err = session.Save(req, res)
	a.NoError(err)

	user, err := CompleteUserAuth(res, req)
	a.NoError(err)

	a.Equal(user.Name, "Homer Simpson")
	a.Equal(user.Email, "homer@example.com")
}

func Test_CompleteUserAuthWithContextParamProvider(t *testing.T) {
	a := assert.New(t)

	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth/callback", nil)
	a.NoError(err)

	req = GetContextWithProvider(req, "faux")

	sess := faux.Session{Name: "Homer Simpson", Email: "homer@example.com"}
	session, _ := Store.Get(req, SessionName)
	session.Values["faux"] = gzipString(sess.Marshal())
	err = session.Save(req, res)
	a.NoError(err)

	user, err := CompleteUserAuth(res, req)
	a.NoError(err)

	a.Equal(user.Name, "Homer Simpson")
	a.Equal(user.Email, "homer@example.com")
}

func Test_Logout(t *testing.T) {
	a := assert.New(t)

	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth/callback?provider=faux", nil)
	a.NoError(err)

	sess := faux.Session{Name: "Homer Simpson", Email: "homer@example.com"}
	session, _ := Store.Get(req, SessionName)
	session.Values["faux"] = gzipString(sess.Marshal())
	err = session.Save(req, res)
	a.NoError(err)

	user, err := CompleteUserAuth(res, req)
	a.NoError(err)

	a.Equal(user.Name, "Homer Simpson")
	a.Equal(user.Email, "homer@example.com")
	err = Logout(res, req)
	a.NoError(err)
	session, _ = Store.Get(req, SessionName)
	a.Equal(session.Values, make(map[interface{}]interface{}))
	a.Equal(session.Options.MaxAge, -1)
}

func Test_SetState(t *testing.T) {
	a := assert.New(t)

	req, _ := http.NewRequest("GET", "/auth?state=state", nil)
	a.Equal(SetState(req), "state")
}

func Test_GetState(t *testing.T) {
	a := assert.New(t)

	req, _ := http.NewRequest("GET", "/auth?state=state", nil)
	a.Equal(GetState(req), "state")
}

func Test_StateValidation(t *testing.T) {
	a := assert.New(t)

	Store = NewProviderStore()
	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth?provider=faux&state=state_REAL", nil)
	a.NoError(err)

	BeginAuthHandler(res, req)
	session, _ := Store.Get(req, SessionName)

	// Assert that matching states will return a nil error
	req, _ = http.NewRequest("GET", "/auth/callback?provider=faux&state=state_REAL", nil)
	session.Save(req, res)
	_, err = CompleteUserAuth(res, req)
	a.NoError(err)

	// Assert that mismatched states will return an error
	req, _ = http.NewRequest("GET", "/auth/callback?provider=faux&state=state_FAKE", nil)
	session.Save(req, res)
	_, err = CompleteUserAuth(res, req)
	a.Error(err)
}

func Test_AppleStateValidation(t *testing.T) {
	a := assert.New(t)
	appleStateValue := "xyz123-#"
	form := url.Values{}
	form.Add("state", appleStateValue)
	req, _ := http.NewRequest("POST", "/", strings.NewReader(form.Encode()))
	req.Form = form
	a.Equal(appleStateValue, GetState(req))
}

func gzipString(value string) string {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write([]byte(value)); err != nil {
		return "err"
	}
	if err := gz.Flush(); err != nil {
		return "err"
	}
	if err := gz.Close(); err != nil {
		return "err"
	}

	return b.String()
}

func ungzipString(value string) string {
	rdata := strings.NewReader(value)
	r, err := gzip.NewReader(rdata)
	if err != nil {
		return "err"
	}
	s, err := ioutil.ReadAll(r)
	if err != nil {
		return "err"
	}

	return string(s)
}
