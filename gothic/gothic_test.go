package gothic_test

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"html"
	"io"
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
	// Intentionally omit a provider argument, force looking in session.
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
	a.NoError(session.Save(req, res))
	_, err = CompleteUserAuth(res, req)
	a.NoError(err)

	// Assert that mismatched states will return an error
	req, _ = http.NewRequest("GET", "/auth/callback?provider=faux&state=state_FAKE", nil)
	a.NoError(session.Save(req, res))
	_, err = CompleteUserAuth(res, req)
	a.Error(err)
}

func Test_AppleStateValidation(t *testing.T) {
	a := assert.New(t)
	appleStateValue := "xyz123-#"
	form := url.Values{}
	form.Add("state", appleStateValue)
	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
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
	s, err := io.ReadAll(r)
	if err != nil {
		return "err"
	}

	return string(s)
}

// Test_StoreInSession_ReturnsErrorOnSaveFailure verifies that StoreInSession
// properly propagates errors from session.Save().
// See: https://github.com/markbates/goth/issues/549
func Test_StoreInSession_ReturnsErrorOnSaveFailure(t *testing.T) {
	a := assert.New(t)

	// Use a store that always fails on save
	originalStore := Store
	Store = &failingStore{err: fmt.Errorf("session save failed: hash key is not set")}
	defer func() { Store = originalStore }()

	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth?provider=faux", nil)
	a.NoError(err)

	// StoreInSession should return the error from the failing store
	err = StoreInSession("faux", "test-value", req, res)
	if a.Error(err, "Expected error from failing store") {
		a.Contains(err.Error(), "session save failed", "Error should be propagated from store")
	}
}

// Test_GetAuthURL_PropagatesSessionErrors verifies that GetAuthURL returns
// errors from session operations, such as when securecookie fails due to
// missing hash key.
// See: https://github.com/markbates/goth/issues/549
func Test_GetAuthURL_PropagatesSessionErrors(t *testing.T) {
	a := assert.New(t)

	// Use a store that fails on save (simulating securecookie with no hash key)
	originalStore := Store
	Store = &failingStore{err: fmt.Errorf("securecookie: hash key is not set")}
	defer func() { Store = originalStore }()

	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth?provider=faux", nil)
	a.NoError(err)

	// GetAuthURL should propagate the session error
	_, err = GetAuthURL(res, req)
	if a.Error(err, "Expected error when session save fails") {
		a.Contains(err.Error(), "hash key is not set", "Original error should be propagated")
	}
}

// failingStore is a test store that always fails on Save
type failingStore struct {
	err error
}

func (f *failingStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.NewSession(f, name), nil
}

func (f *failingStore) New(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.NewSession(f, name), nil
}

func (f *failingStore) Save(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
	return f.err
}

// Test_CompleteUserAuth_SingleSetCookie verifies that CompleteUserAuth only
// produces a single Set-Cookie header (the logout cookie), not two headers
// where one is valid and one is expired.
// See: https://github.com/markbates/goth/issues/626
func Test_CompleteUserAuth_SingleSetCookie(t *testing.T) {
	a := assert.New(t)

	// Use a real cookie store to test Set-Cookie header behavior
	cookieStore := sessions.NewCookieStore([]byte("test-secret-key-32-bytes-long!!"))
	cookieStore.Options.MaxAge = 86400 * 30
	originalStore := Store
	Store = cookieStore
	defer func() { Store = originalStore }()

	// Create request with session containing auth data
	req, err := http.NewRequest("GET", "/auth/callback?provider=faux", nil)
	a.NoError(err)

	// Set up session with provider data (simulating after BeginAuth)
	sess := faux.Session{Name: "Homer Simpson", Email: "homer@example.com"}
	session, _ := Store.New(req, SessionName)
	session.Values["faux"] = gzipString(sess.Marshal())

	// Save session and get the cookie to include in request
	setupRes := httptest.NewRecorder()
	err = session.Save(req, setupRes)
	a.NoError(err)

	// Extract the session cookie from setup response
	cookies := setupRes.Result().Cookies()
	a.NotEmpty(cookies, "Expected session cookie to be set")

	// Create new request with the session cookie
	req, err = http.NewRequest("GET", "/auth/callback?provider=faux", nil)
	a.NoError(err)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	// Now call CompleteUserAuth
	res := httptest.NewRecorder()
	user, err := CompleteUserAuth(res, req)
	a.NoError(err)
	a.Equal("Homer Simpson", user.Name)

	// Count Set-Cookie headers - should be exactly 1 (the logout cookie)
	setCookieHeaders := res.Result().Header["Set-Cookie"]
	a.Len(setCookieHeaders, 1, "Expected exactly 1 Set-Cookie header, got %d: %v", len(setCookieHeaders), setCookieHeaders)

	// The single cookie should be the logout cookie (MaxAge=-1 or expires in past)
	if len(setCookieHeaders) == 1 {
		cookie := setCookieHeaders[0]
		// Logout sets MaxAge=-1 which results in immediate expiry
		a.Contains(cookie, "Max-Age=0", "Expected logout cookie with Max-Age=0")
	}
}

// Test_CompleteUserAuth_ParseFormError verifies that CompleteUserAuth returns
// a proper error when ParseForm fails on a POST request.
func Test_CompleteUserAuth_ParseFormError(t *testing.T) {
	a := assert.New(t)

	Store = NewProviderStore()

	// Override GetState to return empty without calling FormValue
	// (FormValue internally calls ParseForm, consuming the body before our test can)
	originalGetState := GetState
	GetState = func(req *http.Request) string { return "" }
	defer func() { GetState = originalGetState }()

	// Create a POST request with a body that will cause ParseForm to fail.
	req, err := http.NewRequest("POST", "/auth/callback", &errorReader{})
	a.NoError(err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Set provider via context so URL query params are empty
	// (this triggers the ParseForm code path)
	req = GetContextWithProvider(req, "faux")

	// Set up session with provider data but NO AccessToken
	// This causes FetchUser to fail, triggering the form parsing path
	// Note: Must use the request AFTER GetContextWithProvider since
	// ProviderStore keys by request pointer
	sess := faux.Session{ID: "test-id", Name: "Test User", Email: "test@example.com"}
	session, _ := Store.Get(req, SessionName)
	session.Values["faux"] = gzipString(sess.Marshal())

	res := httptest.NewRecorder()
	err = session.Save(req, res)
	a.NoError(err)

	// CompleteUserAuth should return an error from ParseForm
	// The errorReader body will cause ParseForm to fail
	_, err = CompleteUserAuth(res, req)
	if a.Error(err, "Expected error from ParseForm failure") {
		a.Contains(err.Error(), "failed to parse form", "Error should indicate form parsing failure")
	}
}

// errorReader is an io.Reader that always returns an error
type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("simulated read error")
}
