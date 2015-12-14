package gothic_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	. "github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/faux"
	"github.com/stretchr/testify/assert"
)

type ProviderStore struct {
	Store map[*http.Request]*sessions.Session
}

func NewProviderStore() *ProviderStore {
	return &ProviderStore{map[*http.Request]*sessions.Session{}}
}

func (p ProviderStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	s := p.Store[r]
	if s == nil {
		s, err := p.New(r, name)
		return s, err
	}
	return s, nil
}

func (p ProviderStore) New(r *http.Request, name string) (*sessions.Session, error) {
	s := sessions.NewSession(p, name)
	p.Store[r] = s
	return s, nil
}

func (p ProviderStore) Save(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
	p.Store[r] = s
	return nil
}

func init() {
	Store = sessions.NewFilesystemStore(os.TempDir(), []byte("goth-test"))
	goth.UseProviders(&faux.Provider{})
}

func Test_BeginAuthHandler(t *testing.T) {
	t.Parallel()

	a := assert.New(t)

	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth?provider=faux", nil)
	a.NoError(err)

	BeginAuthHandler(res, req)

	a.Equal(http.StatusTemporaryRedirect, res.Code)
	a.Contains(res.Body.String(), `<a href="http://example.com/auth/">Temporary Redirect</a>`)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()

	a := assert.New(t)

	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth?provider=faux", nil)
	a.NoError(err)

	url, err := GetAuthURL(res, req)

	a.NoError(err)

	a.Equal("http://example.com/auth/", url)
}

func Test_CompleteUserAuth(t *testing.T) {
	t.Parallel()

	a := assert.New(t)

	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth/callback?provider=faux", nil)
	a.NoError(err)

	sess := faux.Session{Name: "Homer Simpson", Email: "homer@example.com"}
	session, _ := Store.Get(req, SessionName)
	session.Values[SessionName] = sess.Marshal()
	err = session.Save(req, res)
	a.NoError(err)

	user, err := CompleteUserAuth(res, req)
	a.NoError(err)

	a.Equal(user.Name, "Homer Simpson")
	a.Equal(user.Email, "homer@example.com")
}

func Test_SetState(t *testing.T) {
	t.Parallel()

	a := assert.New(t)

	req, _ := http.NewRequest("GET", "/auth?state=state", nil)
	a.Equal(SetState(req), "state")
}

func Test_GetState(t *testing.T) {
	t.Parallel()

	a := assert.New(t)

	req, _ := http.NewRequest("GET", "/auth?state=state", nil)
	a.Equal(GetState(req), "state")
}
