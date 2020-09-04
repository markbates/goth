package reddit

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var Endpoint = oauth2.Endpoint{
	AuthURL:   "https://www.reddit.com/api/v1/authorize?duration=permanent",
	TokenURL:  "https://www.reddit.com/api/v1/access_token",
	AuthStyle: oauth2.AuthStyleInHeader,
}

// Session stores data during the auth process with Google.
type Session struct {
	AuthURL      string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*redditProvider)
	token, err := p.config.Exchange(goth.ContextForClient(p.Client()), params.Get("code"))
	if err != nil {
		return "", err
	}

	if !token.Valid() {
		return "", errors.New("Invalid token received from provider")
	}

	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
	s.ExpiresAt = token.Expiry
	return token.AccessToken, err
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Google provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}


// New creates a new Reddit provider, and sets up important connection details.
// You should always call `redditProvider.New` to get a new Provider. Never try to create
// one manually.
// https://github.com/reddit-archive/reddit/wiki/oauth2

type redditProvider struct {
	name string
	ClientKey       string
	Secret          string
	CallbackURL     string
	HTTPClient      *http.Client
	config          *oauth2.Config
	authCodeOptions []oauth2.AuthCodeOption
}

func newConfig(provider *redditProvider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint:     Endpoint,
		Scopes:       []string{},
	}

	if len(scopes) > 0 {
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	} else {
		c.Scopes = []string{"identity"}
	}
	return c
}

func (r *redditProvider) Name() string {
	return r.name
}

func (r *redditProvider) SetName(name string) {
	r.name = name
}

func (r *redditProvider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(r.HTTPClient)
}

func (r *redditProvider) BeginAuth(state string) (goth.Session, error) {
	url := r.config.AuthCodeURL(state, r.authCodeOptions...)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

func (r *redditProvider) UnmarshalSession(s string) (goth.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(s)).Decode(sess)
	return sess, err
}

func (r *redditProvider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     r.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}

	if user.AccessToken == "" {
		// Data is not yet retrieved, since accessToken is still empty.
		return user, fmt.Errorf("%s cannot get user information without accessToken", r.name)
	}
	req, _ := http.NewRequest("GET","https://oauth.reddit.com/api/v1/me", nil)
	req.Header.Set("Authorization", "bearer " + user.AccessToken)
	resp, err := r.Client().Do(req)
	if err != nil {
		return user, err
	}
	defer resp.Body.Close()
	b , _ := ioutil.ReadAll(resp.Body)
	var u struct{
		Name string `json:"name"`
	}
	json.Unmarshal(b, &u)
	user.Name = u.Name
	return user, nil
}

func (r *redditProvider) Debug(b bool) {
	return
}

func (r *redditProvider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := r.config.TokenSource(goth.ContextForClient(r.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}

func (r *redditProvider) RefreshTokenAvailable() bool {
	return false
}

type transport struct {
	http.RoundTripper
	useragent string
}


func (t *transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	req.Header.Set("User-Agent", t.useragent)
	return t.RoundTripper.RoundTrip(req)
}


func New(clientKey, secret, callbackURL string, scopes ...string) goth.Provider {
	httpClient := http.DefaultClient
	httpClient.Transport = &transport{
		RoundTripper: http.DefaultTransport,
		// TODO: You may want to replace this with your own useragent,
		// This is a workaround for rate limit reddit has for particular user agents.
		useragent: "Geddit Reddit Bot https://github.com/vageesha-br/goth",
	}
	p := &redditProvider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		name: "reddit",
		HTTPClient: httpClient,
	}
	p.config = newConfig(p, scopes)
	return  p
}