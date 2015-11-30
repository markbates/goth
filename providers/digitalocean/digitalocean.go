package digitalocean

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/smagic39/goth"
	"golang.org/x/oauth2"
)

const (
	authURL         string = "https://cloud.digitalocean.com/v1/oauth/authorize"
	tokenURL        string = "https://cloud.digitalocean.com/v1/oauth/token"
	endpointProfile string = "https://api.digitalocean.com/v2/account"
)

// New creates a new DigitalOcean provider, and sets up important connection details.
// You should always call `digitalocean.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,
	}

	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing DigitalOcean.
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	config      *oauth2.Config
}

var _ goth.Provider = &Provider{}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return "digitalocean"
}

// Debug is a no-op for the digitalocean package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Github for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will go to DigitalOcean and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken: sess.AccessToken,
		Provider:    p.Name(),
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", endpointProfile, nil)
	if err != nil {
		return user, err
	}

	req.Header.Set("Authorization", "Bearer "+sess.AccessToken)

	resp, err := client.Do(req)
	if err != nil {
		return user, err
	}
	defer resp.Body.Close()

	bits, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return user, err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)
	return user, err
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}

func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		Account struct {
			DropletLimit  int    `json:"droplet_limit"`
			Email         string `json:"email"`
			UUID          string `json:"uuid"`
			EmailVerified bool   `json:"email_verified"`
			Status        string `json:"status"`
			StatusMessage string `json:"status_message"`
		} `json:"account"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.Email = u.Account.Email
	user.UserID = u.Account.UUID

	return err
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}

	for _, scope := range scopes {
		c.Scopes = append(c.Scopes, scope)
	}

	return c
}
