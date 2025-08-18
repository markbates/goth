package quickbooks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authEndpoint       = "https://appcenter.intuit.com/connect/oauth2"
	tokenEndpoint      = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
	userInfoURL        = "https://accounts.platform.intuit.com/v1/openid_connect/userinfo"
	sandboxUserInfoURL = "https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo"

	ScopeAccounting = "com.intuit.quickbooks.accounting"
	ScopePayments   = "com.intuit.quickbooks.payments"
	ScopeOpenId     = "openid"
	ScopeEmail      = "email"
	ScopeProfile    = "profile"
	ScopePhone      = "phone"
	ScopeAddress    = "address"
)

type Provider struct {
	providerName string
	clientId     string
	secret       string
	redirectURL  string
	config       *oauth2.Config
	httpClient   *http.Client
	userInfoURL  string
}

func New(clientId, secret, redirectURL string, isSandbox bool, scopes ...string) *Provider {
	p := &Provider{
		clientId:     clientId,
		secret:       secret,
		redirectURL:  redirectURL,
		providerName: "quickbooks",
		userInfoURL:  userInfoURL,
	}
	if isSandbox {
		p.userInfoURL = sandboxUserInfoURL
	}
	p.configure(scopes)
	return p
}

func (p Provider) Name() string {
	return p.providerName
}

func (p *Provider) SetName(name string) {
	p.providerName = name
}

func (p Provider) ClientId() string {
	return p.clientId
}

func (p Provider) Secret() string {
	return p.secret
}

func (p Provider) RedirectURL() string {
	return p.redirectURL
}

func (p Provider) BeginAuth(state string) (goth.Session, error) {
	authURL := p.config.AuthCodeURL(state)
	return &Session{
		AuthURL: authURL,
	}, nil
}

func (Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(s)
	return s, err
}

func (p Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	user := goth.User{
		Provider: p.Name(),
	}

	if s.AccessToken == "" {
		return goth.User{}, fmt.Errorf("no access token obtained for session with provider %s", p.Name())
	}

	req, err := http.NewRequest("GET", p.userInfoURL, nil)
	if err != nil {
		return goth.User{}, err
	}
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)

	resp, err := p.Client().Do(req)
	if err != nil {
		return goth.User{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("failed to get user info: %d", resp.StatusCode)
	}

	bits, err := io.ReadAll(resp.Body)
	if err != nil {
		return user, err
	}

	u := struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
	}{}

	if err := json.NewDecoder(bytes.NewReader(bits)).Decode(&u); err != nil {
		return user, err
	}

	user.UserID = u.Sub
	user.Email = u.Email
	user.Name = u.Name
	user.FirstName = u.GivenName
	user.LastName = u.FamilyName
	user.AccessToken = s.AccessToken
	user.RefreshToken = s.RefreshToken
	user.ExpiresAt = s.ExpiresAt

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	return user, err
}

func (Provider) Debug(bool) {}

func (p Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.httpClient)
}

func (p Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}

func (Provider) RefreshTokenAvailable() bool {
	return true
}

func (p *Provider) configure(scopes []string) {
	c := &oauth2.Config{
		ClientID:     p.clientId,
		ClientSecret: p.secret,
		RedirectURL:  p.redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authEndpoint,
			TokenURL: tokenEndpoint,
		},
		Scopes: make([]string, 0, len(scopes)),
	}

	c.Scopes = append(c.Scopes, scopes...)
	p.config = c
}
