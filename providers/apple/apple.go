// Package `apple` implements the OAuth2 protocol for authenticating users through Apple.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package apple

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authEndpoint   = "https://appleid.apple.com/auth/authorize"
	tokenEndpoint  = "https://appleid.apple.com/auth/token"
	revokeEndpoint = "https://appleid.apple.com/auth/revoke"

	ScopeEmail = "email"
	ScopeName  = "name"

	AppleAudOrIss = "https://appleid.apple.com"
)

type Provider struct {
	providerName         string
	clientId             string
	secret               string
	redirectURL          string
	config               *oauth2.Config
	httpClient           *http.Client
	formPostResponseMode bool
	timeNowFn            func() time.Time
}

func New(clientId, secret, redirectURL string, httpClient *http.Client, scopes ...string) *Provider {
	p := &Provider{
		clientId:     clientId,
		secret:       secret,
		redirectURL:  redirectURL,
		providerName: "apple",
	}
	p.configure(scopes)
	p.httpClient = httpClient
	return p
}

func (p *Provider) Name() string {
	return p.providerName
}

func (p *Provider) SetName(name string) {
	p.providerName = name
}

func (p *Provider) ClientId() string {
	return p.clientId
}

type SecretParams struct {
	PKCS8PrivateKey, TeamId, KeyId, ClientId string
	Iat, Exp                                 int
}

func MakeSecret(sp SecretParams) (*string, error) {
	block, rest := pem.Decode([]byte(strings.TrimSpace(sp.PKCS8PrivateKey)))
	if block == nil || len(rest) > 0 {
		return nil, errors.New("invalid private key")
	}
	pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": sp.TeamId,
		"iat": sp.Iat,
		"exp": sp.Exp,
		"aud": AppleAudOrIss,
		"sub": sp.ClientId,
	})
	token.Header["kid"] = sp.KeyId
	ss, err := token.SignedString(pk)
	return &ss, err
}

func (p *Provider) Secret() string {
	return p.secret
}

func (p *Provider) RedirectURL() string {
	return p.redirectURL
}

func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	opts := make([]oauth2.AuthCodeOption, 0, 1)
	if p.formPostResponseMode {
		opts = append(opts, oauth2.SetAuthURLParam("response_mode", "form_post"))
	}
	authURL := p.config.AuthCodeURL(state, opts...)
	if authURL != "" {
		if u, err := url.Parse(authURL); err == nil {
			// Apple requires spaces to be encoded as %20 instead of +
			u.RawQuery = strings.ReplaceAll(u.RawQuery, "+", "%20")
			authURL = u.String()
		}
	}
	return &Session{
		AuthURL: authURL,
	}, nil
}

func (Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(s)
	return s, err
}

// Apple doesn't seem to provide a user profile endpoint like all the other providers do.
// Therefore this will return a User with the unique identifier obtained through authorization
// as the only identifying attribute.
// A full name and email can be obtained from the form post response (parameter 'user')
// to the redirect page following authentication, if the name and email scopes are requested.
// Additionally, if the response type is form_post and the email scope is requested, the email
// will be encoded into the ID token in the email claim.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	if s.AccessToken == "" {
		return goth.User{}, fmt.Errorf("no access token obtained for session with provider %s", p.Name())
	}

	raw_data := make(map[string]interface{})

	raw_data["access_token"] = s.AccessToken
	raw_data["refresh_token"] = s.RefreshToken
	raw_data["expires_at"] = s.ExpiresAt
	raw_data["is_private_email"] = s.ID.IsPrivateEmail
	raw_data["email_verified"] = s.ID.EmailVerified
	raw_data["sub"] = s.ID.Sub
	raw_data["email"] = s.ID.Email

	return goth.User{
		Provider:     p.Name(),
		UserID:       s.ID.Sub,
		Email:        s.ID.Email,
		AccessToken:  s.AccessToken,
		RefreshToken: s.RefreshToken,
		ExpiresAt:    s.ExpiresAt,
		RawData:      raw_data,
	}, nil
}

// Debug is a no-op for the apple package.
func (Provider) Debug(bool) {}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.httpClient)
}

func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
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

	for _, scope := range scopes {
		c.Scopes = append(c.Scopes, scope)
		if scope == "name" || scope == "email" {
			p.formPostResponseMode = true
		}
	}

	p.config = c
}

func (p *Provider) RevokeToken(token string) error {
	target_url := "https://appleid.apple.com/auth/revoke"
	method := "POST"

	type RevokePayload struct {
		ClientId     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Token        string `json:"token"`
	}

	payload := &RevokePayload{
		ClientId:     p.clientId,
		ClientSecret: p.secret,
		Token:        token,
	}

	// Make a x-www-form-urlencoded POST request
	body := url.Values{}
	body.Set("client_id", payload.ClientId)
	body.Set("client_secret", payload.ClientSecret)
	body.Set("token", payload.Token)

	req, err := http.NewRequest(method, target_url, strings.NewReader(body.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.Client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revoke token request failed with status code: %d", resp.StatusCode)
	}

	return nil
}

func (p *Provider) FetchUserWithToken(token string) (goth.User, error) {
	//TODO:
	return goth.User{}, errors.New("not implemented")
}
