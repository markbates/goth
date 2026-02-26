package twitterv2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

var (
	AuthURL         = "https://twitter.com/i/oauth2/authorize"
	TokenURL        = "https://api.twitter.com/2/oauth2/token"
	endpointProfile = "https://api.twitter.com/2/users/me"
)

// New creates a new Twitter provider, and sets up important connection details.
// You should always call `twitter.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "twitterv2",
	}
	p.config = newConfig(p, []string{"users.read", "tweet.read", "offline.access"})
	return p
}

// NewAuthenticate is the same as New for OAuth 2.0.
// Kept for backward compatibility.
func NewAuthenticate(clientKey, secret, callbackURL string) *Provider {
	return New(clientKey, secret, callbackURL)
}

// NewCustomisedURL is similar to New(...) but can be used to set custom URLs to connect to
func NewCustomisedURL(clientKey, secret, callbackURL, authURL, tokenURL, profileURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "twitterv2",
	}
	AuthURL = authURL
	TokenURL = tokenURL
	endpointProfile = profileURL
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Twitter.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	debug        bool
	config       *oauth2.Config
	providerName string
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug sets the logging of the OAuth client to verbose.
func (p *Provider) Debug(debug bool) {
	p.debug = debug
}

// BeginAuth asks Twitter for an authentication end-point and a request token for a session.
// Twitter uses PKCE for OAuth 2.0.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	verifier := oauth2.GenerateVerifier()

	url := p.config.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(verifier),
	)
	session := &Session{
		AuthURL:      url,
		CodeVerifier: verifier,
	}
	return session, nil
}

// FetchUser will go to Twitter and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		Provider:     p.Name(),
		AccessToken:  sess.AccessToken,
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}

	if sess.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", endpointProfile, nil)
	if err != nil {
		return user, err
	}

	q := req.URL.Query()
	q.Add("user.fields", "id,name,username,description,profile_image_url,location")
	req.URL.RawQuery = q.Encode()

	req.Header.Add("Authorization", "Bearer "+sess.AccessToken)
	response, err := p.Client().Do(req)
	if err != nil {
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	bits, err := io.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	userInfo := struct {
		Data map[string]interface{} `json:"data"`
	}{}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&userInfo)
	if err != nil {
		return user, err
	}

	user.RawData = userInfo.Data
	if user.RawData["name"] != nil {
		user.Name = user.RawData["name"].(string)
	}
	if user.RawData["username"] != nil {
		user.NickName = user.RawData["username"].(string)
	}
	if user.RawData["description"] != nil {
		user.Description = user.RawData["description"].(string)
	}
	if user.RawData["profile_image_url"] != nil {
		user.AvatarURL = user.RawData["profile_image_url"].(string)
	}
	if user.RawData["id"] != nil {
		user.UserID = user.RawData["id"].(string)
	}
	if user.RawData["location"] != nil {
		user.Location = user.RawData["location"].(string)
	}

	return user, err
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  AuthURL,
			TokenURL: TokenURL,
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		Scopes: scopes,
	}

	return c
}

// RefreshTokenAvailable refresh token is provided by twitter
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// RefreshToken get a new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}
