package naver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL    = "https://nid.naver.com/oauth2.0/authorize"
	tokenURL   = "https://nid.naver.com/oauth2.0/token"
	profileURL = "https://openapi.naver.com/v1/nid/me"
)

// Provider is the implementation of `goth.Provider` for accessing naver.com.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
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

// FetchUser will go to navercom and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}

	if user.AccessToken == "" {
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	request, err := http.NewRequest("GET", profileURL, nil)
	if err != nil {
		return user, err
	}

	request.Header.Set("Authorization", "Bearer "+sess.AccessToken)
	response, err := p.Client().Do(request)
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

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)
	return user, err
}

// Debug is a no-op for the naver package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks naver.com for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// RefreshTokenAvailable refresh token is provided by naver
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}

// New creates a New provider and sets up important connection details.
// You should always call `naver.New` to get a new Provider. Never try to craete
// one manually.
// Currently Naver  only supports pre-defined scopes.
// You should visit Naver Developer page in order to define your application's oauth scope.
func New(clientKey, secret, callbackURL string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "naver",
	}
	p.config = newConfig(p)
	return p
}

func newConfig(p *Provider) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     p.ClientKey,
		ClientSecret: p.Secret,
		RedirectURL:  p.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}
	return c
}

func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		Response struct {
			ID           string
			Nickname     string
			Name         string
			Email        string
			Gender       string
			Age          string
			Birthday     string
			ProfileImage string `json:"profile_image"`
		}
	}{}

	if err := json.NewDecoder(reader).Decode(&u); err != nil {
		return err
	}
	r := u.Response
	user.Email = r.Email
	user.Name = r.Name
	user.NickName = r.Nickname
	user.AvatarURL = r.ProfileImage
	user.UserID = r.ID
	user.Description = fmt.Sprintf(`{"gender":"%s","age":"%s","birthday":"%s"}`, r.Gender, r.Age, r.Birthday)

	return nil
}
