// Package fitbit implements the OAuth protocol for authenticating users through Fitbit.
// This package can be used as a reference implementation of an OAuth provider for Goth.
package fitbit

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"fmt"
)

const (
	authURL         string = "https://www.fitbit.com/oauth2/authorize"
	tokenURL        string = "https://api.fitbit.com/oauth2/token"
	endpointProfile string = "https://api.fitbit.com/1/user/-/profile.json" // '-' for logged in user
)

const (
	// ScopeActivity includes activity data and exercise log related features, such as steps, distance, calories burned, and active minutes
	ScopeActivity = "activity"
	// ScopeHeartRate includes the continuous heart rate data and related analysis
	ScopeHeartRate = "heartrate"
	// ScopeLocation includes the GPS and other location data
	ScopeLocation = "location"
	// ScopeNutrition includes calorie consumption and nutrition related features, such as food/water logging, goals, and plans
	ScopeNutrition = "nutrition"
	// ScopeProfile is the basic user information
	ScopeProfile = "profile"
	// ScopeSettings includes user account and device settings, such as alarms
	ScopeSettings = "settings"
	// ScopeSleep includes sleep logs and related sleep analysis
	ScopeSleep = "sleep"
	// ScopeSocial includes friend-related features, such as friend list, invitations, and leaderboard
	ScopeSocial = "social"
	// ScopeWeight includes weight and related information, such as body mass index, body fat percentage, and goals
	ScopeWeight = "weight"
)

// New creates a new Fitbit provider, and sets up important connection details.
// You should always call `fitbit.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:           clientKey,
		Secret:              secret,
		CallbackURL:         callbackURL,
		providerName:        "fitbit",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Fitbit.
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

// Debug is a no-op for the fitbit package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Fitbit for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will go to Fitbit and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	user := goth.User{
		AccessToken:  s.AccessToken,
		Provider:     p.Name(),
		RefreshToken: s.RefreshToken,
		ExpiresAt:    s.ExpiresAt,
		UserID:       s.UserID,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", endpointProfile, nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
	resp, err := p.Client().Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return user, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, resp.StatusCode)
	}

	//err = userFromReader(io.TeeReader(resp.Body, os.Stdout), &user)
	err = userFromReader(resp.Body, &user)
	return user, err
}

func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		User struct {
			Avatar      string `json:"avatar"`
			Country     string `json:"country"`
			FullName    string `json:"fullName"`
			DisplayName string `json:"displayName"`
		} `json:"user"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.Location = u.User.Country
	user.Name = u.User.FullName
	user.NickName = u.User.DisplayName
	user.AvatarURL = u.User.Avatar

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
		Scopes: []string{
			ScopeProfile,
		},
	}

	defaultScopes := map[string]struct{}{
		ScopeProfile: {},
	}

	for _, scope := range scopes {
		if _, exists := defaultScopes[scope]; !exists {
			c.Scopes = append(c.Scopes, scope)
		}
	}

	return c
}

//RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(oauth2.NoContext, token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}

//RefreshTokenAvailable refresh token is not provided by fitbit
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}
