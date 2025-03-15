package cognito

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// Provider is the implementation of `goth.Provider` for accessing AWS Cognito.
// New takes 3 parameters all from the Cognito console:
// - The client ID
// - The client secret
// - The base URL for your service, either a custom domain or cognito pool based URL
// You need to ensure that the source login URL is whitelisted as a login page in the client configuration in the cognito console.
// GOTH does not provide a full token logout, to do that you need to do it in your code.
// If you do not perform a full logout their existing token will be used on a login and the user won't be prompted to login until after expiry.
// To perform a logout
// - Destroy your session (or however else you handle the logout internally)
// - redirect to https://CUSTOM_DOMAIN.auth.us-east-1.amazoncognito.com/logout?client_id=clinet_id&logout_uri=http://localhost:8080/
//        (or whatever your login/start page is).
// - Note that this page needs to be white-labeled as a logout page in the cognito console as well.

// This is based upon the implementation for okta

type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	issuerURL    string
	profileURL   string
}

// New creates a new AWS Cognito provider and sets up important connection details.
// You should always call `cognito.New` to get a new provider.  Never try to
// create one manually.
func New(clientID, secret, baseUrl, callbackURL string, scopes ...string) *Provider {
	issuerURL := baseUrl + "/oauth2/default"
	authURL := baseUrl + "/oauth2/authorize"
	tokenURL := baseUrl + "/oauth2/token"
	profileURL := baseUrl + "/oauth2/userInfo"
	return NewCustomisedURL(clientID, secret, callbackURL, authURL, tokenURL, issuerURL, profileURL, scopes...)
}

// NewCustomisedURL is similar to New(...) but can be used to set custom URLs to connect to
func NewCustomisedURL(clientID, secret, callbackURL, authURL, tokenURL, issuerURL, profileURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientID,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "cognito",
		issuerURL:    issuerURL,
		profileURL:   profileURL,
	}
	p.config = newConfig(p, authURL, tokenURL, scopes)
	return p
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

// Debug is a no-op for the aws package.
func (p *Provider) Debug(debug bool) {
	if debug {
		fmt.Println("WARNING: Debug request for goth/providers/cognito but no debug is available")
	}
}

// BeginAuth asks AWS for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to aws and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
		UserID:       sess.UserID,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", p.profileURL, nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", "Bearer "+sess.AccessToken)
	response, err := p.Client().Do(req)
	if err != nil {
		if response != nil {
			_ = response.Body.Close()
		}
		return user, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

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

func newConfig(provider *Provider, authURL, tokenURL string, scopes []string) *oauth2.Config {
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

	if len(scopes) > 0 {
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	}
	return c
}

// userFromReader
// These are the standard cognito attributes
// from: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html
// all attributes are optional
// it is possible for there to be custom attributes in cognito, but they don't seem to be passed as in the claims
// all the standard claims are mapped into the raw data
func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		ID            string `json:"sub"`
		Address       string `json:"address"`
		Birthdate     string `json:"birthdate"`
		Email         string `json:"email"`
		EmailVerified string `json:"email_verified"`
		FirstName     string `json:"given_name"`
		LastName      string `json:"family_name"`
		MiddleName    string `json:"middle_name"`
		Name          string `json:"name"`
		NickName      string `json:"nickname"`
		Locale        string `json:"locale"`
		PhoneNumber   string `json:"phone_number"`
		PictureURL    string `json:"picture"`
		ProfileURL    string `json:"profile"`
		Username      string `json:"preferred_username"`
		UpdatedAt     string `json:"updated_at"`
		WebSite       string `json:"website"`
		Zoneinfo      string `json:"zoneinfo"`
	}{}

	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}

	// Ensure all standard claims are in the raw data
	rd := make(map[string]interface{})
	rd["Address"] = u.Address
	rd["Birthdate"] = u.Birthdate
	rd["Locale"] = u.Locale
	rd["MiddleName"] = u.MiddleName
	rd["PhoneNumber"] = u.PhoneNumber
	rd["PictureURL"] = u.PictureURL
	rd["ProfileURL"] = u.ProfileURL
	rd["UpdatedAt"] = u.UpdatedAt
	rd["Username"] = u.Username
	rd["WebSite"] = u.WebSite
	rd["EmailVerified"] = u.EmailVerified

	user.UserID = u.ID
	user.Email = u.Email
	user.Name = u.Name
	user.NickName = u.NickName
	user.FirstName = u.FirstName
	user.LastName = u.LastName
	user.AvatarURL = u.PictureURL
	user.RawData = rd

	return nil
}

// RefreshTokenAvailable refresh token is provided by auth provider or not
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
