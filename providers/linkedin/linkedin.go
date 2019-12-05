// Package linkedin implements the OAuth2 protocol for authenticating users through Linkedin.
package linkedin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// more details about linkedin fields:
// User Profile and Email Address - https://docs.microsoft.com/en-gb/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin
// User Avatar - https://docs.microsoft.com/en-gb/linkedin/shared/references/v2/digital-media-asset

const (
	authURL  string = "https://www.linkedin.com/oauth/v2/authorization"
	tokenURL string = "https://www.linkedin.com/oauth/v2/accessToken"

	//userEndpoint requires scope "r_liteprofile"
	userEndpoint string = "//api.linkedin.com/v2/me?projection=(id,firstName,lastName,profilePicture(displayImage~:playableStreams))"
	//emailEndpoint requires scope "r_emailaddress"
	emailEndpoint string = "//api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))"
)

// New creates a new linkedin provider, and sets up important connection details.
// You should always call `linkedin.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "linkedin",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Linkedin.
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

// Client returns an HTTPClientWithFallback
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the linkedin package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Linkedin for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will go to Linkedin and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	user := goth.User{
		AccessToken: s.AccessToken,
		Provider:    p.Name(),
		ExpiresAt:   s.ExpiresAt,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	// create request for user r_liteprofile
	req, err := http.NewRequest("GET", "", nil)
	if err != nil {
		return user, err
	}

	// add url as opaque to avoid escaping of "("
	req.URL = &url.URL{
		Scheme: "https",
		Host:   "api.linkedin.com",
		Opaque: userEndpoint,
	}

	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
	resp, err := p.Client().Do(req)
	if err != nil {
		return user, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user profile", p.providerName, resp.StatusCode)
	}

	// read r_liteprofile information
	err = userFromReader(resp.Body, &user)
	if err != nil {
		return user, err
	}

	// create request for user r_emailaddress
	reqEmail, err := http.NewRequest("GET", "", nil)
	if err != nil {
		return user, err
	}

	// add url as opaque to avoid escaping of "("
	reqEmail.URL = &url.URL{
		Scheme: "https",
		Host:   "api.linkedin.com",
		Opaque: emailEndpoint,
	}

	reqEmail.Header.Set("Authorization", "Bearer "+s.AccessToken)
	respEmail, err := p.Client().Do(reqEmail)
	if err != nil {
		return user, err
	}
	defer respEmail.Body.Close()

	if respEmail.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user email", p.providerName, respEmail.StatusCode)
	}

	// read r_emailaddress information
	err = emailFromReader(respEmail.Body, &user)

	return user, err
}

func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		ID        string `json:"id"`
		FirstName struct {
			PreferredLocale struct {
				Country  string `json:"country"`
				Language string `json:"language"`
			} `json:"preferredLocale"`
			Localized map[string]string `json:"localized"`
		} `json:"firstName"`
		LastName struct {
			Localized       map[string]string
			PreferredLocale struct {
				Country  string `json:"country"`
				Language string `json:"language"`
			} `json:"preferredLocale"`
		} `json:"lastName"`
		ProfilePicture struct {
			DisplayImage struct {
				Elements []struct {
					AuthorizationMethod string `json:"authorizationMethod"`
					Identifiers         []struct {
						Identifier     string `json:"identifier"`
						IdentifierType string `json:"identifierType"`
					} `json:"identifiers"`
				} `json:"elements"`
			} `json:"displayImage~"`
		} `json:"profilePicture"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.FirstName = u.FirstName.Localized[u.FirstName.PreferredLocale.Language+"_"+u.FirstName.PreferredLocale.Country]
	user.LastName = u.LastName.Localized[u.LastName.PreferredLocale.Language+"_"+u.LastName.PreferredLocale.Country]
	user.Name = user.FirstName + " " + user.LastName
	user.NickName = user.FirstName
	user.UserID = u.ID

	avatarURL := ""
	// loop all displayimage elements
	for _, element := range u.ProfilePicture.DisplayImage.Elements {
		// only retrieve data where the authorization method allows public (unauthorized) access
		if element.AuthorizationMethod == "PUBLIC" {
			for _, identifier := range element.Identifiers {
				// check to ensure the identifer type is a url linking to the image
				if identifier.IdentifierType == "EXTERNAL_URL" {
					avatarURL = identifier.Identifier
					// we only need the first image url
					break
				}
			}
		}
		// if we have a valid image, exit the loop as we only support a single avatar image
		if len(avatarURL) > 0 {
			break
		}
	}

	user.AvatarURL = avatarURL

	return err
}

func emailFromReader(reader io.Reader, user *goth.User) error {
	e := struct {
		Elements []struct {
			Handle struct {
				EmailAddress string `json:"emailAddress"`
			} `json:"handle~"`
		} `json:"elements"`
	}{}

	err := json.NewDecoder(reader).Decode(&e)
	if err != nil {
		return err
	}

	if len(e.Elements) > 0 {
		user.Email = e.Elements[0].Handle.EmailAddress
	}

	if len(user.Email) == 0 {
		return errors.New("Unable to retrieve email address")
	}

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

	if len(scopes) == 0 {
		// add helper as new API requires the scope to be specified and these are the minimum to retrieve profile information and user's email address
		scopes = append(scopes, "r_liteprofile", "r_emailaddress")
	}

	for _, scope := range scopes {
		c.Scopes = append(c.Scopes, scope)
	}

	return c
}

//RefreshToken refresh token is not provided by linkedin
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by linkedin")
}

//RefreshTokenAvailable refresh token is not provided by linkedin
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
