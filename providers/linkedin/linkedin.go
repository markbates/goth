// Package linkedin implements the OAuth2 protocol for authenticating users through LinkedIn.
package linkedin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"net/url"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// More details about LinkedIn fields:
// https://developer.linkedin.com/documents/profile-fields
const (
	authURL  string = "https://www.linkedin.com/uas/oauth2/authorization"
	tokenURL string = "https://www.linkedin.com/uas/oauth2/accessToken"

	// userEndpoint requires scopes "r_basicprofile", "r_emailaddress". You must set the scopes when you register your application with LinkedIn.
	userEndpoint string = "//api.linkedin.com/v1/people/~:(id,first-name,last-name,headline,location:(name),picture-url,email-address)"
)

// New creates a new linkedin provider, and sets up important connection
// details. You should always call `linkedin.New` to get a new Provider.
// Never try to create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Linkedin.
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	config      *oauth2.Config
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return "linkedin"
}

// Debug is a no-op for the linkedin package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Linkedin for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	s := &Session{
		AuthURL: url,
	}
	fmt.Println("The URL: ", url)
	return s, nil
}

// FetchUser will go to Linkedin and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	user := goth.User{
		AccessToken: s.AccessToken,
		Provider:    p.Name(),
	}

	req, err := http.NewRequest("GET", "", nil)
	if err != nil {
		return user, err
	}

	// Add url as opaque to avoid escaping of "("
	req.URL = &url.URL{
		Scheme: "https",
		Host:   "api.linkedin.com",
		Opaque: userEndpoint,
	}

	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
	// Tell LinkedIn to respond with JSON for our request
	req.Header.Add("x-li-format", "json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return user, err
	}
	defer resp.Body.Close()
	err = userFromReader(resp.Body, &user)
	return user, err
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := Session{}
	err := json.Unmarshal([]byte(data), &s)
	return &s, err
}

func userFromReader(reader io.Reader, user *goth.User) error {

	u := struct {
		ID         string `json:"id"`
		Email      string `json:"emailAddress"`
		FirstName  string `json:"firstName"`
		LastName   string `json:"lastName"`
		Headline   string `json:"headline"`
		PictureURL string `json:"pictureUrl"`
		Location   struct {
			Name string `json:"name"`
		} `json:"location"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.Name = u.FirstName + " " + u.LastName
	user.NickName = u.FirstName
	user.Email = u.Email
	user.Description = u.Headline
	user.AvatarURL = u.PictureURL
	user.UserID = u.ID
	user.Location = u.Location.Name

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
