package spalktestprovider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// Provider is used only for testing.
type Provider struct {
	HTTPClient   *http.Client
	providerName string
}

// Session is used only for testing.
type Session struct {
	ID          string
	Name        string
	Email       string
	AuthURL     string
	AccessToken string
}

// Name is used only for testing.
func (p *Provider) Name() string {
	return "spalktest"
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// BeginAuth is used only for testing.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	c := &oauth2.Config{
		Endpoint: oauth2.Endpoint{
			AuthURL: "http://example.com/auth",
		},
	}
	url := c.AuthCodeURL(state)
	return &Session{
		ID:      "id",
		AuthURL: url,
	}, nil
}

// FetchUser will hit a predefined URL and return whatever it gets back as a goth User
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	var user goth.User
	reqUrl := "http://example.com/auth"
	response, err := p.Client().Get(reqUrl)
	if err != nil {
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	bits, err := ioutil.ReadAll(response.Body)
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

func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		About     string `json:"about"`
		Name      string `json:"name"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Link      string `json:"link"`
		Picture   struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
		Location struct {
			Name string `json:"name"`
		} `json:"location"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.Name = u.Name
	user.FirstName = u.FirstName
	user.LastName = u.LastName
	user.NickName = u.Name
	user.Email = u.Email
	user.Description = u.About
	user.AvatarURL = u.Picture.Data.URL
	user.UserID = u.ID
	user.Location = u.Location.Name

	return err
}

// UnmarshalSession is used only for testing.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is used only for testing.
func (p *Provider) Debug(debug bool) {}

//RefreshTokenAvailable is used only for testing
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

//RefreshToken is used only for testing
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, nil
}

// Authorize is used only for testing.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	s.AccessToken = "access"
	return s.AccessToken, nil
}

// Marshal is used only for testing.
func (s *Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

// GetAuthURL is used only for testing.
func (s *Session) GetAuthURL() (string, error) {
	return s.AuthURL, nil
}
