package yammer

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/markbates/goth"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// Session stores data during the auth process with Yammer.
type Session struct {
	AuthURL     string
	AccessToken string
	userMap     map[string]interface{} //stores yammer user detail in map
}

var _ goth.Session = &Session{}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Yammer provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New("an AuthURL has not be set")
	}
	return s.AuthURL, nil
}

// Authorize the session with Yammer and return the access token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	v := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         CondVal(params.Get("code")),
		"redirect_uri": CondVal(p.config.RedirectURL),
		"scope":        CondVal(strings.Join(p.config.Scopes, " ")),
	}
	//Cant use standard auth2 implementation as yammer returns access_token as json rather than string
	//stand methods are throwing exception
	//token, err := p.config.Exchange(oauth2.NoContext, params.Get("code"))
	autData, err := retrieveAuthData(p.ClientKey, p.Secret, tokenURL, v)
	if err != nil {
		return "", err
	}
	token := autData["access_token"]["token"].(string)
	s.AccessToken = token
	s.userMap = autData["user"]
	return token, err
}

// Marshal the session into a string
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s Session) String() string {
	return s.Marshal()
}

//Custom implementation for yammer to get access token and user data
//Yammer provides user data along with access token, no separate api available
func retrieveAuthData(ClientID, ClientSecret, TokenURL string, v url.Values) (map[string]map[string]interface{}, error) {
	v.Set("client_id", ClientID)
	v.Set("client_secret", ClientSecret)
	req, err := http.NewRequest("POST", TokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	r, err := http.DefaultClient.Do(req)
	if err != nil {
		if r != nil {
			r.Body.Close()
		}
		return nil, err
	}
	defer r.Body.Close()
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v\nResponse: %s", r.Status, body)
	}

	var objmap map[string]map[string]interface{}

	err = json.Unmarshal(body, &objmap)

	if err != nil {
		return nil, err
	}
	return objmap, nil
}

//CondVal convert string in string array
func CondVal(v string) []string {
	if v == "" {
		return nil
	}
	return []string{v}
}

// UnmarshalSession wil unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(s)
	return s, err
}
