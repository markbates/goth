// Package lastfm implements the OAuth protocol for authenticating users through LastFM.
// This package can be used as a reference impleentation of an OAuth provider for Goth.
package lastfm

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

var (
	authURL         = "http://www.lastfm.com/api/auth"
	endpointProfile = "http://ws.audioscrobbler.com/2.0/"
)

// New creates a new LastFM provider, and sets up important connection details.
// You should always call `lastfm.New` to get a new Provider. Never try to craete
// one manullay.
func New(clientKey string, secret string, callbackURL string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "lastfm",
	}
	return p
}

// Provider is the implementation of `goth.Provider` for accessing LastFM
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	UserAgent    string
	HTTPClient   *http.Client
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

// Debug is a no-op for the lastfm package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks LastFm for an authentication end-point
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	urlParams := url.Values{}
	urlParams.Add("api_key", p.ClientKey)
	urlParams.Add("cb", p.CallbackURL)

	session := &Session{
		AuthURL: authURL + "?" + urlParams.Encode(),
	}

	return session, nil
}

// FetchUser will go to LastFM and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken: sess.AccessToken,
		Provider:    p.Name(),
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s has no user information available (yet)", p.providerName)
	}

	u := struct {
		XMLName    xml.Name `xml:"user"`
		ID         string   `xml:"id"`
		Name       string   `xml:"name"`
		RealName   string   `xml:"realname"`
		URL        string   `xml:"url"`
		Country    string   `xml:"country"`
		Age        string   `xml:"age"`
		Gender     string   `xml:"gender"`
		Subscriber string   `xml:"subscriber"`
		PlayCount  string   `xml:"playcount"`
		Playlists  string   `xml:"playlists"`
		Bootstrap  string   `xml:"bootstrap"`
		Registered struct {
			Unixtime string `xml:"unixtime,attr"`
			Time     string `xml:",chardata"`
		} `xml:"registered"`
		Images []struct {
			Size string `xml:"size,attr"`
			URL  string `xml:",chardata"`
		} `xml:"image"`
	}{}

	login := session.(*Session).Login
	err := p.request(false, map[string]string{"method": "user.getinfo", "user": login}, &u)

	if err == nil {
		user.Name = u.RealName
		user.NickName = u.Name
		user.AvatarURL = u.Images[3].URL
		user.UserID = u.ID
		user.Location = u.Country
	}

	return user, err
}

// GetSession token from LastFM
func (p *Provider) GetSession(token string) (map[string]string, error) {
	sess := struct {
		Name       string `xml:"name"`
		Key        string `xml:"key"`
		Subscriber bool   `xml:"subscriber"`
	}{}

	err := p.request(true, map[string]string{"method": "auth.getSession", "token": token}, &sess)
	return map[string]string{"login": sess.Name, "token": sess.Key}, err
}

func (p *Provider) request(sign bool, params map[string]string, result interface{}) error {
	urlParams := url.Values{}
	urlParams.Add("method", params["method"])

	params["api_key"] = p.ClientKey
	for k, v := range params {
		urlParams.Add(k, v)
	}

	if sign {
		urlParams.Add("api_sig", signRequest(p.Secret, params))
	}

	uri := endpointProfile + "?" + urlParams.Encode()

	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", p.UserAgent)

	res, err := p.Client().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode/100 == 5 { // only 5xx class errros
		err = errors.New(fmt.Errorf("Request error(%v) %v", res.StatusCode, res.Status).Error())
		return err
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	base := struct {
		XMLName xml.Name `xml:"lfm"`
		Status  string   `xml:"status,attr"`
		Inner   []byte   `xml:",innerxml"`
	}{}

	err = xml.Unmarshal(body, &base)
	if err != nil {
		return err
	}

	if base.Status != "ok" {
		errorDetail := struct {
			Code    int    `xml:"code,attr"`
			Message string `xml:",chardata"`
		}{}

		err = xml.Unmarshal(base.Inner, &errorDetail)
		if err != nil {
			return err
		}

		return errors.New(fmt.Errorf("Request Error(%v): %v", errorDetail.Code, errorDetail.Message).Error())
	}

	return xml.Unmarshal(base.Inner, result)
}

func signRequest(secret string, params map[string]string) string {
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sigPlain string
	for _, k := range keys {
		sigPlain += k + params[k]
	}
	sigPlain += secret

	hasher := md5.New()
	hasher.Write([]byte(sigPlain))
	return hex.EncodeToString(hasher.Sum(nil))
}

// RefreshToken refresh token is not provided by lastfm
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by lastfm")
}

// RefreshTokenAvailable refresh token is not provided by lastfm
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
