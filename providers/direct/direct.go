package direct

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

type AccessTokenGenerator func() string

type UserFetcher func(email string) (goth.User, error)

type CredChecker func(email, password string) error

type Provider struct {
	name    string
	debug   bool
	AuthURL string
	UserFetcher
	CredChecker
	AccessTokenGenerator
}

func DefaultTokenGenerator() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func New(authUrl string, userFetcher UserFetcher, credChecker CredChecker) *Provider {
	return &Provider{
		name:                 "direct",
		AccessTokenGenerator: DefaultTokenGenerator,
		AuthURL:              authUrl,
		UserFetcher:          userFetcher,
		CredChecker:          credChecker,
	}
}

func (p *Provider) Name() string {
	return p.name
}

func (p *Provider) SetName(name string) {
	p.name = name
}

func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.AuthURL,
	}, nil
}

func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}

func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	directSession := session.(*Session)

	if directSession.Email == "" {
		// data is not yet retrieved since accessToken is still empty
		return goth.User{}, fmt.Errorf("%s cannot get user information without accessToken", p.name)
	}

	user, err := p.UserFetcher(directSession.Email)
	if err != nil {
		return goth.User{}, err
	}

	return user, nil
}

func (p *Provider) Debug(debug bool) {
	p.debug = debug
}

func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("refreshToken not supported for the password grant")
}

func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

func (p *Provider) IssueSession(email, password string) (goth.Session, error) {
	if p.CredChecker(email, password) != nil {
		return nil, errors.New("invalid username or password")
	}

	return &Session{
		Email: email,
	}, nil
}
