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

type FetchUserByToken func(token string) (goth.User, error)

type CredChecker func(email, password string) error

type DirectProvider struct {
	name    string
	debug   bool
	AuthURL string
	FetchUserByToken
	CredChecker
	AccessTokenGenerator
}

func DefaultTokenGenerator() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func New(authUrl string) *DirectProvider {
	return &DirectProvider{
		name:                 "direct",
		AccessTokenGenerator: DefaultTokenGenerator,
		AuthURL:              authUrl,
	}
}

func (p *DirectProvider) Name() string {
	return p.name
}

func (p *DirectProvider) SetName(name string) {
	p.name = name
}

func (p *DirectProvider) BeginAuth(state string) (goth.Session, error) {
	return &DirectSession{
		AuthURL: p.AuthURL,
	}, nil
}

func (p *DirectProvider) UnmarshalSession(data string) (goth.Session, error) {
	sess := &DirectSession{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}

func (p *DirectProvider) FetchUser(session goth.Session) (goth.User, error) {
	directSession := session.(*DirectSession)

	if directSession.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return goth.User{}, fmt.Errorf("%s cannot get user information without accessToken", p.name)
	}

	user, err := p.FetchUserByToken(directSession.AccessToken)
	if err != nil {
		return goth.User{}, err
	}

	return user, nil
}

func (p *DirectProvider) Debug(debug bool) {
	p.debug = debug
}

func (p *DirectProvider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("refreshToken not supported for the password grant")
}

func (p *DirectProvider) RefreshTokenAvailable() bool {
	return false
}

func (p *DirectProvider) IssueSession(email, password string) (goth.Session, error) {
	if p.CredChecker(email, password) != nil {
		return nil, errors.New("invalid username or password")
	}

	accessToken := p.AccessTokenGenerator()
	return &DirectSession{
		AccessToken: accessToken,
		Email:       email,
	}, nil
}
