package email

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/smtp"
	"net/url"
	"time"

	"github.com/Avyukth/goth"
	"golang.org/x/oauth2"
)

const (
	providerName = "email"
	tokenLength  = 32
)

// Provider is the implementation of `goth.Provider` for email authentication.
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	HTTPClient  *http.Client
	config      *Config
	name        string
}

type Config struct {
	Server                   SMTPServer
	From                     string
	MaxAge                   time.Duration
	SendVerificationRequest  func(params VerificationRequestParams) error
	GenerateVerificationToken func() (string, error)
	NormalizeIdentifier      func(identifier string) string
}

type SMTPServer struct {
	Host string
	Port int
	User string
	Pass string
}

type VerificationRequestParams struct {
	Identifier string
	URL        string
	Token      string
	Provider   *Provider
	Expires    time.Time
}

// New creates a new Email provider
func New(clientKey, secret, callbackURL string, config *Config) *Provider {
	p := &Provider{
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,
		name:        providerName,
		config:      config,
	}

	if p.config == nil {
		p.config = &Config{}
	}

	// Set defaults
	if p.config.Server.Host == "" {
		p.config.Server.Host = "localhost"
	}
	if p.config.Server.Port == 0 {
		p.config.Server.Port = 25
	}
	if p.config.From == "" {
		p.config.From = "pathshala.dev <no-reply@pathshala.dev>"
	}
	if p.config.MaxAge == 0 {
		p.config.MaxAge = 24 * time.Hour
	}
	if p.config.SendVerificationRequest == nil {
		p.config.SendVerificationRequest = p.DefaultSendVerificationRequest
	}
	if p.config.GenerateVerificationToken == nil {
		p.config.GenerateVerificationToken = p.DefaultGenerateVerificationToken
	}
	if p.config.NormalizeIdentifier == nil {
		p.config.NormalizeIdentifier = p.DefaultNormalizeIdentifier
	}

	return p
}

func (p *Provider) Name() string {
	return p.name
}

func (p *Provider) SetName(name string) {
	p.name = name
}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

func (p *Provider) Debug(debug bool) {}

func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.CallbackURL,
	}, nil
}

func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		Email:    sess.Email,
		Provider: p.Name(),
	}
	return user, nil
}

func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("refresh token is not available for email provider")
}

func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

func (p *Provider) SendVerificationRequest(email, callbackURL string) error {
	token, err := p.config.GenerateVerificationToken()
	if err != nil {
		return err
	}

	u, err := url.Parse(callbackURL)
	if err != nil {
		return err
	}

	q := u.Query()
	q.Set("token", token)
	q.Set("email", email)
	u.RawQuery = q.Encode()

	expires := time.Now().Add(p.config.MaxAge)

	params := VerificationRequestParams{
		Identifier: email,
		URL:        u.String(),
		Token:      token,
		Provider:   p,
		Expires:    expires,
	}

	return p.config.SendVerificationRequest(params)
}

func (p *Provider) DefaultSendVerificationRequest(params VerificationRequestParams) error {
	auth := smtp.PlainAuth("", p.config.Server.User, p.config.Server.Pass, p.config.Server.Host)

	to := []string{params.Identifier}
	msg := []byte(fmt.Sprintf("To: %s\r\n"+
		"Subject: Sign in to %s\r\n"+
		"\r\n"+
		"Click the link below to sign in:\r\n"+
		"%s\r\n", params.Identifier, params.URL, params.URL))

	err := smtp.SendMail(fmt.Sprintf("%s:%d", p.config.Server.Host, p.config.Server.Port), auth, p.config.From, to, msg)
	if err != nil {
		return err
	}

	return nil
}

func (p *Provider) DefaultGenerateVerificationToken() (string, error) {
	b := make([]byte, tokenLength)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (p *Provider) DefaultNormalizeIdentifier(identifier string) string {
	return identifier
}
