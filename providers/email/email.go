// email.go
package email

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/smtp"
	"time"

	"github.com/Avyukth/goth"
	"golang.org/x/oauth2"
)

const (
    providerName = "email"
    tokenLength  = 32
    tokenExpiry  = 24 * time.Hour
)

// Provider is the implementation of `goth.Provider` for email authentication.
type Provider struct {
    CallbackURL  string
    SMTPServer   string
    SMTPPort     string
    SMTPUsername string
    SMTPPassword string
    FromEmail    string
    providerName string
    debug        bool
}

// New creates a new Email provider
func New(callbackURL, smtpServer, smtpPort, smtpUsername, smtpPassword, fromEmail string) *Provider {
    return &Provider{
        CallbackURL:  callbackURL,
        SMTPServer:   smtpServer,
        SMTPPort:     smtpPort,
        SMTPUsername: smtpUsername,
        SMTPPassword: smtpPassword,
        FromEmail:    fromEmail,
        providerName: providerName,
    }
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
    return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
    p.providerName = name
}

// Debug sets the logging of debug messages from the OAuth2 Client
func (p *Provider) Debug(debug bool) {
    p.debug = debug
}

// BeginAuth is not used for email authentication
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
    return &Session{}, nil
}

// FetchUser will go to the email provider and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
    sess := session.(*Session)
    user := goth.User{
        Email:    sess.Email,
        Provider: p.Name(),
    }
    return user, nil
}

// SendVerificationEmail sends a verification email to the user
func (p *Provider) SendVerificationEmail(email string) error {
    token, err := generateToken()
    if err != nil {
        return err
    }

    verificationURL := fmt.Sprintf("%s?token=%s&email=%s", p.CallbackURL, token, email)
    
    subject := "Sign in to your account"
    body := fmt.Sprintf("Click the following link to sign in: %s", verificationURL)

    err = p.sendEmail(email, subject, body)
    if err != nil {
        return err
    }

    // Here you would typically store the token in your database
    // along with the email and expiration time

    return nil
}

func (p *Provider) sendEmail(to, subject, body string) error {
    auth := smtp.PlainAuth("", p.SMTPUsername, p.SMTPPassword, p.SMTPServer)

    msg := fmt.Sprintf("To: %s\r\n"+
        "Subject: %s\r\n"+
        "\r\n"+
        "%s\r\n", to, subject, body)

    err := smtp.SendMail(p.SMTPServer+":"+p.SMTPPort, auth, p.FromEmail, []string{to}, []byte(msg))
    if err != nil {
        return err
    }

    return nil
}

func generateToken() (string, error) {
    b := make([]byte, tokenLength)
    _, err := rand.Read(b)
    if err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}

// RefreshToken refresh token is not available for email provider
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
    return nil, errors.New("refresh token is not available for email provider")
}

// RefreshTokenAvailable refresh token is not available for email provider
func (p *Provider) RefreshTokenAvailable() bool {
    return false
}

// VerifyToken verifies the token sent in the email
func (p *Provider) VerifyToken(token, email string) (bool, error) {
    // Here you would typically check if the token is valid in your database
    // and if it hasn't expired
    // For this example, we'll just return true
    return true, nil
}
