package shopify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/markbates/goth"
)

const (
	shopifyHostnameRegex = `^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`
)

// Session stores data during the auth process with Shopify.
type Session struct {
	AuthURL     string
	AccessToken string
	Hostname    string
	HMAC        string
	ExpiresAt   time.Time
}

var _ goth.Session = &Session{}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Shopify provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize the session with Shopify and return the access token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	// Validate the incoming HMAC is valid.
	// See: https://help.shopify.com/en/api/getting-started/authentication/oauth#verification
	digest := fmt.Sprintf(
		"code=%s&host=%s&shop=%s&state=%s&timestamp=%s",
		params.Get("code"),
		params.Get("host"),
		params.Get("shop"),
		params.Get("state"),
		params.Get("timestamp"),
	)
	h := hmac.New(sha256.New, []byte(os.Getenv("SHOPIFY_SECRET")))
	h.Write([]byte(digest))
	sha := hex.EncodeToString(h.Sum(nil))

	// Ensure our HMAC hash's match.
	if sha != params.Get("hmac") {
		return "", errors.New("Invalid HMAC received")
	}

	// Validate the hostname matches what we're expecting.
	// See: https://help.shopify.com/en/api/getting-started/authentication/oauth#step-3-confirm-installation
	re := regexp.MustCompile(shopifyHostnameRegex)
	if !re.MatchString(params.Get("shop")) {
		return "", errors.New("Invalid hostname received")
	}

	// Make the exchange for an access token.
	p := provider.(*Provider)
	token, err := p.config.Exchange(goth.ContextForClient(p.Client()), params.Get("code"))
	if err != nil {
		return "", err
	}

	// Ensure it's valid.
	if !token.Valid() {
		return "", errors.New("Invalid token received from provider")
	}

	s.AccessToken = token.AccessToken
	s.Hostname = params.Get("hostname")
	s.HMAC = params.Get("hmac")

	return token.AccessToken, err
}

// Marshal the session into a string
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s Session) String() string {
	return s.Marshal()
}

// UnmarshalSession wil unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(s)
	return s, err
}
