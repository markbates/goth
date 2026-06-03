// Package telegram implements OAuth2/OpenID Connect authentication for Telegram.
package telegram

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	endpointAuth  = "https://oauth.telegram.org/auth"
	endpointToken = "https://oauth.telegram.org/token"
	endpointJWKS  = "https://oauth.telegram.org/.well-known/jwks.json"
	issuer        = "https://oauth.telegram.org"
)

// New creates a new Telegram provider.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "telegram",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of goth.Provider for Telegram.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

type keySet struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	KeyType  string `json:"kty"`
	KeyID    string `json:"kid"`
	Use      string `json:"use"`
	Alg      string `json:"alg"`
	Modulus  string `json:"n"`
	Exponent string `json:"e"`
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider.
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Client returns an HTTP client to be used in all fetch operations.
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the telegram package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Telegram for an authentication endpoint.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	verifier := oauth2.GenerateVerifier()
	url := p.config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	return &Session{
		AuthURL:      url,
		CodeVerifier: verifier,
		State:        state,
	}, nil
}

// FetchUser returns Telegram user data collected from the ID token.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess, ok := session.(*Session)
	if !ok {
		return goth.User{}, fmt.Errorf("invalid telegram session")
	}
	if sess.User.UserID == "" {
		return goth.User{}, fmt.Errorf("telegram user is empty")
	}
	return sess.User, nil
}

// RefreshTokenAvailable returns whether Telegram supports refresh tokens.
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

// RefreshToken gets a new access token based on a refresh token.
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	return ts.Token()
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile"}
	}
	return &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  endpointAuth,
			TokenURL: endpointToken,
		},
	}
}

func parseIDToken(ctx context.Context, client *http.Client, idToken, clientID string) (jwt.MapClaims, error) {
	keys, err := fetchKeySet(ctx, client)
	if err != nil {
		return nil, err
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(
		idToken,
		claims,
		keys.keyfunc,
		jwt.WithIssuer(issuer),
		jwt.WithAudience(clientID),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("parse telegram id_token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("telegram id_token is invalid")
	}
	return claims, nil
}

func fetchKeySet(ctx context.Context, client *http.Client) (*keySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointJWKS, nil)
	if err != nil {
		return nil, err
	}
	resp, err := goth.HTTPClientWithFallBack(client).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch telegram jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch telegram jwks: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read telegram jwks: %w", err)
	}
	keys := &keySet{}
	if err := json.Unmarshal(body, keys); err != nil {
		return nil, fmt.Errorf("decode telegram jwks: %w", err)
	}
	return keys, nil
}

func (ks *keySet) keyfunc(token *jwt.Token) (any, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected telegram signing method: %s", token.Header["alg"])
	}
	kid, _ := token.Header["kid"].(string)
	for _, key := range ks.Keys {
		if key.KeyType != "RSA" || key.Modulus == "" || key.Exponent == "" {
			continue
		}
		if kid != "" && key.KeyID != kid {
			continue
		}
		if key.Alg != "" && key.Alg != token.Method.Alg() {
			continue
		}
		publicKey, err := key.rsaPublicKey()
		if err != nil {
			return nil, err
		}
		return publicKey, nil
	}
	return nil, fmt.Errorf("telegram jwk not found")
}

func (key jwkKey) rsaPublicKey() (*rsa.PublicKey, error) {
	modulus, err := base64.RawURLEncoding.DecodeString(key.Modulus)
	if err != nil {
		return nil, fmt.Errorf("decode telegram jwk modulus: %w", err)
	}
	exponent, err := base64.RawURLEncoding.DecodeString(key.Exponent)
	if err != nil {
		return nil, fmt.Errorf("decode telegram jwk exponent: %w", err)
	}
	if len(exponent) == 0 {
		return nil, fmt.Errorf("telegram jwk exponent is empty")
	}
	e := 0
	for _, b := range exponent {
		e = e<<8 + int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: e}, nil
}

func userFromClaims(claims jwt.MapClaims) (goth.User, error) {
	subject, err := claims.GetSubject()
	if err != nil {
		return goth.User{}, fmt.Errorf("read telegram subject: %w", err)
	}
	if subject == "" {
		return goth.User{}, fmt.Errorf("telegram subject is empty")
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		return goth.User{}, fmt.Errorf("marshal telegram id_token claims: %w", err)
	}

	return goth.User{
		Provider:  "telegram",
		UserID:    subject,
		Name:      stringClaim(claims, "name"),
		NickName:  stringClaim(claims, "preferred_username"),
		AvatarURL: stringClaim(claims, "picture"),
		RawData: map[string]interface{}{
			"raw_profile": string(raw),
			"telegram_id": telegramIDClaim(claims),
		},
	}, nil
}

func stringClaim(claims jwt.MapClaims, key string) string {
	value, ok := claims[key]
	if !ok {
		return ""
	}
	s, _ := value.(string)
	return s
}

func telegramIDClaim(claims jwt.MapClaims) string {
	value, ok := claims["id"]
	if !ok {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatInt(int64(v), 10)
	default:
		return fmt.Sprintf("%v", v)
	}
}
