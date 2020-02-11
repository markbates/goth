// Package login.gov implements the OAuth2 protocol for authenticating users through login.gov.
// This package should NOT be used as a reference implementation of an OAuth2 provider for Goth,
// as login.gov uses a different flow than typical providers.
package logingov

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"fmt"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	// Standard Claims http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
	// fixed, cannot be changed
	subjectClaim  = "sub"
	expiryClaim   = "exp"
	audienceClaim = "aud"
	issuerClaim   = "iss"

	UuidClaim          = "uuid"
	EmailClaim         = "email"
	EmailVerifiedClaim = "email_verified"
	GivenNameClaim     = "given_name"
	FamilyNameClaim    = "family_name"
	PhoneClaim         = "phone"
	BirthdateClaim     = "birthdate"
	SsnClaim           = "social_security_number"
	AddressClaim       = "address"

	clockSkew = 10 * time.Second
)

// These vars are necessary for login.gov auth to work.
const ResponseType string = "code"

// These default to the login.gov sandbox values
// AcrValues: Accepts /ial/1 or /ial/2, OR /loa/1/ or /loa/3/
//   * See https://developers.login.gov/oidc/#authorization
// I can't test /loa/3 or /ial/2 because my account is only /loa/1.
var (
	AcrValues      = "http://idmanagement.gov/ns/assurance/loa/1"
	ApprovedEmails = []string{}
)

type OpenIdConfig struct {
	AuthEndpoint     string `json:"authorization_endpoint"`
	TokenEndpoint    string `json:"token_endpoint"`
	UserInfoEndpoint string `json:"userinfo_endpoint"`
	Issuer           string `json:"issuer"`
}

type Address struct {
	Formatted     string
	StreetAddress string
	Locality      string
	Region        string
	PostalCode    string
	Country       string
}

// Provider is the implementation of `goth.Provider` for accessing login.gov.
type Provider struct {
	IssuerId       string
	CallbackUrl    string
	HTTPClient     *http.Client
	providerName   string
	cfg            *oauth2.Config
	openIdCfg      *OpenIdConfig
	codeVerifier   string
	AcrValues      string
	ApprovedEmails []string

	UuidClaims          []string
	EmailClaims         []string
	EmailVerifiedClaims []string
	GivenNameClaims     []string
	FamilyNameClaims    []string
	PhoneClaims         []string
	BirthdateClaims     []string
	SsnClaims           []string
	AddressClaims       []string
}

func New(issuerId, callbackUrl, discoveryUrl string, scopes ...string) (*Provider, error) {
	return NewCustomisedURL(issuerId, callbackUrl, discoveryUrl, AcrValues, ApprovedEmails, scopes...)
}

// New creates a new login.gov provider and sets up important connection details.
// You should always call `logingov.New` or `logingov.NewCustomisedURL` to get a new
// provider. Never try to create one manually.
func NewCustomisedURL(
	issuerId, callbackUrl, discoveryUrl, acrValues string,
	approvedEmails []string, scopes ...string) (*Provider, error) {
	p := &Provider{
		IssuerId:       issuerId,
		CallbackUrl:    callbackUrl,
		AcrValues:      acrValues,
		ApprovedEmails: approvedEmails,

		UuidClaims:          []string{UuidClaim},
		EmailClaims:         []string{EmailClaim},
		EmailVerifiedClaims: []string{EmailVerifiedClaim},
		GivenNameClaims:     []string{GivenNameClaim},
		FamilyNameClaims:    []string{FamilyNameClaim},
		PhoneClaims:         []string{PhoneClaim},
		AddressClaims:       []string{AddressClaim},
		BirthdateClaims:     []string{BirthdateClaim},
		SsnClaims:           []string{SsnClaim},

		providerName: "login.gov",
	}

	// default is sandbox login.gov
	if discoveryUrl == "" {
		discoveryUrl = "https://idp.int.identitysandbox.gov/.well-known/openid-configuration"
	}

	openIdConfig, err := getOpenIdConfig(p, discoveryUrl)
	if err != nil {
		return nil, err
	}
	p.openIdCfg = openIdConfig

	p.cfg = newConfig(p, scopes)
	return p, nil
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

// Debug is a no-op for the login.gov package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks login.gov for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	nonce, err := randomHex(32)
	if err != nil {
		return &Session{}, err
	}

	codeVerifier, codeChallenge, err := genCodeChallenge(32)
	if err != nil {
		return &Session{}, err
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("acr_values", p.AcrValues),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("redirect_uri", p.CallbackUrl),
		oauth2.SetAuthURLParam("response_type", ResponseType),
	}
	return &Session{
		AuthURL:      p.cfg.AuthCodeURL(state, opts...),
		CodeVerifier: codeVerifier,
	}, nil
}

func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	expiresAt := sess.ExpiresAt

	if sess.IdToken == "" {
		return goth.User{}, fmt.Errorf("%s cannot get user information without id_token", p.providerName)
	}

	claims, err := decodeJWT(sess.IdToken)
	if err != nil {
		return goth.User{}, fmt.Errorf("oauth2: error decoding JWT token: %v", err)
	}

	expiry, err := p.validateClaims(claims)
	if err != nil {
		return goth.User{}, fmt.Errorf("oauth2: error validating JWT token: %v", err)
	}

	if err != nil {
		return goth.User{}, fmt.Errorf("oauth2: error validating JWT token: %v", err)
	}

	if expiry.Before(expiresAt) {
		expiresAt = expiry
	}

	if err := p.getUserInfo(sess.AccessToken, claims); err != nil {
		return goth.User{}, err
	}
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    expiresAt,
		RawData:      claims,
		IDToken:      sess.IdToken,
	}

	p.userFromClaims(claims, &user)
	if err != nil {
		return goth.User{}, err
	}

	// block access if email isn't approved
	if len(p.ApprovedEmails) > 0 {
		if !contains(p.ApprovedEmails, user.Email) {
			return goth.User{}, errors.New("This email is not on the approved access list.")
		}
	}

	return user, err

}

func (p *Provider) userFromClaims(claims map[string]interface{}, user *goth.User) {
	if p.AcrValues == "http://idmanagement.gov/ns/assurance/loa/3" {
		user.Email = getClaimValue(claims, p.EmailClaims)
		user.RawData["uuid"] = getClaimValue(claims, p.UuidClaims)
	}

	// email is a required value
	user.Email = getClaimValue(claims, p.EmailClaims)
}

func (p *Provider) getUserInfo(accessToken string, claims map[string]interface{}) error {
	userInfoClaims, err := p.fetchUserInfo(p.openIdCfg.UserInfoEndpoint, accessToken)
	if err != nil {
		return err
	}

	// The sub (subject) Claim MUST always be returned in the UserInfo Response.
	// http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
	userInfoSubject := getClaimValue(userInfoClaims, []string{subjectClaim})
	if userInfoSubject == "" {
		return fmt.Errorf("userinfo response did not contain a 'sub' claim: %#v", userInfoClaims)
	}

	// The sub Claim in the UserInfo Response MUST be verified to exactly match the sub Claim in the ID Token;
	// if they do not match, the UserInfo Response values MUST NOT be used.
	// http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
	subject := getClaimValue(claims, []string{subjectClaim})
	if userInfoSubject != subject {
		return fmt.Errorf("userinfo 'sub' claim (%s) did not match id_token 'sub' claim (%s)", userInfoSubject, subject)
	}

	// Merge in userinfo claims in case id_token claims contained some that userinfo did not
	for k, v := range userInfoClaims {
		claims[k] = v
	}

	return nil
}

// FetchUser will go to login.gov and access basic information about the user.
func (p *Provider) fetchUserInfo(url, accessToken string) (map[string]interface{}, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := p.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	return unMarshal(data)
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.IssuerId,
		ClientSecret: "", // not necessary for login.gov
		RedirectURL:  provider.CallbackUrl,
		Endpoint: oauth2.Endpoint{
			AuthURL:  provider.openIdCfg.AuthEndpoint,
			TokenURL: provider.openIdCfg.TokenEndpoint,
		},
		Scopes: []string{},
	}

	// "email" is the only available scope for IAL1 / LOA1
	// See https://developers.login.gov/attributes/
	if len(scopes) > 0 {
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	} else {
		c.Scopes = append(c.Scopes, "email")
	}

	return c
}

//RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

//RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.cfg.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}

// validate according to standard, returns expiry
// http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func (p *Provider) validateClaims(claims map[string]interface{}) (time.Time, error) {
	audience := getClaimValue(claims, []string{audienceClaim})
	if audience != p.IssuerId {
		found := false
		audiences := getClaimValues(claims, []string{audienceClaim})
		for _, aud := range audiences {
			if aud == p.IssuerId {
				found = true
				break
			}
		}
		if !found {
			return time.Time{}, errors.New("audience in token does not match client key")
		}
	}

	issuer := getClaimValue(claims, []string{issuerClaim})
	if issuer != p.openIdCfg.Issuer {
		return time.Time{}, errors.New("issuer in token does not match issuer in OpenIDConfig discovery")
	}

	// expiry is required for JWT, not for UserInfoResponse
	// is actually a int64, so force it in to that type
	expiryClaim := int64(claims[expiryClaim].(float64))
	expiry := time.Unix(expiryClaim, 0)
	if expiry.Add(clockSkew).Before(time.Now()) {
		return time.Time{}, errors.New("user info JWT token is expired")
	}
	return expiry, nil
}

func getClaimValue(data map[string]interface{}, claims []string) string {
	for _, claim := range claims {
		if value, ok := data[claim]; ok {
			if stringValue, ok := value.(string); ok && len(stringValue) > 0 {
				return stringValue
			}
		}
	}

	return ""
}

func getClaimValues(data map[string]interface{}, claims []string) []string {
	var result []string

	for _, claim := range claims {
		if value, ok := data[claim]; ok {
			if stringValues, ok := value.([]interface{}); ok {
				for _, stringValue := range stringValues {
					if s, ok := stringValue.(string); ok && len(s) > 0 {
						result = append(result, s)
					}
				}
			}
		}
	}

	return result
}

// decodeJWT decodes a JSON Web Token into a simple map
// http://openid.net/specs/draft-jones-json-web-token-07.html
// from providers/openidConnect.go
func decodeJWT(jwt string) (map[string]interface{}, error) {
	jwtParts := strings.Split(jwt, ".")
	if len(jwtParts) != 3 {
		return nil, errors.New("jws: invalid token received, not all parts available")
	}

	// Re-pad, if needed
	encodedPayload := jwtParts[1]
	if l := len(encodedPayload) % 4; l != 0 {
		encodedPayload += strings.Repeat("=", 4-l)
	}

	decodedPayload, err := base64.StdEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, err
	}

	return unMarshal(decodedPayload)
}

func unMarshal(payload []byte) (map[string]interface{}, error) {
	data := make(map[string]interface{})

	return data, json.NewDecoder(bytes.NewBuffer(payload)).Decode(&data)
}

func getOpenIdConfig(p *Provider, openIDAutoDiscoveryURL string) (*OpenIdConfig, error) {
	res, err := p.Client().Get(openIDAutoDiscoveryURL)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	openIdConfig := &OpenIdConfig{}
	err = json.Unmarshal(body, openIdConfig)
	if err != nil {
		return nil, err
	}

	return openIdConfig, nil
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)

	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

func genCodeChallenge(length int) (string, string, error) {
	code, err := randomHex(length)
	if err != nil {
		return "", "", err
	}

	sum := sha256.Sum256([]byte(code))

	return code, b64.StdEncoding.EncodeToString(sum[:]), nil
}

func contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}
