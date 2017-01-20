package openid_connect

import (
	"net/http"
	"strings"
	"fmt"
	"encoding/json"
	"io/ioutil"
	"errors"
	"golang.org/x/oauth2"
	"github.com/markbates/goth"
	"golang.org/x/oauth2/jws"
	"time"
)

const (
	// Standard Claims http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
	PreferredUsernameClaim   = "preferred_username"
	EmailClaim               = "email"
	NameClaim                = "name"
	NicknameClaim            = "nickname"
	PictureClaim             = "picture"
	GivenNameClaim           = "given_name"
	FamilyNameClaim          = "family_name"
	MiddleNameClaim          = "middle_name"
	ProfileClaim             = "profile"
	WebsiteClaim             = "website"
	EmailVerifiedClaim       = "email_verified"
	GenderClaim              = "gender"
	BirthdateClaim           = "birthdate"
	ZoneinfoClaim            = "zoneinfo"
	LocaleClaim              = "locale"
	PhoneNumberClaim         = "phone_number"
	PhoneNumberVerifiedClaim = "phone_number_verified"
	AddressClaim             = "address"
	UpdatedAtClaim           = "updated_at"

	clockSkew = 10 * time.Second
)

// Provider is the implementation of `goth.Provider` for accessing OpenID Connect provider
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	HTTPClient  *http.Client
	config      *oauth2.Config

	IDClaim                string
	PreferredUsernameClaim string
	EmailClaim             string
	NameClaim              string
}

type OpenIDConfig struct {
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`
	JWKSEndpoint  string `json:"jwks_uri"`
}

// New creates a new OpenID Connect provider, and sets up important connection details.
// You should always call `openid-connect.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL, openIDAutoDiscoveryURL string, scopes ...string) (*Provider, error) {
	openIDConfig, err := getOpenIDConfig(openIDAutoDiscoveryURL)
	if err != nil {
		return nil, err
	}

	p := &Provider{
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,
	}

	p.config = newConfig(p, scopes, openIDConfig)
	return p, nil
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return "openid-connect"
}

// Debug is a no-op for the openid-connect package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks the OpenID Connect provider for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will use the the id_token and access requested information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)

	expiresAt := sess.ExpiresAt

	// decode returned id token to get expiry
	claimSet, err := jws.Decode(sess.IDToken)

	if err != nil {
		return nil, fmt.Errorf("oauth2: error decoding JWT token: %v", err)
	}

	expiry := time.Unix(claimSet.Exp, 0)
	if !expiry.Add(-clockSkew).Before(time.Now()) {
		return nil, errors.New("user info JWT token is expired")
	}
	if expiry.Before(expiresAt) {
		expiresAt = expiry
	}

	var rawData map[string]interface{}
	json.Unmarshal([]byte(sess.IDToken), &rawData)

	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    expiresAt,
		RawData:      rawData,
	}

	err = userFromToken(claimSet, &user)
	return user, err
}

func userFromToken(claims *jws.ClaimSet, user *goth.User) error {
	user.UserID = claims.Sub

	user.Name = claims.PrivateClaims[NameClaim].(string)
	user.NickName = claims.PrivateClaims[PreferredUsernameClaim].(string)
	user.Email = claims.PrivateClaims[EmailClaim].(string)
	user.AvatarURL = claims.PrivateClaims[PictureClaim].(string)
	user.FirstName = claims.PrivateClaims[GivenNameClaim].(string)
	user.LastName = claims.PrivateClaims[FamilyNameClaim].(string)

	return nil
}

//RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

//RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(oauth2.NoContext, token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}

func getOpenIDConfig(openIDAutoDiscoveryURL string) (OpenIDConfig, error) {
	openIDConfig := OpenIDConfig{}

	res, err := http.Get(openIDAutoDiscoveryURL)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(body, &openIDConfig)
	if err != nil {
		return nil, err
	}

	return openIDConfig, err
}

func newConfig(provider *Provider, scopes []string, openIDConfig OpenIDConfig) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  openIDConfig.AuthEndpoint,
			TokenURL: openIDConfig.TokenEndpoint,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		foundOpenIDScope := false

		for _, scope := range scopes {
			if scope == "openid" {
				foundOpenIDScope = true
			}
			c.Scopes = append(c.Scopes, scope)
		}

		if !foundOpenIDScope {
			c.Scopes = append(c.Scopes, "openid")
		}
	} else {
		c.Scopes = []string{"openid"}
	}

	return c
}

// NewProvider returns an implementation of an OpenID Connect Authorization Code Flow
// See http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
// ID Token decryption is not supported
// UserInfo decryption is not supported
/*
	if !sets.NewString(config.Scopes...).Has("openid") {
		return nil, errors.New("Scopes must include openid")
	}

	if len(config.IDClaims) == 0 {
		return nil, errors.New("IDClaims must specify at least one claim")
	}

*/

// GetUserIdentity implements external/interfaces/Provider.GetUserIdentity
/*
func (p provider) GetUserIdentity(data *osincli.AccessData) (authapi.UserIdentityInfo, bool, error) {
	// Token response MUST include id_token
	// http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
	idToken, ok := data.ResponseData["id_token"].(string)
	if !ok {
		return nil, false, fmt.Errorf("No id_token returned in %v", data.ResponseData)
	}

	// id_token MUST be a valid JWT
	idTokenClaims, err := decodeJWT(idToken)
	if err != nil {
		return nil, false, err
	}

	if p.IDTokenValidator != nil {
		if err := p.IDTokenValidator(idTokenClaims); err != nil {
			return nil, false, err
		}
	}

	// TODO: validate JWT
	// http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

	// id_token MUST contain a sub claim as the subject identifier
	// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
	idTokenSubject, ok := idTokenClaims[SubjectClaim].(string)
	if !ok {
		return nil, false, fmt.Errorf("id_token did not contain a 'sub' claim: %#v", idTokenClaims)
	}

	// Use id_token claims by default
	claims := idTokenClaims

	// If we have a userinfo URL, use it to get more detailed claims
	if len(p.UserInfoURL) != 0 {
		userInfoClaims, err := fetchUserInfo(p.UserInfoURL, data.AccessToken, p.transport)
		if err != nil {
			return nil, false, err
		}

		// The sub (subject) Claim MUST always be returned in the UserInfo Response.
		// http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
		userInfoSubject, ok := userInfoClaims[SubjectClaim].(string)
		if !ok {
			return nil, false, fmt.Errorf("userinfo response did not contain a 'sub' claim: %#v", userInfoClaims)
		}

		// The sub Claim in the UserInfo Response MUST be verified to exactly match the sub Claim in the ID Token;
		// if they do not match, the UserInfo Response values MUST NOT be used.
		// http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
		if userInfoSubject != idTokenSubject {
			return nil, false, fmt.Errorf("userinfo 'sub' claim (%s) did not match id_token 'sub' claim (%s)", userInfoSubject, idTokenSubject)
		}

		// Merge in userinfo claims in case id_token claims contained some that userinfo did not
		for k, v := range userInfoClaims {
			claims[k] = v
		}
	}

	glog.V(5).Infof("openid claims: %#v", claims)

	id, _ := getClaimValue(claims, p.IDClaims)
	if id == "" {
		return nil, false, fmt.Errorf("Could not retrieve id claim for %#v from %#v", p.IDClaims, claims)
	}
	identity := authapi.NewDefaultUserIdentityInfo(p.providerName, id)

	if preferredUsername, _ := getClaimValue(claims, p.PreferredUsernameClaims); len(preferredUsername) != 0 {
		identity.Extra[authapi.IdentityPreferredUsernameKey] = preferredUsername
	}

	if email, _ := getClaimValue(claims, p.EmailClaims); len(email) != 0 {
		identity.Extra[authapi.IdentityEmailKey] = email
	}

	if name, _ := getClaimValue(claims, p.NameClaims); len(name) != 0 {
		identity.Extra[authapi.IdentityDisplayNameKey] = name
	}

	glog.V(4).Infof("identity=%v", identity)

	return identity, true, nil
}
*/

func getClaimValue(data map[string]interface{}, claims []string) (string, error) {
	for _, claim := range claims {
		value, ok := data[claim]
		if !ok {
			continue
		}
		stringValue, ok := value.(string)
		if !ok {
			return "", fmt.Errorf("Claim %s was not a string type", claim)
		}
		if len(stringValue) > 0 {
			return stringValue, nil
		}
	}
	return "", errors.New("No value found")
}

// fetch and decode JSON from the given UserInfo URL
func fetchUserInfo(url, accessToken string, transport http.RoundTripper) (map[string]interface{}, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Non-200 response from UserInfo: %d, WWW-Authenticate=%s", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	// The UserInfo Claims MUST be returned as the members of a JSON object
	// http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	decoded := map[string]interface{}{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, err
	}

	return decoded, nil
}

// Decode JWT
// http://openid.net/specs/draft-jones-json-web-token-07.html
func decodeJWT(jwt string) (map[string]interface{}, error) {
	jwtParts := strings.Split(jwt, ".")
	if len(jwtParts) != 3 {
		return nil, fmt.Errorf("Invalid JSON Web Token: expected 3 parts, got %d", len(jwtParts))
	}

	// Re-pad, if needed
	encodedPayload := jwtParts[1]
	if l := len(encodedPayload) % 4; l != 0 {
		encodedPayload += strings.Repeat("=", 4-l)
	}

	// Decode base-64
	decodedPayload, err := base64.StdEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, fmt.Errorf("Error decoding payload: %v", err)
	}

	// Parse JSON
	var data map[string]interface{}
	err = json.Unmarshal([]byte(decodedPayload), &data)
	if err != nil {
		return nil, fmt.Errorf("Error parsing token: %v", err)
	}

	return data, nil
}
