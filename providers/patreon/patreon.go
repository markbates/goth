package patreon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	// AuthorizationURL specifies Patreon's OAuth2 authorization endpoint (see https://tools.ietf.org/html/rfc6749#section-3.1).
	// See Example_refreshToken for examples.
	authorizationURL = "https://www.patreon.com/oauth2/authorize"

	// AccessTokenURL specifies Patreon's OAuth2 token endpoint (see https://tools.ietf.org/html/rfc6749#section-3.2).
	// See Example_refreshToken for examples.
	tokenURL = "https://www.patreon.com/api/oauth2/token"

	profileURL = "https://www.patreon.com/api/oauth2/v2/identity?fields%5Buser%5D=created,email,full_name,image_url,vanity"
)

//goland:noinspection GoUnusedConst
const (
	// ScopeIdentity provides read access to data about the user. See the /identity endpoint documentation for details about what data is available.
	ScopeIdentity = "identity"

	// ScopeIdentityEmail provides read access to the user’s email.
	ScopeIdentityEmail = "identity[email]"

	// ScopeIdentityMemberships provides read access to the user’s memberships.
	ScopeIdentityMemberships = "identity.memberships"

	// ScopeCampaigns provides read access to basic campaign data. See the /campaign endpoint documentation for details about what data is available.
	ScopeCampaigns = "campaigns"

	// ScopeCampaignsWebhook provides read, write, update, and delete access to the campaign’s webhooks created by the client.
	ScopeCampaignsWebhook = "w:campaigns.webhook"

	// ScopeCampaignsMembers provides read access to data about a campaign’s members. See the /members endpoint documentation for details about what data is available. Also allows the same information to be sent via webhooks created by your client.
	ScopeCampaignsMembers = "campaigns.members"

	// ScopeCampaignsMembersEmail provides read access to the member’s email. Also allows the same information to be sent via webhooks created by your client.
	ScopeCampaignsMembersEmail = "campaigns.members[email]"

	// ScopeCampaignsMembersAddress provides read access to the member’s address, if an address was collected in the pledge flow. Also allows the same information to be sent via webhooks created by your client.
	ScopeCampaignsMembersAddress = "campaigns.members.address"

	// ScopeCampaignsPosts provides read access to the posts on a campaign.
	ScopeCampaignsPosts = "campaigns.posts"
)

// New creates a new Patreon provider and sets up important connection details.
// You should always call `patreon.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	return NewCustomisedURL(clientKey, secret, callbackURL, authorizationURL, tokenURL, profileURL, scopes...)
}

// NewCustomisedURL is similar to New(...) but can be used to set custom URLs to connect to
func NewCustomisedURL(clientKey, secret, callbackURL, authURL, tokenURL, profileURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "patreon",
		profileURL:   profileURL,
	}
	p.config = newConfig(p, authURL, tokenURL, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Patreon.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	authURL      string
	tokenURL     string
	profileURL   string
}

// Name gets the name used to retrieve this provider later.
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

// Debug is a no-op for the Patreon package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Patreon for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to Patreon and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", p.profileURL, nil)
	if err != nil {
		return user, err
	}

	req.Header.Add("authorization", "Bearer "+sess.AccessToken)
	response, err := p.Client().Do(req)
	if err != nil {
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	bits, err := io.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)

	return user, err
}

// RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}

func newConfig(provider *Provider, authURL, tokenURL string, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	}
	return c
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		Data struct {
			Attributes struct {
				Created  time.Time `json:"created"`
				Email    string    `json:"email"`
				FullName string    `json:"full_name"`
				ImageURL string    `json:"image_url"`
				Vanity   string    `json:"vanity"`
			} `json:"attributes"`
			ID string `json:"id"`
		} `json:"data"`
	}{}
	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}
	user.Email = u.Data.Attributes.Email
	user.Name = u.Data.Attributes.FullName
	user.NickName = u.Data.Attributes.Vanity
	user.UserID = u.Data.ID
	user.AvatarURL = u.Data.Attributes.ImageURL
	return nil
}
