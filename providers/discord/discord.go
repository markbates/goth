// Package discord implements the OAuth2 protocol for authenticating users through Discord.
// This package can be used as a reference implementation of an OAuth2 provider for Discord.
package discord

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL      string = "https://discord.com/api/oauth2/authorize"
	tokenURL     string = "https://discord.com/api/oauth2/token"
	userEndpoint string = "https://discord.com/api/users/@me"
)

const (
	// ScopeIdentify allows /users/@me without email
	ScopeIdentify string = "identify"
	// ScopeEmail enables /users/@me to return an email
	ScopeEmail string = "email"
	// ScopeConnections allows /users/@me/connections to return linked Twitch and YouTube accounts
	ScopeConnections string = "connections"
	// ScopeGuilds allows /users/@me/guilds to return basic information about all of a user's guilds
	ScopeGuilds string = "guilds"
	// ScopeJoinGuild allows /invites/{invite.id} to be used for joining a user's guild
	ScopeJoinGuild string = "guilds.join"
	// ScopeGroupDMjoin allows your app to join users to a group dm
	ScopeGroupDMjoin string = "gdm.join"
	// ScopeBot is for oauth2 bots, this puts the bot in the user's selected guild by default
	ScopeBot string = "bot"
	// ScopeWebhook	generates a webhook that is returned in the oauth token response for authorization code grants
	ScopeWebhook string = "webhook.incoming"
	// ScopeReadGuilds	allows /users/@me/guilds/{guild.id}/member to return a user's member information in a guild
	ScopeReadGuilds string = "guilds.members.read"
)

// New creates a new Discord provider, and sets up important connection details.
// You should always call `discord.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey string, secret string, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "discord",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Discord
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	permissions  string
}

// Name gets the name used to retrieve this provider.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// SetPermissions is to update the bot permissions (used for when ScopeBot is set)
func (p *Provider) SetPermissions(permissions string) {
	p.permissions = permissions
}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is no-op for the Discord package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Discord for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {

	opts := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("prompt", "none"),
	}

	if p.permissions != "" {
		opts = append(opts, oauth2.SetAuthURLParam("permissions", p.permissions))
	}

	url := p.config.AuthCodeURL(state, opts...)

	s := &Session{
		AuthURL: url,
	}
	return s, nil
}

// FetchUser will go to Discord and access basic info about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)

	user := goth.User{
		AccessToken:  s.AccessToken,
		Provider:     p.Name(),
		RefreshToken: s.RefreshToken,
		ExpiresAt:    s.ExpiresAt,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", userEndpoint, nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
	resp, err := p.Client().Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return user, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, resp.StatusCode)
	}

	bits, err := io.ReadAll(resp.Body)
	if err != nil {
		return user, err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)
	if err != nil {
		return user, err
	}

	return user, err
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		Name          string `json:"username"`
		Email         string `json:"email"`
		AvatarID      string `json:"avatar"`
		MFAEnabled    bool   `json:"mfa_enabled"`
		Discriminator string `json:"discriminator"`
		Verified      bool   `json:"verified"`
		ID            string `json:"id"`
	}{}

	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}

	// If this prefix is present, the image should be available as a gif,
	// See : https://discord.com/developers/docs/reference#image-formatting
	// Introduced by : Yyewolf

	if u.AvatarID != "" {
		avatarExtension := ".jpg"
		prefix := "a_"
		if len(u.AvatarID) >= len(prefix) && u.AvatarID[0:len(prefix)] == prefix {
			avatarExtension = ".gif"
		}
		user.AvatarURL = "https://media.discordapp.net/avatars/" + u.ID + "/" + u.AvatarID + avatarExtension
	}

	user.Name = u.Name
	user.Email = u.Email
	user.UserID = u.ID

	return nil
}

func newConfig(p *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     p.ClientKey,
		ClientSecret: p.Secret,
		RedirectURL:  p.CallbackURL,
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
	} else {
		c.Scopes = []string{ScopeIdentify}
	}

	return c
}

// RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(oauth2.NoContext, token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}
