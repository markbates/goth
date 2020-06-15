// Package twitch implements the OAuth2 protocol for authenticating users through Twitch.
// This package can be used as a reference implementation of an OAuth2 provider for Twitch.
package twitch

import (
	"encoding/json"
	"io"
	"net/http"

	"fmt"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL      string = "https://id.twitch.tv/oauth2/authorize"
	tokenURL     string = "https://id.twitch.tv/oauth2/token"
	userEndpoint string = "https://api.twitch.tv/helix/users"
)

const (
	// ScopeChannelCheckSubscription provides access to read whether a user is
	// subscribed to your channel.
	ScopeChannelCheckSubscription string = "channel_check_subscription"
	// ScopeChannelCommercial provides access to trigger commercials on
	// channel.
	ScopeChannelCommercial string = "channel_commercial"
	// ScopeChannelEditor provides access to write channel metadata
	// (game, status, etc).
	ScopeChannelEditor string = "channel_editor"
	// ScopeChannelFeedEdit provides access to add posts and reactions to a
	// channel feed.
	ScopeChannelFeedEdit string = "channel_feed_edit"
	// ScopeChannelFeedRead provides access to view a channel feed.
	ScopeChannelFeedRead string = "channel_feed_read"
	// ScopeChannelRead provides access to read nonpublic channel information,
	// including email address and stream key.
	ScopeChannelRead string = "channel_read"
	// ScopeChannelStream provides access to reset a channel’s stream key.
	ScopeChannelStream string = "channel_stream"
	// ScopeChannelSubscriptions provides access to read all subscribers to
	// your channel.
	ScopeChannelSubscriptions string = "channel_subscriptions"
	// ScopeCollectionsEdit provides access to manage a user’s collections
	// (of videos).
	ScopeCollectionsEdit string = "collections_edit"
	// ScopeCommunitiesEdit provides access to manage a user’s communities.
	ScopeCommunitiesEdit string = "communities_edit"
	// ScopeCommunitiesModerate provides access to manage community moderators.
	ScopeCommunitiesModerate string = "communities_moderate"
	// ScopeOpenID provides access to use OpenID Connect authentication.
	ScopeOpenID string = "openid"
	// ScopeUserBlocksEdit provides access to turn on/off ignoring a user.
	// Ignoring users means you cannot see them type, receive messages from
	// them, etc.
	ScopeUserBlocksEdit string = "user_blocks_edit"
	// ScopeUserBlocksRead provides access to read a user’s list of ignored
	// users.
	ScopeUserBlocksRead string = "user_blocks_read"
	// ScopeUserFollowsEdit provides access to manage a user’s followed
	// channels.
	ScopeUserFollowsEdit string = "user_follows_edit"
	// ScopeUserRead provides access to read nonpublic user information, like
	// email address.
	ScopeUserRead string = "user_read"
	// ScopeUserSubscriptions provides access to read a user’s subscriptions.
	ScopeUserSubscriptions string = "user_subscriptions"
	// ScopeViewingActivityRead provides access to turn on Viewer Heartbeat
	// Service ability to record user data.
	ScopeViewingActivityRead string = "viewing_activity_read"
	// ScopeChatLogin (Deprecated — cannot be requested by new clients.) Log
	// into chat and send messages.
	ScopeChatLogin string = "chat_login"
)

// New creates a new Twitch provider, and sets up important connection details.
// You should always call `twitch.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey string, secret string, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "twitch",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Twitch
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// Name gets the name used to retrieve this provider.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Client ...
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is no-op for the Twitch package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Twitch for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	s := &Session{
		AuthURL: url,
	}
	return s, nil
}

// FetchUser will go to Twitch and access basic info about the user.
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
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
	req.Header.Set("Client-ID", p.config.ClientID)
	resp, err := p.Client().Do(req)
	if err != nil {
		return user, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, resp.StatusCode)
	}

	err = userFromReader(resp.Body, &user)
	return user, err
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		Data []struct {
			ID              string `json:"id"`
			Login           string `json:"login"`
			DisplayName     string `json:"display_name"`
			Description     string `json:"description"`
			ProfileImageURL string `json:"profile_image_url"`
			Email           string `json:"email"`
		} `json:"data"`
	}{}

	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}

	if len(u.Data) != 1 {
		return fmt.Errorf("user not found in response")
	}

	user.Name = u.Data[0].Login
	user.Email = u.Data[0].Email
	user.NickName = u.Data[0].DisplayName
	user.Location = "No location is provided by the Twitch API"
	user.AvatarURL = u.Data[0].ProfileImageURL
	user.Description = u.Data[0].Description
	user.UserID = u.Data[0].ID

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
		c.Scopes = []string{ScopeUserRead}
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
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}
