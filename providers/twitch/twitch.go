// Package twitch implements the OAuth2 protocol for authenticating users through Twitch.
// This package can be used as a reference implementation of an OAuth2 provider for Twitch.
package twitch

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL      string = "https://id.twitch.tv/oauth2/authorize"
	tokenURL     string = "https://id.twitch.tv/oauth2/token"
	userEndpoint string = "https://api.twitch.tv/helix/users"
)

const (
	// ScopeAnalyticsReadExtensions provides access to view analytics data for
	// the Twitch Extensions owned by the authenticated account.
	ScopeAnalyticsReadExtensions = "analytics:read:extensions"
	// ScopeAnalyticsReadGames provides accesss to view analytics data for the
	// games owned by the authenticated account.
	ScopeAnalyticsReadGames = "analytics:read:games"
	// ScopeBitsRead provides access to view Bits information for a channel.
	ScopeBitsRead = "bits:read"
	// ScopeChannelManageBroadcast provides access to manage a channel’s
	// broadcast configuration, including updating channel configuration and
	// managing stream markers and stream tags.
	ScopeChannelManageBroadcast = "channel:manage:broadcast"
	// ScopeChannelReadCharity provides access to read charity campaign details
	// and user donations on your channel.
	ScopeChannelReadCharity = "channel:read:charity"
	// ScopeChannelEditCommercial provides access to run commercials on a
	// channel.
	ScopeChannelEditCommercial = "channel:edit:commercial"
	// ScopeChannelReadEditors provides access to view a list of users with the
	// editor role for a channel.
	ScopeChannelReadEditors = "channel:read:editors"
	// ScopeChannelManageExtensions provides access to manage a channel’s
	// Extension configuration, including activating Extensions.
	ScopeChannelManageExtensions = "channel:manage:extensions"
	// ScopeChannelReadGoals provides access to view Creator Goals for a
	// channel.
	ScopeChannelReadGoals = "channel:read:goals"
	// ScopeChannelReadGuestStar provides access to read Guest Star details
	// for your channel.
	ScopeChannelReadGuestStar = "channel:read:guest_star"
	// ScopeChannelManageGuestStar provides access to manage Guest Star
	// for your channel.
	ScopeChannelManageGuestStar = "channel:manage:guest_star"
	// ScopeChannelReadHypeTrain provides access to view Hype Train information
	// for a channel.
	ScopeChannelReadHypeTrain = "channel:read:hype_train"
	// ScopeChannelManageModerators provides access to add or remove the
	// moderator role from users in your channel.
	ScopeChannelManageModerators = "channel:manage:moderators"
	// ScopeChannelReadPolls provides access to view a channel’s polls.
	ScopeChannelReadPolls = "channel:read:polls"
	// ScopeChannelManagePolls provides access to manage a channel’s polls.
	ScopeChannelManagePolls = "channel:manage:polls"
	// ScopeChannelReadPredictions provides access to view a channel’s Channel
	// Points Predictions.
	ScopeChannelReadPredictions = "channel:read:predictions"
	// ScopeChannelManagePredictions provides access to manage a channel’s
	// Channel Points Predictions.
	ScopeChannelManagePredictions = "channel:manage:predictions"
	// ScopeChannelManageRaids provides access to manage a channel raiding another channel.
	ScopeChannelManageRaids = "channel:manage:raids"
	// ScopeChannelReadRedemptions provides access to view Channel Points custom
	// rewards and their redemptions on a channel.
	ScopeChannelReadRedemptions = "channel:read:redemptions"
	// ScopeChannelManageRedemptions provides access to manage Channel Points
	// custom rewards and their redemptions on a channel.
	ScopeChannelManageRedemptions = "channel:manage:redemptions"
	// ScopeChannelManageSchedule provides access to manage a channel’s stream
	// schedule.
	ScopeChannelManageSchedule = "channel:manage:schedule"
	// ScopeChannelReadStreamKey provides access to view an authorized user’s
	// stream key.
	ScopeChannelReadStreamKey = "channel:read:stream_key"
	// ScopeChannelReadSubscriptions provides access to view a list of all
	// subscribers to a channel and check if a user is subscribed to a channel.
	ScopeChannelReadSubscriptions = "channel:read:subscriptions"
	// ScopeChannelManageVideos provides access to manage a channel’s videos,
	// including deleting videos.
	ScopeChannelManageVideos = "channel:manage:videos"
	// ScopeChannelReadVips provides access to read the list of VIPs in your channel.
	ScopeChannelReadVips = "channel:read:vips"
	// ScopeChannelManageVips provide access to add or remove the VIP role from
	// users in your channel.
	ScopeChannelManageVips = "channel:manage:vips"
	// ScopeClipsEdit provides access to manage Clips for a channel.
	ScopeClipsEdit = "clips:edit"
	// ScopeModerationRead provides access to view a channel’s moderation data
	// including Moderators, Bans, Timeouts, and AutoMod settings.
	ScopeModerationRead = "moderation:read"
	// ScopeModeratorManageAnnouncements provides access to send announcements
	// in channels where you have the moderator role.
	ScopeModeratorManageAnnouncements = "moderator:manage:announcements"
	// ScopeModeratorManageAutomod provides access to manage messages held for
	// review by AutoMod in channels where you are a moderator.
	ScopeModeratorManageAutomod = "moderator:manage:automod"
	// ScopeModeratorReadAutomodSettings provides access to view a broadcaster’s
	// AutoMod settings.
	ScopeModeratorReadAutomodSettings = "moderator:read:automod_settings"
	// ScopeModeratorManageAutomodSettings provides access to manage a broadcaster’s
	// AutoMod settings.
	ScopeModeratorManageAutomodSettings = "moderator:manage:automod_settings"
	// ScopeModeratorManageBannedUsers provides access to ban and unban users.
	ScopeModeratorManageBannedUsers = "moderator:manage:banned_users"
	// ScopeModeratorReadBlockedTerms provides access to view a broadcaster’s
	// list of blocked terms.
	ScopeModeratorReadBlockedTerms = "moderator:read:blocked_terms"
	// ScopeModeratorManageBlockedTerms provides access to manage a
	// broadcaster’s list of blocked terms.
	ScopeModeratorManageBlockedTerms = "moderator:manage:blocked_terms"
	// ScopeModeratorManageChatMessages provides access to delete chat messages
	// in channels where you have the moderator role
	ScopeModeratorManageChatMessages = "moderator:manage:chat_messages"
	// ScopeModeratorReadChatSettings provides access to view a broadcaster’s
	// chat room settings.
	ScopeModeratorReadChatSettings = "moderator:read:chat_settings"
	// ScopeModeratorManageChatSettings provides access to manage a
	// broadcaster’s chat room settings.
	ScopeModeratorManageChatSettings = "moderator:manage:chat_settings"
	// ScopeModeratorReadChatters provides access to view the chatters
	// in a broadcaster’s chat room.
	ScopeModeratorReadChatters = "moderator:read:chatters"
	// ScopeModeratorReadFollowers provides access to read the followers of a broadcaster.
	ScopeModeratorReadFollowers = "moderator:read:followers"
	// ScopeModeratorReadGuestStar provides access to read Guest Star details
	// for channels where you are a Guest Star moderator.
	ScopeModeratorReadGuestStar = "moderator:read:guest_star"
	// ScopeModeratorManageGuestStar provides access to Manage Guest Star for
	// channels where you are a Guest Star moderator.
	ScopeModeratorManageGuestStar = "moderator:manage:guest_star"
	// ScopeModeratorReadShieldMode provides access to view a broadcaster’s
	// Shield Mode status.
	ScopeModeratorReadShieldMode = "moderator:read:shield_mode"
	// ScopeModeratorManageShieldMode provides access to manage a broadcaster’s
	// Shield Mode status.
	ScopeModeratorManageShieldMode = "moderator:manage:shield_mode"
	// ScopeModeratorReadShoutouts provides access to view a broadcaster’s shoutouts.
	ScopeModeratorReadShoutouts = "moderator:read:shoutouts"
	// ScopeModeratorManageShoutouts provides access to manage a broadcaster’s shoutouts.
	ScopeModeratorManageShoutouts = "moderator:manage:shoutouts"
	// ScopeUserEdit provides access to manage a user object.
	ScopeUserEdit = "user:edit"
	// ScopeUserEditFollows is deprecated. Was previously used for
	// “Create User Follows” and “Delete User Follows.”
	ScopeUserEditFollows = "user:edit:follows"
	// ScopeUserReadBlockedUsers provides access to view the block list of a
	// user.
	ScopeUserReadBlockedUsers = "user:read:blocked_users"
	// ScopeUserManageBlockedUsers provides access to manage the block list of a
	// user.
	ScopeUserManageBlockedUsers = "user:manage:blocked_users"
	// ScopeUserReadBroadcast provides access to view a user’s broadcasting
	// configuration, including Extension configurations.
	ScopeUserReadBroadcast = "user:read:broadcast"
	// ScopeUserManageChatColor provides access to update the color use
	// for the user’s name in chat.
	ScopeUserManageChatColor = "user:manage:chat_color"
	// ScopeUserReadEmail provides access to view a user’s email address.
	ScopeUserReadEmail = "user:read:email"
	// ScopeUserReadFollows provides access to view the list of channels a user
	// follows.
	ScopeUserReadFollows = "user:read:follows"
	// ScopeUserReadSubscriptions provides access to view if an authorized user
	// is subscribed to specific channels.
	ScopeUserReadSubscriptions = "user:read:subscriptions"
	// ScopeUserManageWhispers provides access to read whispers that you send and receive,
	// and send whispers on your behalf.
	ScopeUserManageWhispers = "user:manage:whispers"
	// ScopeChannelModerate provides access to perform moderation actions in a channel.
	// The user requesting the scope must be a moderator in the channel.
	ScopeChannelModerate = "channel:moderate"
	// ScopeChatEdit provides access to send live stream chat messages.
	ScopeChatEdit = "chat:edit"
	// ScopeChatRead provides access to view live stream chat messages.
	ScopeChatRead = "chat:read"
	// ScopeWhispersRead provides access to view your whisper messages.
	ScopeWhispersRead = "whispers:read"
	// ScopeWhispersEdit provides access to send whisper messages.
	ScopeWhispersEdit = "whispers:edit"

	// ScopeChannelSubscriptions is a v5 scope.
	ScopeChannelSubscriptions = ScopeChannelReadSubscriptions
	// ScopeChannelCommercial is a v5 scope.
	ScopeChannelCommercial = ScopeChannelEditCommercial
	// ScopeChannelEditor is a v5 scope which maps to channel:manage:broadcast
	// and channel:manage:videos.
	ScopeChannelEditor = "channel_editor"
	// ScopeUserFollowsEdit is a v5 scope.
	ScopeUserFollowsEdit = ScopeUserEditFollows
	// ScopeChannelRead is a v5 scope which maps to channel:read:editors,
	// channel:read:stream_key, and user:read:email.
	ScopeChannelRead = "channel_read"
	// ScopeUserRead is a v5 scope.
	ScopeUserRead = ScopeUserReadEmail
	// ScopeUserBlocksRead is a v5 scope.
	ScopeUserBlocksRead = ScopeUserReadBlockedUsers
	// ScopeUserBlocksEdit is a v5 scope.
	ScopeUserBlocksEdit = ScopeUserManageBlockedUsers
	// ScopeUserSubscriptions is a v5 scope.
	ScopeUserSubscriptions = ScopeUserReadSubscriptions
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
	req.Header.Set("Client-Id", p.config.ClientID)
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
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
	var users struct {
		Data []struct {
			ID          string `json:"id"`
			Name        string `json:"login"`
			Nickname    string `json:"display_name"`
			Description string `json:"description"`
			AvatarURL   string `json:"profile_image_url"`
			Email       string `json:"email"`
		} `json:"data"`
	}
	err := json.NewDecoder(r).Decode(&users)
	if err != nil {
		return err
	}
	if len(users.Data) == 0 {
		return errors.New("user not found")
	}
	u := users.Data[0]
	user.Name = u.Name
	user.Email = u.Email
	user.NickName = u.Nickname
	user.Location = "No location is provided by the Twitch API"
	user.AvatarURL = u.AvatarURL
	user.Description = u.Description
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
		c.Scopes = []string{ScopeUserReadEmail}
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
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}
