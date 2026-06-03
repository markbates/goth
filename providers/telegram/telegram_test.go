package telegram

import (
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestBeginAuthUsesTelegramOIDCEndpointAndPKCE(t *testing.T) {
	provider := New("client", "secret", "https://example.com/callback")
	session, err := provider.BeginAuth("state-value")
	require.NoError(t, err)

	authURL, err := session.GetAuthURL()
	require.NoError(t, err)

	parsed, err := url.Parse(authURL)
	require.NoError(t, err)
	require.Equal(t, endpointAuth, parsed.Scheme+"://"+parsed.Host+parsed.Path)
	require.Equal(t, "client", parsed.Query().Get("client_id"))
	require.Equal(t, "https://example.com/callback", parsed.Query().Get("redirect_uri"))
	require.Equal(t, "state-value", parsed.Query().Get("state"))
	require.Equal(t, "S256", parsed.Query().Get("code_challenge_method"))
	require.NotEmpty(t, parsed.Query().Get("code_challenge"))
	require.True(t, strings.Contains(parsed.Query().Get("scope"), "openid"))
	require.True(t, strings.Contains(parsed.Query().Get("scope"), "profile"))

	telegramSession := session.(*Session)
	require.Equal(t, "state-value", telegramSession.State)
	require.NotEmpty(t, telegramSession.CodeVerifier)
}

func TestSessionMarshalRoundTrip(t *testing.T) {
	provider := New("client", "secret", "https://example.com/callback")
	session := &Session{AuthURL: "https://oauth.telegram.org/auth", CodeVerifier: "verifier", State: "state"}

	unmarshaled, err := provider.UnmarshalSession(session.Marshal())
	require.NoError(t, err)

	telegramSession := unmarshaled.(*Session)
	require.Equal(t, session.AuthURL, telegramSession.AuthURL)
	require.Equal(t, session.CodeVerifier, telegramSession.CodeVerifier)
	require.Equal(t, session.State, telegramSession.State)
}

func TestUserFromClaims(t *testing.T) {
	claims := jwt.MapClaims{
		"sub":                "telegram-subject",
		"id":                 int64(12345),
		"name":               "Telegram User",
		"preferred_username": "tguser",
		"picture":            "https://example.com/avatar.jpg",
	}

	user, err := userFromClaims(claims)
	require.NoError(t, err)

	require.Equal(t, "telegram", user.Provider)
	require.Equal(t, "telegram-subject", user.UserID)
	require.Equal(t, "Telegram User", user.Name)
	require.Equal(t, "tguser", user.NickName)
	require.Equal(t, "https://example.com/avatar.jpg", user.AvatarURL)
	require.Equal(t, "12345", user.RawData["telegram_id"])
	require.NotEmpty(t, user.RawData["raw_profile"])
}
