package discord

import (
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
)

func provider() *Provider {
	return New(os.Getenv("DISCORD_KEY"),
		os.Getenv("DISCORD_SECRET"), "/foo", "user")
}

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("DISCORD_KEY"))
	a.Equal(p.Secret, os.Getenv("DISCORD_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_ImplementsProvider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), provider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.BeginAuth("test_state")
	s := session.(*Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "discord.com/api/oauth2/authorize")
}

func Test_DefaultScopeAlwaysIncludesIdentify(t *testing.T) {
	// Regression test for #414: passing any custom scope (e.g. only "email")
	// used to drop ScopeIdentify from the OAuth2 config, which caused Discord
	// to return 401 on /users/@me — so FetchUser failed for everyone who
	// hadn't explicitly listed "identify". ScopeIdentify must always be in
	// the scope list, and never duplicated when the caller passes it.
	t.Parallel()
	a := assert.New(t)

	cases := []struct {
		name   string
		scopes []string
		want   []string
	}{
		{
			name:   "no scopes",
			scopes: nil,
			want:   []string{ScopeIdentify},
		},
		{
			name:   "email only",
			scopes: []string{ScopeEmail},
			want:   []string{ScopeIdentify, ScopeEmail},
		},
		{
			name:   "identify explicit (no dupe)",
			scopes: []string{ScopeIdentify, ScopeEmail},
			want:   []string{ScopeIdentify, ScopeEmail},
		},
		{
			name:   "multiple custom",
			scopes: []string{ScopeEmail, ScopeConnections, ScopeGuilds},
			want:   []string{ScopeIdentify, ScopeEmail, ScopeConnections, ScopeGuilds},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := New("k", "s", "/cb", tc.scopes...)
			a.Equal(tc.want, p.config.Scopes, tc.name)
		})
	}
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://discord.com/api/oauth2/authorize", "AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*Session)
	a.Equal(s.AuthURL, "https://discord.com/api/oauth2/authorize")
	a.Equal(s.AccessToken, "1234567890")
}
