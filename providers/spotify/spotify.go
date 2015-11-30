// Package spotify implements the OAuth protocol for authenticating users through Spotify.
// This package can be used as a reference implementation of an OAuth provider for Goth.
package spotify

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/smagic39/goth"
	"golang.org/x/oauth2"
)

const (
	authURL      = "https://accounts.spotify.com/authorize"
	tokenURL     = "https://accounts.spotify.com/api/token"
	userEndpoint = "https://api.spotify.com/v1/me"
)

const (
	// ScopePlaylistReadPrivate seeks permission to read
	// a user's private playlists.
	ScopePlaylistReadPrivate = "playlist-read-private"
	// ScopePlaylistModifyPublic seeks write access
	// to a user's public playlists.
	ScopePlaylistModifyPublic = "playlist-modify-public"
	// ScopePlaylistModifyPrivate seeks write access to
	// a user's private playlists.
	ScopePlaylistModifyPrivate = "playlist-modify-private"
	// ScopeUserFollowModify seeks write/delete access to
	// the list of artists and other users that a user follows.
	ScopeUserFollowModify = "user-follow-modify"
	// ScopeUserFollowRead seeks read access to the list of
	// artists and other users that a user follows.
	ScopeUserFollowRead = "user-follow-read"
	// ScopeUserLibraryModify seeks write/delete acess to a
	// user's "Your Music" library.
	ScopeUserLibraryModify = "user-library-modify"
	// ScopeUserLibraryRead seeks read access to a user's
	// "Your Music" library.
	ScopeUserLibraryRead = "user-library-read"
	// ScopeUserReadPrivate seeks read access to a user's
	// subsription details (type of user account)
	ScopeUserReadPrivate = "user-read-private"
	// ScopeUserReadEmail seeks read access to a user's
	// email address.
	ScopeUserReadEmail = "user-read-email"
)

// New creates a new Spotify provider and sets up important connection details.
// You should always call `spotify.New` to get a new Provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Spotify.
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	config      *oauth2.Config
}

// Name gets the name used to retrieve this provider.
func (p *Provider) Name() string {
	return "spotify"
}

// Debug is a no-op for the spotify package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Spotify for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will go to Spotify and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	user := goth.User{
		AccessToken: s.AccessToken,
		Provider:    p.Name(),
	}

	req, err := http.NewRequest("GET", userEndpoint, nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return user, err
	}
	defer resp.Body.Close()
	//err = userFromReader(io.TeeReader(resp.Body, os.Stdout), &user)
	err = userFromReader(resp.Body, &user)
	return user, err
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := Session{}
	err := json.Unmarshal([]byte(data), &s)
	return &s, err
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		Country     string `json:"country"`
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
		ID          string `json:"id"`
		Images      []struct {
			URL string `json:"url"`
		} `json:"images"`
	}{}

	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}

	user.Name = u.DisplayName
	user.Email = u.Email
	user.UserID = u.ID
	user.Location = u.Country
	if len(u.Images) > 0 {
		user.AvatarURL = u.Images[0].URL
	}
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
		Scopes: []string{ScopeUserReadEmail, ScopeUserReadPrivate},
	}
	return c
}
