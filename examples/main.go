package main

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"github.com/julienschmidt/httprouter"
	"github.com/smagic39/goth"
	"github.com/smagic39/goth/gothic"
	"github.com/smagic39/goth/providers/digitalocean"
	"github.com/smagic39/goth/providers/dropbox"
	"github.com/smagic39/goth/providers/facebook"
	"github.com/smagic39/goth/providers/github"
	"github.com/smagic39/goth/providers/gplus"
	"github.com/smagic39/goth/providers/lastfm"
	"github.com/smagic39/goth/providers/linkedin"
	"github.com/smagic39/goth/providers/spotify"
	"github.com/smagic39/goth/providers/twitch"
	"github.com/smagic39/goth/providers/twitter"

)

func main() {
	goth.UseProviders(
		twitter.New(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), "http://localhost:1337/user/auth/twitter/callback"),
		// If you'd like to use user/authenticate instead of user/authorize in Twitter provider, use this instead.
		// twitter.Newuser/Authenticate(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), "http://localhost:1337/user/auth/twitter/callback"),

		facebook.New(os.Getenv("FACEBOOK_KEY"), os.Getenv("FACEBOOK_SECRET"), "http://localhost:1337/user/auth/facebook/callback"),
		gplus.New(os.Getenv("GPLUS_KEY"), os.Getenv("GPLUS_SECRET"), "http://localhost:1337/user/auth/gplus/callback"),
		github.New(os.Getenv("GITHUB_KEY"), os.Getenv("GITHUB_SECRET"), "http://localhost:1337/user/auth/github/callback"),
		spotify.New(os.Getenv("SPOTIFY_KEY"), os.Getenv("SPOTIFY_SECRET"), "http://localhost:1337/user/auth/spotify/callback"),
		linkedin.New(os.Getenv("LINKEDIN_KEY"), os.Getenv("LINKEDIN_SECRET"), "http://localhost:1337/user/auth/linkedin/callback"),
		lastfm.New(os.Getenv("LASTFM_KEY"), os.Getenv("LASTFM_SECRET"), "http://localhost:1337/user/auth/lastfm/callback"),
		twitch.New(os.Getenv("TWITCH_KEY"), os.Getenv("TWITCH_SECRET"), "http://localhost:1337/user/auth/twitch/callback"),
		dropbox.New(os.Getenv("DROPBOX_KEY"), os.Getenv("DROPBOX_SECRET"), "http://localhost:1337/user/auth/dropbox/callback"),
		digitalocean.New(os.Getenv("DIGITALOCEAN_KEY"), os.Getenv("DIGITALOCEAN_SECRET"), "http://localhost:1337/user/auth/digitalocean/callback", "read"),
	)

	// Assign the GetState function variable so we can return the
	// state string we want to get back at the end of the ouser/auth process.
	// Only works with facebook and gplus providers.

	r := httprouter.New()
	r.GET("/user/auth/:provider/callback", func(res http.ResponseWriter, req *http.Request, p httprouter.Params) {

		// print our state string to the console

		user, err := gothic.CompleteUserAuth(res, req, p)
		if err != nil {
			fmt.Fprintln(res, err)
			return
		}
		t, _ := template.New("foo").Parse(userTemplate)
		t.Execute(res, user)
	})

	r.GET("/user/auth/:provider", gothic.Beginuser/AuthHandler)
	r.GET("/", func(res http.ResponseWriter, req *http.Request, p httprouter.Params) {
		t, _ := template.New("foo").Parse(indexTemplate)
		t.Execute(res, nil)
	})
	http.ListenAndServe(":1337", r)
}

var indexTemplate = `
<p><a href="/user/auth/twitter">Log in with Twitter</a></p>
<p><a href="/user/auth/facebook">Log in with Facebook</a></p>
<p><a href="/user/auth/gplus">Log in with GPlus</a></p>
<p><a href="/user/auth/github">Log in with Github</a></p>
<p><a href="/user/auth/spotify">Log in with Spotify</a></p>
<p><a href="/user/auth/lastfm">Log in with LastFM</a></p>
<p><a href="/user/auth/twitch">Log in with Twitch</a></p>
<p><a href="/user/auth/dropbox">Log in with Dropbox</a></p>
<p><a href="/user/auth/digitalocean">Log in with DigitalOcean</a></p>
`

var userTemplate = `
<p>Name: {{.Name}}</p>
<p>Email: {{.Email}}</p>
<p>NickName: {{.NickName}}</p>
<p>Location: {{.Location}}</p>
<p>AvatarURL: {{.AvatarURL}} <img src="{{.AvatarURL}}"></p>
<p>Description: {{.Description}}</p>
<p>UserID: {{.UserID}}</p>
<p>AccessToken: {{.AccessToken}}</p>
`
