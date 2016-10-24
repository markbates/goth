package main

/* 
This example uses HTTPS + HSTS to secure the webserver. 
You can learn more about HTTPS and Golang here: 
https://blog.bracelab.com/achieving-perfect-ssl-labs-score-with-go
*/

import (
    "crypto/tls"
    "log"
    "net/http"
    "html/template"
    "os"
    "sort"
    "fmt"

    "github.com/gorilla/pat"
    "github.com/gorilla/sessions"
    "github.com/markbates/goth"
    "github.com/markbates/goth/gothic"
    "github.com/markbates/goth/providers/amazon"
    "github.com/markbates/goth/providers/bitbucket"
    "github.com/markbates/goth/providers/box"
    "github.com/markbates/goth/providers/dailymotion"
    "github.com/markbates/goth/providers/deezer"
    "github.com/markbates/goth/providers/digitalocean"
    "github.com/markbates/goth/providers/dropbox"
    "github.com/markbates/goth/providers/facebook"
    "github.com/markbates/goth/providers/fitbit"
    "github.com/markbates/goth/providers/github"
    "github.com/markbates/goth/providers/gitlab"
    "github.com/markbates/goth/providers/gplus"
    "github.com/markbates/goth/providers/heroku"
    "github.com/markbates/goth/providers/instagram"
    "github.com/markbates/goth/providers/intercom"
    "github.com/markbates/goth/providers/lastfm"
    "github.com/markbates/goth/providers/linkedin"
    "github.com/markbates/goth/providers/onedrive"
    "github.com/markbates/goth/providers/paypal"
    "github.com/markbates/goth/providers/salesforce"
    "github.com/markbates/goth/providers/slack"
    "github.com/markbates/goth/providers/soundcloud"
    "github.com/markbates/goth/providers/spotify"
    "github.com/markbates/goth/providers/steam"
    "github.com/markbates/goth/providers/stripe"
    "github.com/markbates/goth/providers/twitch"
    "github.com/markbates/goth/providers/twitter"
    "github.com/markbates/goth/providers/uber"
    "github.com/markbates/goth/providers/wepay"
    "github.com/markbates/goth/providers/yahoo"
    "github.com/markbates/goth/providers/yammer"
)

func init() {
    gothic.Store = sessions.NewFilesystemStore(os.TempDir(), []byte("goth-example"))
}

func main() {
    goth.UseProviders(
        twitter.New(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), "https://localhost/auth/twitter/callback"),
        // If you'd like to use authenticate instead of authorize in Twitter provider, use this instead.
        // twitter.NewAuthenticate(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), "https://localhost/auth/twitter/callback"),

        facebook.New(os.Getenv("FACEBOOK_KEY"), os.Getenv("FACEBOOK_SECRET"), "https://localhost/auth/facebook/callback"),
        fitbit.New(os.Getenv("FITBIT_KEY"), os.Getenv("FITBIT_SECRET"), "https://localhost/auth/fitbit/callback"),
        gplus.New(os.Getenv("GPLUS_KEY"), os.Getenv("GPLUS_SECRET"), "https://localhost/auth/gplus/callback"),
        github.New(os.Getenv("GITHUB_KEY"), os.Getenv("GITHUB_SECRET"), "https://localhost/auth/github/callback"),
        spotify.New(os.Getenv("SPOTIFY_KEY"), os.Getenv("SPOTIFY_SECRET"), "https://localhost/auth/spotify/callback"),
        linkedin.New(os.Getenv("LINKEDIN_KEY"), os.Getenv("LINKEDIN_SECRET"), "https://localhost/auth/linkedin/callback"),
        lastfm.New(os.Getenv("LASTFM_KEY"), os.Getenv("LASTFM_SECRET"), "https://localhost/auth/lastfm/callback"),
        twitch.New(os.Getenv("TWITCH_KEY"), os.Getenv("TWITCH_SECRET"), "https://localhost/auth/twitch/callback"),
        dropbox.New(os.Getenv("DROPBOX_KEY"), os.Getenv("DROPBOX_SECRET"), "https://localhost/auth/dropbox/callback"),
        digitalocean.New(os.Getenv("DIGITALOCEAN_KEY"), os.Getenv("DIGITALOCEAN_SECRET"), "https://localhost/auth/digitalocean/callback", "read"),
        bitbucket.New(os.Getenv("BITBUCKET_KEY"), os.Getenv("BITBUCKET_SECRET"), "https://localhost/auth/bitbucket/callback"),
        instagram.New(os.Getenv("INSTAGRAM_KEY"), os.Getenv("INSTAGRAM_SECRET"), "https://localhost/auth/instagram/callback"),
        intercom.New(os.Getenv("INTERCOM_KEY"), os.Getenv("INTERCOM_SECRET"), "https://localhost/auth/intercom/callback"),
        box.New(os.Getenv("BOX_KEY"), os.Getenv("BOX_SECRET"), "https://localhost/auth/box/callback"),
        salesforce.New(os.Getenv("SALESFORCE_KEY"), os.Getenv("SALESFORCE_SECRET"), "https://localhost/auth/salesforce/callback"),
        amazon.New(os.Getenv("AMAZON_KEY"), os.Getenv("AMAZON_SECRET"), "https://localhost/auth/amazon/callback"),
        yammer.New(os.Getenv("YAMMER_KEY"), os.Getenv("YAMMER_SECRET"), "https://localhost/auth/yammer/callback"),
        onedrive.New(os.Getenv("ONEDRIVE_KEY"), os.Getenv("ONEDRIVE_SECRET"), "https://localhost/auth/onedrive/callback"),

        //Pointed localhost.com to https://localhost/auth/yahoo/callback through proxy as yahoo
        // does not allow to put custom ports in redirection uri
        yahoo.New(os.Getenv("YAHOO_KEY"), os.Getenv("YAHOO_SECRET"), "http://localhost.com"),
        slack.New(os.Getenv("SLACK_KEY"), os.Getenv("SLACK_SECRET"), "https://localhost/auth/slack/callback"),
        stripe.New(os.Getenv("STRIPE_KEY"), os.Getenv("STRIPE_SECRET"), "https://localhost/auth/stripe/callback"),
        wepay.New(os.Getenv("WEPAY_KEY"), os.Getenv("WEPAY_SECRET"), "https://localhost/auth/wepay/callback", "view_user"),
        //By default paypal production auth urls will be used, please set PAYPAL_ENV=sandbox as environment variable for testing
        //in sandbox environment
        paypal.New(os.Getenv("PAYPAL_KEY"), os.Getenv("PAYPAL_SECRET"), "https://localhost/auth/paypal/callback"),
        steam.New(os.Getenv("STEAM_KEY"), "https://localhost/auth/steam/callback"),
        heroku.New(os.Getenv("HEROKU_KEY"), os.Getenv("HEROKU_SECRET"), "https://localhost/auth/heroku/callback"),
        uber.New(os.Getenv("UBER_KEY"), os.Getenv("UBER_SECRET"), "https://localhost/auth/uber/callback"),
        soundcloud.New(os.Getenv("SOUNDCLOUD_KEY"), os.Getenv("SOUNDCLOUD_SECRET"), "https://localhost/auth/soundcloud/callback"),
        gitlab.New(os.Getenv("GITLAB_KEY"), os.Getenv("GITLAB_SECRET"), "https://localhost/auth/gitlab/callback"),
        dailymotion.New(os.Getenv("DAILYMOTION_KEY"), os.Getenv("DAILYMOTION_SECRET"), "https://localhost/auth/dailymotion/callback", "email"),
        deezer.New(os.Getenv("DEEZER_KEY"), os.Getenv("DEEZER_SECRET"), "https://localhost/auth/deezer/callback", "email"),
    )

    m := make(map[string]string)
    m["amazon"] = "Amazon"
    m["bitbucket"] = "Bitbucket"
    m["box"] = "Box"
    m["dailymotion"] = "Dailymotion"
    m["deezer"] = "Deezer"
    m["digitalocean"] = "Digital Ocean"
    m["dropbox"] = "Dropbox"
    m["facebook"] = "Facebook"
    m["fitbit"] = "Fitbit"
    m["github"] = "Github"
    m["gitlab"] = "Gitlab"
    m["soundcloud"] = "SoundCloud"
    m["spotify"] = "Spotify"
    m["steam"] = "Steam"
    m["stripe"] = "Stripe"
    m["twitch"] = "Twitch"
    m["uber"] = "Uber"
    m["wepay"] = "Wepay"
    m["yahoo"] = "Yahoo"
    m["yammer"] = "Yammer"
    m["gplus"] = "Google Plus"
    m["heroku"] = "Heroku"
    m["instagram"] = "Instagram"
    m["intercom"] = "Intercom"
    m["lastfm"] = "Last FM"
    m["linkedin"] = "Linkedin"
    m["onedrive"] = "Onedrive"
    m["paypal"] = "Paypal"
    m["twitter"] = "Twitter"
    m["salesforce"] = "Salesforce"
    m["slack"] = "Slack"

    var keys []string
    for k := range m {
        keys = append(keys, k)
    }
    sort.Strings(keys)

    providerIndex := &ProviderIndex{Providers: keys, ProvidersMap: m}

    webhandler := pat.New()

    webhandler.Get("/auth/{provider}/callback", func(res http.ResponseWriter, req *http.Request) {
        user, err := gothic.CompleteUserAuth(res, req)
        if err != nil {
          fmt.Fprintln(res, err)
          return
        }
        t, _ := template.New("foo").Parse(userTemplate)
        t.Execute(res, user)
      })
      webhandler.Get("/auth/{provider}", gothic.BeginAuthHandler)
      webhandler.Get("/", func(res http.ResponseWriter, req *http.Request) {
        res.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains") // HSTS Header.
        t, _ := template.New("foo").Parse(indexTemplate)
        t.Execute(res, providerIndex)
    })

    cfg := &tls.Config{
        MinVersion:               tls.VersionTLS12,
        CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
        PreferServerCipherSuites: true,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
        },
    }

    srv := &http.Server{
        Addr:         ":443",
        Handler:      webhandler,
        TLSConfig:    cfg,
        TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
    }
    log.Fatal(srv.ListenAndServeTLS("server.crt", "server.key")) // You may need to be root to bind to port 443.
}

type ProviderIndex struct {
    Providers    []string
    ProvidersMap map[string]string
}

var indexTemplate = `{{range $key,$value:=.Providers}}
    <p><a href="/auth/{{$value}}">Log in with {{index $.ProvidersMap $value}}</a></p>
{{end}}`

var userTemplate = `
<p>Name: {{.Name}} [{{.LastName}}, {{.FirstName}}]</p>
<p>Email: {{.Email}}</p>
<p>NickName: {{.NickName}}</p>
<p>Location: {{.Location}}</p>
<p>AvatarURL: {{.AvatarURL}} <img src="{{.AvatarURL}}"></p>
<p>Description: {{.Description}}</p>
<p>UserID: {{.UserID}}</p>
<p>AccessToken: {{.AccessToken}}</p>
<p>ExpiresAt: {{.ExpiresAt}}</p>
<p>RefreshToken: {{.RefreshToken}}</p>
`
