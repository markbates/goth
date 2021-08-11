package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"sort"

	"github.com/gorilla/pat"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/amazon"
	"github.com/markbates/goth/providers/apple"
	"github.com/markbates/goth/providers/auth0"
	"github.com/markbates/goth/providers/azuread"
	"github.com/markbates/goth/providers/battlenet"
	"github.com/markbates/goth/providers/bitbucket"
	"github.com/markbates/goth/providers/box"
	"github.com/markbates/goth/providers/dailymotion"
	"github.com/markbates/goth/providers/deezer"
	"github.com/markbates/goth/providers/digitalocean"
	"github.com/markbates/goth/providers/discord"
	"github.com/markbates/goth/providers/dropbox"
	"github.com/markbates/goth/providers/eveonline"
	"github.com/markbates/goth/providers/facebook"
	"github.com/markbates/goth/providers/fitbit"
	"github.com/markbates/goth/providers/gitea"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/gitlab"
	"github.com/markbates/goth/providers/google"
	"github.com/markbates/goth/providers/gplus"
	"github.com/markbates/goth/providers/heroku"
	"github.com/markbates/goth/providers/instagram"
	"github.com/markbates/goth/providers/intercom"
	"github.com/markbates/goth/providers/kakao"
	"github.com/markbates/goth/providers/lastfm"
	"github.com/markbates/goth/providers/line"
	"github.com/markbates/goth/providers/linkedin"
	"github.com/markbates/goth/providers/mastodon"
	"github.com/markbates/goth/providers/meetup"
	"github.com/markbates/goth/providers/microsoftonline"
	"github.com/markbates/goth/providers/naver"
	"github.com/markbates/goth/providers/nextcloud"
	"github.com/markbates/goth/providers/okta"
	"github.com/markbates/goth/providers/onedrive"
	"github.com/markbates/goth/providers/openidConnect"
	"github.com/markbates/goth/providers/paypal"
	"github.com/markbates/goth/providers/salesforce"
	"github.com/markbates/goth/providers/seatalk"
	"github.com/markbates/goth/providers/shopify"
	"github.com/markbates/goth/providers/slack"
	"github.com/markbates/goth/providers/soundcloud"
	"github.com/markbates/goth/providers/spotify"
	"github.com/markbates/goth/providers/steam"
	"github.com/markbates/goth/providers/strava"
	"github.com/markbates/goth/providers/stripe"
	"github.com/markbates/goth/providers/twitch"
	"github.com/markbates/goth/providers/twitter"
	"github.com/markbates/goth/providers/typetalk"
	"github.com/markbates/goth/providers/uber"
	"github.com/markbates/goth/providers/vk"
	"github.com/markbates/goth/providers/wecom"
	"github.com/markbates/goth/providers/wepay"
	"github.com/markbates/goth/providers/xero"
	"github.com/markbates/goth/providers/yahoo"
	"github.com/markbates/goth/providers/yammer"
	"github.com/markbates/goth/providers/yandex"
)

func main() {
	goth.UseProviders(
		twitter.New(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), "http://localhost:3000/auth/twitter/callback"),
		// If you'd like to use authenticate instead of authorize in Twitter provider, use this instead.
		// twitter.NewAuthenticate(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), "http://localhost:3000/auth/twitter/callback"),

		facebook.New(os.Getenv("FACEBOOK_KEY"), os.Getenv("FACEBOOK_SECRET"), "http://localhost:3000/auth/facebook/callback"),
		fitbit.New(os.Getenv("FITBIT_KEY"), os.Getenv("FITBIT_SECRET"), "http://localhost:3000/auth/fitbit/callback"),
		google.New(os.Getenv("GOOGLE_KEY"), os.Getenv("GOOGLE_SECRET"), "http://localhost:3000/auth/google/callback"),
		gplus.New(os.Getenv("GPLUS_KEY"), os.Getenv("GPLUS_SECRET"), "http://localhost:3000/auth/gplus/callback"),
		github.New(os.Getenv("GITHUB_KEY"), os.Getenv("GITHUB_SECRET"), "http://localhost:3000/auth/github/callback"),
		spotify.New(os.Getenv("SPOTIFY_KEY"), os.Getenv("SPOTIFY_SECRET"), "http://localhost:3000/auth/spotify/callback"),
		linkedin.New(os.Getenv("LINKEDIN_KEY"), os.Getenv("LINKEDIN_SECRET"), "http://localhost:3000/auth/linkedin/callback"),
		line.New(os.Getenv("LINE_KEY"), os.Getenv("LINE_SECRET"), "http://localhost:3000/auth/line/callback", "profile", "openid", "email"),
		lastfm.New(os.Getenv("LASTFM_KEY"), os.Getenv("LASTFM_SECRET"), "http://localhost:3000/auth/lastfm/callback"),
		twitch.New(os.Getenv("TWITCH_KEY"), os.Getenv("TWITCH_SECRET"), "http://localhost:3000/auth/twitch/callback"),
		dropbox.New(os.Getenv("DROPBOX_KEY"), os.Getenv("DROPBOX_SECRET"), "http://localhost:3000/auth/dropbox/callback"),
		digitalocean.New(os.Getenv("DIGITALOCEAN_KEY"), os.Getenv("DIGITALOCEAN_SECRET"), "http://localhost:3000/auth/digitalocean/callback", "read"),
		bitbucket.New(os.Getenv("BITBUCKET_KEY"), os.Getenv("BITBUCKET_SECRET"), "http://localhost:3000/auth/bitbucket/callback"),
		instagram.New(os.Getenv("INSTAGRAM_KEY"), os.Getenv("INSTAGRAM_SECRET"), "http://localhost:3000/auth/instagram/callback"),
		intercom.New(os.Getenv("INTERCOM_KEY"), os.Getenv("INTERCOM_SECRET"), "http://localhost:3000/auth/intercom/callback"),
		box.New(os.Getenv("BOX_KEY"), os.Getenv("BOX_SECRET"), "http://localhost:3000/auth/box/callback"),
		salesforce.New(os.Getenv("SALESFORCE_KEY"), os.Getenv("SALESFORCE_SECRET"), "http://localhost:3000/auth/salesforce/callback"),
		seatalk.New(os.Getenv("SEATALK_KEY"), os.Getenv("SEATALK_SECRET"), "http://localhost:3000/auth/seatalk/callback"),
		amazon.New(os.Getenv("AMAZON_KEY"), os.Getenv("AMAZON_SECRET"), "http://localhost:3000/auth/amazon/callback"),
		yammer.New(os.Getenv("YAMMER_KEY"), os.Getenv("YAMMER_SECRET"), "http://localhost:3000/auth/yammer/callback"),
		onedrive.New(os.Getenv("ONEDRIVE_KEY"), os.Getenv("ONEDRIVE_SECRET"), "http://localhost:3000/auth/onedrive/callback"),
		azuread.New(os.Getenv("AZUREAD_KEY"), os.Getenv("AZUREAD_SECRET"), "http://localhost:3000/auth/azuread/callback", nil),
		microsoftonline.New(os.Getenv("MICROSOFTONLINE_KEY"), os.Getenv("MICROSOFTONLINE_SECRET"), "http://localhost:3000/auth/microsoftonline/callback"),
		battlenet.New(os.Getenv("BATTLENET_KEY"), os.Getenv("BATTLENET_SECRET"), "http://localhost:3000/auth/battlenet/callback"),
		eveonline.New(os.Getenv("EVEONLINE_KEY"), os.Getenv("EVEONLINE_SECRET"), "http://localhost:3000/auth/eveonline/callback"),
		kakao.New(os.Getenv("KAKAO_KEY"), os.Getenv("KAKAO_SECRET"), "http://localhost:3000/auth/kakao/callback"),

		//Pointed localhost.com to http://localhost:3000/auth/yahoo/callback through proxy as yahoo
		// does not allow to put custom ports in redirection uri
		yahoo.New(os.Getenv("YAHOO_KEY"), os.Getenv("YAHOO_SECRET"), "http://localhost.com"),
		typetalk.New(os.Getenv("TYPETALK_KEY"), os.Getenv("TYPETALK_SECRET"), "http://localhost:3000/auth/typetalk/callback", "my"),
		slack.New(os.Getenv("SLACK_KEY"), os.Getenv("SLACK_SECRET"), "http://localhost:3000/auth/slack/callback"),
		stripe.New(os.Getenv("STRIPE_KEY"), os.Getenv("STRIPE_SECRET"), "http://localhost:3000/auth/stripe/callback"),
		wepay.New(os.Getenv("WEPAY_KEY"), os.Getenv("WEPAY_SECRET"), "http://localhost:3000/auth/wepay/callback", "view_user"),
		//By default paypal production auth urls will be used, please set PAYPAL_ENV=sandbox as environment variable for testing
		//in sandbox environment
		paypal.New(os.Getenv("PAYPAL_KEY"), os.Getenv("PAYPAL_SECRET"), "http://localhost:3000/auth/paypal/callback"),
		steam.New(os.Getenv("STEAM_KEY"), "http://localhost:3000/auth/steam/callback"),
		heroku.New(os.Getenv("HEROKU_KEY"), os.Getenv("HEROKU_SECRET"), "http://localhost:3000/auth/heroku/callback"),
		uber.New(os.Getenv("UBER_KEY"), os.Getenv("UBER_SECRET"), "http://localhost:3000/auth/uber/callback"),
		soundcloud.New(os.Getenv("SOUNDCLOUD_KEY"), os.Getenv("SOUNDCLOUD_SECRET"), "http://localhost:3000/auth/soundcloud/callback"),
		gitlab.New(os.Getenv("GITLAB_KEY"), os.Getenv("GITLAB_SECRET"), "http://localhost:3000/auth/gitlab/callback"),
		dailymotion.New(os.Getenv("DAILYMOTION_KEY"), os.Getenv("DAILYMOTION_SECRET"), "http://localhost:3000/auth/dailymotion/callback", "email"),
		deezer.New(os.Getenv("DEEZER_KEY"), os.Getenv("DEEZER_SECRET"), "http://localhost:3000/auth/deezer/callback", "email"),
		discord.New(os.Getenv("DISCORD_KEY"), os.Getenv("DISCORD_SECRET"), "http://localhost:3000/auth/discord/callback", discord.ScopeIdentify, discord.ScopeEmail),
		meetup.New(os.Getenv("MEETUP_KEY"), os.Getenv("MEETUP_SECRET"), "http://localhost:3000/auth/meetup/callback"),

		//Auth0 allocates domain per customer, a domain must be provided for auth0 to work
		auth0.New(os.Getenv("AUTH0_KEY"), os.Getenv("AUTH0_SECRET"), "http://localhost:3000/auth/auth0/callback", os.Getenv("AUTH0_DOMAIN")),
		xero.New(os.Getenv("XERO_KEY"), os.Getenv("XERO_SECRET"), "http://localhost:3000/auth/xero/callback"),
		vk.New(os.Getenv("VK_KEY"), os.Getenv("VK_SECRET"), "http://localhost:3000/auth/vk/callback"),
		naver.New(os.Getenv("NAVER_KEY"), os.Getenv("NAVER_SECRET"), "http://localhost:3000/auth/naver/callback"),
		yandex.New(os.Getenv("YANDEX_KEY"), os.Getenv("YANDEX_SECRET"), "http://localhost:3000/auth/yandex/callback"),
		nextcloud.NewCustomisedDNS(os.Getenv("NEXTCLOUD_KEY"), os.Getenv("NEXTCLOUD_SECRET"), "http://localhost:3000/auth/nextcloud/callback", os.Getenv("NEXTCLOUD_URL")),
		gitea.New(os.Getenv("GITEA_KEY"), os.Getenv("GITEA_SECRET"), "http://localhost:3000/auth/gitea/callback"),
		shopify.New(os.Getenv("SHOPIFY_KEY"), os.Getenv("SHOPIFY_SECRET"), "http://localhost:3000/auth/shopify/callback", shopify.ScopeReadCustomers, shopify.ScopeReadOrders),
		apple.New(os.Getenv("APPLE_KEY"), os.Getenv("APPLE_SECRET"), "http://localhost:3000/auth/apple/callback", nil, apple.ScopeName, apple.ScopeEmail),
		strava.New(os.Getenv("STRAVA_KEY"), os.Getenv("STRAVA_SECRET"), "http://localhost:3000/auth/strava/callback"),
		okta.New(os.Getenv("OKTA_ID"), os.Getenv("OKTA_SECRET"), os.Getenv("OKTA_ORG_URL"), "http://localhost:3000/auth/okta/callback", "openid", "profile", "email"),
		mastodon.New(os.Getenv("MASTODON_KEY"), os.Getenv("MASTODON_SECRET"), "http://localhost:3000/auth/mastodon/callback", "read:accounts"),
		wecom.New(os.Getenv("WECOM_CORP_ID"), os.Getenv("WECOM_SECRET"), os.Getenv("WECOM_AGENT_ID"), "http://localhost:3000/auth/wecom/callback"),
	)

	// OpenID Connect is based on OpenID Connect Auto Discovery URL (https://openid.net/specs/openid-connect-discovery-1_0-17.html)
	// because the OpenID Connect provider initialize it self in the New(), it can return an error which should be handled or ignored
	// ignore the error for now
	openidConnect, _ := openidConnect.New(os.Getenv("OPENID_CONNECT_KEY"), os.Getenv("OPENID_CONNECT_SECRET"), "http://localhost:3000/auth/openid-connect/callback", os.Getenv("OPENID_CONNECT_DISCOVERY_URL"))
	if openidConnect != nil {
		goth.UseProviders(openidConnect)
	}

	m := make(map[string]string)
	m["amazon"] = "Amazon"
	m["bitbucket"] = "Bitbucket"
	m["box"] = "Box"
	m["dailymotion"] = "Dailymotion"
	m["deezer"] = "Deezer"
	m["digitalocean"] = "Digital Ocean"
	m["discord"] = "Discord"
	m["dropbox"] = "Dropbox"
	m["eveonline"] = "Eve Online"
	m["facebook"] = "Facebook"
	m["fitbit"] = "Fitbit"
	m["gitea"] = "Gitea"
	m["github"] = "Github"
	m["gitlab"] = "Gitlab"
	m["google"] = "Google"
	m["gplus"] = "Google Plus"
	m["shopify"] = "Shopify"
	m["soundcloud"] = "SoundCloud"
	m["spotify"] = "Spotify"
	m["steam"] = "Steam"
	m["stripe"] = "Stripe"
	m["twitch"] = "Twitch"
	m["uber"] = "Uber"
	m["wepay"] = "Wepay"
	m["yahoo"] = "Yahoo"
	m["yammer"] = "Yammer"
	m["heroku"] = "Heroku"
	m["instagram"] = "Instagram"
	m["intercom"] = "Intercom"
	m["kakao"] = "Kakao"
	m["lastfm"] = "Last FM"
	m["linkedin"] = "Linkedin"
	m["line"] = "LINE"
	m["onedrive"] = "Onedrive"
	m["azuread"] = "Azure AD"
	m["microsoftonline"] = "Microsoft Online"
	m["battlenet"] = "Battlenet"
	m["paypal"] = "Paypal"
	m["twitter"] = "Twitter"
	m["salesforce"] = "Salesforce"
	m["typetalk"] = "Typetalk"
	m["slack"] = "Slack"
	m["meetup"] = "Meetup.com"
	m["auth0"] = "Auth0"
	m["openid-connect"] = "OpenID Connect"
	m["xero"] = "Xero"
	m["vk"] = "VK"
	m["naver"] = "Naver"
	m["yandex"] = "Yandex"
	m["nextcloud"] = "NextCloud"
	m["seatalk"] = "SeaTalk"
	m["apple"] = "Apple"
	m["strava"] = "Strava"
	m["okta"] = "Okta"
	m["mastodon"] = "Mastodon"
	m["wecom"] = "WeCom"

	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	providerIndex := &ProviderIndex{Providers: keys, ProvidersMap: m}

	p := pat.New()
	p.Get("/auth/{provider}/callback", func(res http.ResponseWriter, req *http.Request) {

		user, err := gothic.CompleteUserAuth(res, req)
		if err != nil {
			fmt.Fprintln(res, err)
			return
		}
		t, _ := template.New("foo").Parse(userTemplate)
		t.Execute(res, user)
	})

	p.Get("/logout/{provider}", func(res http.ResponseWriter, req *http.Request) {
		gothic.Logout(res, req)
		res.Header().Set("Location", "/")
		res.WriteHeader(http.StatusTemporaryRedirect)
	})

	p.Get("/auth/{provider}", func(res http.ResponseWriter, req *http.Request) {
		// try to get the user without re-authenticating
		if gothUser, err := gothic.CompleteUserAuth(res, req); err == nil {
			t, _ := template.New("foo").Parse(userTemplate)
			t.Execute(res, gothUser)
		} else {
			gothic.BeginAuthHandler(res, req)
		}
	})

	p.Get("/", func(res http.ResponseWriter, req *http.Request) {
		t, _ := template.New("foo").Parse(indexTemplate)
		t.Execute(res, providerIndex)
	})

	log.Println("listening on localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", p))
}

type ProviderIndex struct {
	Providers    []string
	ProvidersMap map[string]string
}

var indexTemplate = `{{range $key,$value:=.Providers}}
    <p><a href="/auth/{{$value}}">Log in with {{index $.ProvidersMap $value}}</a></p>
{{end}}`

var userTemplate = `
<p><a href="/logout/{{.Provider}}">logout</a></p>
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
