# Goth: Multi-Provider Authentication for Go [![GoDoc](https://godoc.org/github.com/markbates/goth?status.svg)](https://godoc.org/github.com/markbates/goth) [![Build Status](https://github.com/markbates/goth/workflows/ci/badge.svg)](https://github.com/markbates/goth/actions) [![Go Report Card](https://goreportcard.com/badge/github.com/markbates/goth)](https://goreportcard.com/report/github.com/markbates/goth)

Package goth provides a simple, clean, and idiomatic way to write authentication
packages for Go web applications.

Unlike other similar packages, Goth, lets you write OAuth, OAuth2, or any other
protocol providers, as long as they implement the [Provider](https://github.com/markbates/goth/blob/master/provider.go#L13-L22) and [Session](https://github.com/markbates/goth/blob/master/session.go#L13-L21) interfaces.

This package was inspired by [https://github.com/intridea/omniauth](https://github.com/intridea/omniauth).

## Installation

Paste the following command in the terminal

```text
go get github.com/markbates/goth
```

## Supported Providers

- Amazon
- Apple
- Auth0
- Azure AD
- Battle.net
- Bitbucket
- Box
- ClassLink
- Cloud Foundry
- Dailymotion
- Deezer
- DigitalOcean
- Discord
- Dropbox
- Eve Online
- Facebook
- Fitbit
- Gitea
- GitHub
- Gitlab
- Google
- Google+ (deprecated)
- Heroku
- InfluxCloud
- Instagram
- Intercom
- Kakao
- Lastfm
- LINE
- Linkedin
- Mailru
- Meetup
- MicrosoftOnline
- Naver
- Nextcloud
- Okta
- OneDrive
- OpenID Connect (auto discovery)
- Oura
- Patreon
- Paypal
- Reddit
- SalesForce
- Shopify
- Slack
- Soundcloud
- Spotify
- Steam
- Strava
- Stripe
- TikTok
- Tumblr
- Twitch
- Twitter
- Typetalk
- Uber
- VK
- WeCom
- Wepay
- Xero
- Yahoo
- Yammer
- Yandex
- Zoom

## Examples

See the [examples](examples) folder for a working application that lets users authenticate
through Twitter, Facebook, Google Plus etc.

To run the example use either of the methods below ::

1. Clone the source from GitHub - (Copy and paste the following command block into your terminal.)
   ```text
   git clone git@github.com:markbates/goth.git
   cd goth/examples
   go get -v
   go build
   ./examples
   ```

or use

2. Get the repository as a dependency - (Copy and paste the following command block into your terminal.)
   ```text
   go get github.com/markbates/goth
   cd $GOPATH/pkg/mod/github.com/markbates/goth@v1.80.0/examples
   go get -v
   go build
   ./examples
   ```
   Note: The second command navigates to the appropriate `/examples` directory. Note that the specific version of Goth (`goth@v1.80.0`) in the directory path may change in the future, requiring an update to the command accordingly.

Now open up your browser and go to [http://localhost:3000](http://localhost:3000) to see the example.

Most likely error screen will appear for most of the options when clicked on. To actually use the different providers, please make sure you set environment variables before running the built Go program (example.exe in this case).

Environment variables can be set using following command in the terminal

```text
export key=value
```

For example, To enable Google Sign-in, set the environment variables `GOOGLE_KEY` and `GOOGLE_SECRET` to their corresponding values. Obtain these credentials from Google Cloud Console.

```text
export GOOGLE_KEY=your_google_client_id
export GOOGLE_SECRET=your_google_secret_key
```

## Security Notes

By default, gothic uses a `CookieStore` from the `gorilla/sessions` package to store session data.

As configured, this default store (`gothic.Store`) will generate cookies with `Options`:

```go
&Options{
   Path:   "/",
   Domain: "",
   MaxAge: 86400 * 30,
   HttpOnly: true,
   Secure: false,
 }
```

To tailor these fields for your application, you can override the `gothic.Store` variable at startup.

The following snippet shows one way to do this:

```go
key := ""             // Replace with your SESSION_SECRET or similar
maxAge := 86400 * 30  // 30 days
isProd := false       // Set to true when serving over https

store := sessions.NewCookieStore([]byte(key))
store.MaxAge(maxAge)
store.Options.Path = "/"
store.Options.HttpOnly = true   // HttpOnly should always be enabled
store.Options.Secure = isProd

gothic.Store = store
```

## Issues

Issues always stand a significantly better chance of getting fixed if they are accompanied by a
pull request.

## Contributing

Would I love to see more providers? Certainly! Would you love to contribute one? Hopefully, yes!

1. Fork it
2. Create your feature branch (git checkout -b my-new-feature)
3. Write Tests!
4. Make sure the codebase adhere to the Go coding standards by executing `gofmt -s -w ./`
5. Commit your changes (git commit -am 'Add some feature')
6. Push to the branch (git push origin my-new-feature)
7. Create new Pull Request
