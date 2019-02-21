package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/markbates/goth/providers/twitter"
	"html/template"
	"net/http"
	"os"

	"sort"

	"log"

	"github.com/gin-gonic/gin"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
)

func init() {
	gothic.GetProviderName = func(req *http.Request) (string, error) {
		provider, ok := req.Context().Value("provider").(string)
		if !ok {
			return "", errors.New("error")
		}
		return provider, nil
	}
}

func main() {
	goth.UseProviders(
		twitter.New(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), "http://localhost:3000/auth/twitter/callback"),
	)

	m := make(map[string]string)
	m["twitter"] = "Twitter"

	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	providerIndex := &ProviderIndex{Providers: keys, ProvidersMap: m}

	r := gin.Default()

	r.GET("/auth/:provider/callback", func(c *gin.Context) {
		provider := c.Param("provider")
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), "provider", provider))

		user, err := gothic.CompleteUserAuth(c.Writer, c.Request)
		if err != nil {
			fmt.Fprintln(c.Writer, err)
			return
		}
		t, _ := template.New("foo").Parse(userTemplate)
		t.Execute(c.Writer, user)
	})

	r.GET("/logout/:provider", func(c *gin.Context) {
		gothic.Logout(c.Writer, c.Request)
		c.Redirect(http.StatusTemporaryRedirect, "/")
	})

	r.GET("/auth/:provider", func(c *gin.Context) {
		provider := c.Param("provider")
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), "provider", provider))

		// try to get the user without re-authenticating
		if gothUser, err := gothic.CompleteUserAuth(c.Writer, c.Request); err == nil {
			t, _ := template.New("foo").Parse(userTemplate)
			t.Execute(c.Writer, gothUser)
		} else {
			gothic.BeginAuthHandler(c.Writer, c.Request)
		}
	})

	r.GET("/", func(c *gin.Context) {
		t, _ := template.New("foo").Parse(indexTemplate)
		t.Execute(c.Writer, providerIndex)
	})

	log.Fatal(r.Run(":3000"))
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
