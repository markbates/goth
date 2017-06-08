package main

import (
  "os"
  "fmt"
  "net/http"

  "github.com/go-martini/martini"
  "github.com/markbates/goth"
  "github.com/markbates/goth/gothic"
  "github.com/markbates/goth/providers/facebook"
)

func main() {
  goth.UseProviders(
    facebook.New(os.Getenv("FACEBOOK_KEY"), os.Getenv("FACEBOOK_SECRET"), "http://localhost:3000/auth/callback?provider=facebook"),
  )

  // instantiate Martini
  m := martini.Classic()

  m.Get("/", func() string {
    return "Hello world!"
  })

  m.Get("/auth/callback", func(res http.ResponseWriter, req *http.Request) string {
    user, err := gothic.CompleteUserAuth(res, req)
    if err != nil {
      return "something went wrong"
    }
    return fmt.Sprintf("Logged in as %s!", user.Name)
  })

  m.Get("/auth", gothic.BeginAuthHandler)

  m.Run()
}
