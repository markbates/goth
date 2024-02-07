package reddit

import (
	"encoding/json"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

var response = redditResponse{
	Id:   "invader21",
	Name: "JohnDoe",
}

func TestProvider(t *testing.T) {
	t.Run("create a new provider", func(t *testing.T) {
		got := New("client id", "client secret", "redirect uri", "duration", "example.com", "userURL", "scope1", "scope2", "scope 3")
		want := Provider{
			providerName: "reddit",
			duration:     "duration",
			config: oauth2.Config{
				ClientID:     "client id",
				ClientSecret: "client secret",
				Endpoint: oauth2.Endpoint{
					AuthURL:   authURL,
					TokenURL:  "example.com",
					AuthStyle: 0,
				},
				RedirectURL: "redirect uri",
				Scopes:      []string{"scope1", "scope2", "scope 3"},
			},
			userURL: "userURL",
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("\033[31;1;4mgot\033[0m %+v, \n\t \033[31;1;4mwant\033[0m %+v", got, want)
		}
	})

	t.Run("fetch reddit user that created the given session", func(t *testing.T) {
		redditServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			b, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			writer.Header().Add("Content-Type", "application/json")
			writer.Write(b)
		}))

		defer redditServer.Close()

		userURL := redditServer.URL
		p := New("client id", "client secret", "redirect uri", "duration", "example.com", userURL, "scope1", "scope2", "scope 3")
		s := &Session{
			AuthURL:      "",
			AccessToken:  "i am a token",
			TokenType:    "bearer",
			RefreshToken: "your refresh token",
			Expiry:       time.Time{},
		}

		got, err := p.FetchUser(s)
		if err != nil {
			t.Errorf("did not expect an error: %s", err)
		}

		want := goth.User{
			RawData: map[string]interface{}{
				"id":   "invader21",
				"name": "JohnDoe",
			},
			Provider:     "reddit",
			Name:         "JohnDoe",
			UserID:       "invader21",
			AccessToken:  "i am a token",
			RefreshToken: "your refresh token",
			ExpiresAt:    time.Time{},
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("\033[31;1;4mgot\033[0m %+v, \n\t\t \033[31;1;4mwant\033[0m %+v", got, want)
		}
	})
}
