package reddit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

var validAuthResponseTestData = struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
}{
	AccessToken:  "i am a token",
	TokenType:    "type",
	ExpiresIn:    120,
	Scope:        "identity",
	RefreshToken: "your refresh token",
}

var invalidAuthResponseTestData = struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
}{
	AccessToken:  "",
	TokenType:    "type",
	ExpiresIn:    120,
	Scope:        "identity",
	RefreshToken: "Your refresh token",
}

func TestSession(t *testing.T) {
	t.Run("gets the URL for the authentication end-point for the provider", func(t *testing.T) {
		s := Session{AuthURL: "example.com"}
		got, err := s.GetAuthURL()
		if err != nil {
			t.Fatal("should return a url string")
		}

		want := "example.com"

		if got != want {
			t.Errorf("got %q want %q", got, want)
		}
	})

	t.Run("generates a string representation of the session", func(t *testing.T) {
		s := Session{
			AuthURL: "example",
		}
		got := s.Marshal()
		want := `{"AuthURL":"example","access_token":"","expiry":"0001-01-01T00:00:00Z"}`

		if got != want {
			t.Errorf("got %q want %q", got, want)
		}
	})

	t.Run("return an access token", func(t *testing.T) {

		s := Session{AuthURL: "example.com"}
		authServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			b, err := json.Marshal(validAuthResponseTestData)
			if err != nil {
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			writer.Write(b)
		}))

		tokenURL := authServer.URL

		p := New("CLIENT_ID", "CLIENT_SECRET", "URI", "DURATION", tokenURL, "SCOPE_STRING1", "SCOPE_STRING2")
		u := url.Values{}
		u.Set("code", "12345678")

		got, err := s.Authorize(&p, u)
		if err != nil {
			t.Fatal("did not expect an error: ", err)
		}

		want := validAuthResponseTestData.AccessToken

		if got != want {
			t.Errorf("got %q want %q", got, want)
		}
	})

	t.Run("validates access token", func(t *testing.T) {
		s := Session{AuthURL: "example.com"}
		authServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			b, err := json.Marshal(invalidAuthResponseTestData)
			if err != nil {
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			writer.Write(b)
		}))

		tokenURL := authServer.URL

		p := New("CLIENT_ID", "CLIENT_SECRET", "URI", "DURATION", tokenURL, "SCOPE_STRING1", "SCOPE_STRING2")
		u := url.Values{}
		u.Set("code", "12345678")

		_, err := s.Authorize(&p, u)
		if err == nil {
			t.Errorf("expected an error but didn't get one")
		}
	})
}
