package direct_test

import (
	"encoding/json"
	"testing"

	"github.com/markbates/goth/providers/direct"
)

func TestDirectSession(t *testing.T) {
	t.Run("Marshal", func(t *testing.T) {
		session := &direct.DirectSession{
			AccessToken: "1234567890",
			Email:       "test@mail.com",
			AuthURL:     "/login",
		}
		marshaled := session.Marshal()

		var unmarshaled direct.DirectSession
		err := json.Unmarshal([]byte(marshaled), &unmarshaled)

		if err != nil {
			t.Errorf("unexpected error when unmarshaling session data: %v", err)
		}

		if unmarshaled.AccessToken != session.AccessToken {
			t.Errorf("expected access token to be '%s', got '%s'", session.AccessToken, unmarshaled.AccessToken)
		}

		if unmarshaled.Email != session.Email {
			t.Errorf("expected email to be '%s', got '%s'", session.Email, unmarshaled.Email)
		}

		if unmarshaled.AuthURL != session.AuthURL {
			t.Errorf("expected auth url to be '%s', got '%s'", session.AuthURL, unmarshaled.AuthURL)
		}
	})

	t.Run("GetAuthURL", func(t *testing.T) {
		session := &direct.DirectSession{
			AuthURL: "/",
		}

		url, err := session.GetAuthURL()
		if err != nil {
			t.Error("unexpected error when calling GetAuthURL")
		}

		if url != "/" {
			t.Errorf("expected auth url to be '/', got '%s'", url)
		}
	})
}
