package direct_test

import (
	"errors"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/direct"
)

func TestDirectProvider(t *testing.T) {
	p := direct.New("/login")

	users := map[string]goth.User{
		"123": {
			Email: "test@example.com",
		},
	}

	p.AccessTokenGenerator = func() string {
		return "123"
	}
	p.FetchUserByToken = func(token string) (goth.User, error) {
		if user, ok := users[token]; ok {
			return user, nil
		}
		return goth.User{}, errors.New("user not found")
	}
	p.CredChecker = func(email, password string) error {
		if email == "test@example.com" && password == "password" {
			return nil
		}
		return errors.New("invalid email or password")
	}

	t.Run("Name", func(t *testing.T) {
		if p.Name() != "direct" {
			t.Errorf("expected provider name to be 'direct', got %s", p.Name())
		}
	})

	t.Run("SetName", func(t *testing.T) {
		p.SetName("direct_custom")
		if p.Name() != "direct_custom" {
			t.Errorf("expected provider name to be 'direct_custom', got %s", p.Name())
		}
	})

	t.Run("IssueSession", func(t *testing.T) {
		_, err := p.IssueSession("test@example.com", "password")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		_, err = p.IssueSession("test@example.com", "wrong_password")
		if err == nil {
			t.Error("expected error for invalid password, got nil")
		}

		_, err = p.IssueSession("nonexistent@example.com", "password")
		if err == nil {
			t.Error("expected error for non-existent user, got nil")
		}
	})

	t.Run("FetchUser", func(t *testing.T) {
		session, _ := p.IssueSession("test@example.com", "password")

		user, err := p.FetchUser(session)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if user.Email != "test@example.com" {
			t.Errorf("expected email to be 'test@example.com', got %s", user.Email)
		}
	})

	t.Run("UnmarshalSession", func(t *testing.T) {
		session, _ := p.IssueSession("test@example.com", "password")
		data := session.Marshal()

		unmarshalledSession, err := p.UnmarshalSession(data)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Check if the unmarshalled session is the same as the original session
		if session.Marshal() != unmarshalledSession.Marshal() {
			t.Error("unmarshalled session data does not match the original session data")
		}
	})
}
