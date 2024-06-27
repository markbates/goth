package apple

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/Avyukth/goth"
)

func Test_Implements_Session(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &Session{}

	a.Implements((*goth.Session)(nil), s)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/foo"

	url, _ := s.GetAuthURL()
	a.Equal(url, "/foo")
}

func Test_ToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &Session{}

	data := s.Marshal()
	a.Equal(data, `{"AuthURL":"","AccessToken":"","RefreshToken":"","ExpiresAt":"0001-01-01T00:00:00Z","sub":"","email":"","is_private_email":false,"email_verified":false}`)
}

func Test_String(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &Session{}

	a.Equal(s.String(), s.Marshal())
}

func TestIDTokenClaimsUnmarshal(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	cases := []struct {
		name           string
		idToken        string
		expectedClaims IDTokenClaims
	}{
		{
			name:    "'is_private_email' claim is a string",
			idToken: `{"AuthURL":"","AccessToken":"","RefreshToken":"","ExpiresAt":"0001-01-01T00:00:00Z","sub":"","email":"test-email@privaterelay.appleid.com","is_private_email":"true", "email_verified":"true"}`,
			expectedClaims: IDTokenClaims{
				Email: "test-email@privaterelay.appleid.com",
				IsPrivateEmail: BoolString{
					StringValue: "true",
				},
				EmailVerified: BoolString{
					StringValue: "true",
				},
			},
		},
		{
			name:    "'is_private_email' claim is a boolean",
			idToken: `{"AuthURL":"","AccessToken":"","RefreshToken":"","ExpiresAt":"0001-01-01T00:00:00Z","sub":"","email":"test-email@privaterelay.appleid.com","is_private_email":true,"email_verified":true}`,
			expectedClaims: IDTokenClaims{
				Email: "test-email@privaterelay.appleid.com",
				IsPrivateEmail: BoolString{
					BoolValue:   true,
					IsValidBool: true,
				},
				EmailVerified: BoolString{
					BoolValue:   true,
					IsValidBool: true,
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idTokenClaims := IDTokenClaims{}
			err := json.Unmarshal([]byte(c.idToken), &idTokenClaims)
			a.NoError(err)
			a.Equal(idTokenClaims, c.expectedClaims)
		})
	}
}
