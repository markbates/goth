package microsoftonline_test

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/microsoftonline"
	"github.com/stretchr/testify/assert"
)

// compressed session of: Session{AuthURL:"https://login.microsoftonline.com/common/oauth2/v2.0/authorize",AccessToken: "1234567890"}
var compressedSession18 = []byte{31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 28, 198, 191, 10, 194, 48, 16, 7, 224, 119, 249, 205, 181, 119, 173, 255, 179, 117, 112, 115, 146, 186, 184, 73, 136, 38, 216, 228, 74, 114, 21, 81, 124, 119, 177, 240, 13, 223, 7, 221, 164, 254, 124, 58, 194, 192, 171, 142, 197, 16, 13, 114, 15, 169, 142, 193, 102, 41, 114, 83, 73, 67, 72, 174, 182, 18, 201, 74, 140, 146, 72, 174, 147, 250, 150, 158, 109, 205, 244, 175, 228, 240, 118, 168, 208, 89, 235, 74, 233, 229, 225, 18, 12, 154, 118, 185, 90, 111, 182, 187, 61, 163, 194, 225, 53, 134, 236, 74, 167, 48, 96, 230, 102, 49, 235, 153, 205, 236, 130, 239, 15, 0, 0, 255, 255, 1, 0, 0, 255, 255, 123, 236, 131, 18, 138, 0, 0, 0}
var compressedSession17 = []byte{31, 139, 8, 0, 0, 9, 110, 136, 0, 255, 28, 198, 191, 10, 194, 48, 16, 7, 224, 119, 249, 205, 181, 119, 173, 255, 179, 117, 112, 115, 146, 186, 184, 73, 136, 38, 216, 228, 74, 114, 21, 81, 124, 119, 177, 240, 13, 223, 7, 221, 164, 254, 124, 58, 194, 192, 171, 142, 197, 16, 13, 114, 15, 169, 142, 193, 102, 41, 114, 83, 73, 67, 72, 174, 182, 18, 201, 74, 140, 146, 72, 174, 147, 250, 150, 158, 109, 205, 244, 175, 228, 240, 118, 168, 208, 89, 235, 74, 233, 229, 225, 18, 12, 154, 118, 185, 90, 111, 182, 187, 61, 163, 194, 225, 53, 134, 236, 74, 167, 48, 96, 230, 102, 49, 235, 153, 205, 236, 130, 239, 15, 0, 0, 255, 255, 1, 0, 0, 255, 255, 123, 236, 131, 18, 138, 0, 0, 0}

// retrieves session based on runtime version as gziped values differs in some bytes between versions
func compressedSession() []byte {
	var minor int
	fmt.Sscanf(runtime.Version(), "go1.%d", &minor)

	if minor <= 7 {
		return compressedSession17
	}
	return compressedSession18
}

func Test_Implements_Session(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &microsoftonline.Session{}

	a.Implements((*goth.Session)(nil), s)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &microsoftonline.Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/foo"

	url, _ := s.GetAuthURL()
	a.Equal(url, "/foo")
}

func Test_ToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &microsoftonline.Session{
		AuthURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		AccessToken: "1234567890",
	}

	data := s.Marshal()
	a.Equal(compressedSession(), []byte(data))
}

func Test_String(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &microsoftonline.Session{
		AuthURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		AccessToken: "1234567890",
	}

	a.Equal(s.String(), s.Marshal())
}
