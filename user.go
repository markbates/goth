package goth

import (
	"encoding/gob"
	"time"
)

func init() {
	gob.Register(User{})
}

// User contains the information common amongst most OAuth and OAuth2 providers.
// All the "raw" data from the provider can be found in the `RawData` field.
type User struct {
	RawData           map[string]interface{}
	Provider          string
	Email             string
	Name              string
	FirstName         string
	LastName          string
	NickName          string
	Description       string
	UserID            string
	AvatarURL         string
	Location          string
	AccessToken       string
	AccessTokenSecret string
	RefreshToken      string
	ExpiresAt         time.Time
	IDToken           string
}
