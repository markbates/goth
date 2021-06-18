package apple

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	idTokenVerificationKeyEndpoint = "https://appleid.apple.com/auth/keys"
)

type ID struct {
	Sub            string `json:"sub"`
	Email          string `json:"email"`
	IsPrivateEmail bool   `json:"is_private_email"`
}

type Session struct {
	AuthURL      string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	ID
}

func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

type IDTokenClaims struct {
	jwt.StandardClaims
	AccessTokenHash string `json:"at_hash"`
	AuthTime        int    `json:"auth_time"`
	Email           string `json:"email"`
	IsPrivateEmail  bool   `json:"is_private_email,string"`
}

func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	opts := []oauth2.AuthCodeOption{
		// Apple requires client id & secret as headers
		oauth2.SetAuthURLParam("client_id", p.clientId),
		oauth2.SetAuthURLParam("client_secret", p.secret),
	}
	token, err := p.config.Exchange(oauth2.NoContext, params.Get("code"), opts...)
	if err != nil {
		return "", err
	}

	if !token.Valid() {
		return "", errors.New("invalid token received from provider")
	}

	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
	s.ExpiresAt = token.Expiry

	if idToken := token.Extra("id_token"); idToken != nil {
		idToken, err := jwt.ParseWithClaims(idToken.(string), &IDTokenClaims{}, func(t *jwt.Token) (interface{}, error) {
			kid := t.Header["kid"].(string)
			claims := t.Claims.(*IDTokenClaims)
			vErr := new(jwt.ValidationError)
			if !claims.VerifyAudience(p.clientId, true) {
				vErr.Inner = fmt.Errorf("audience is incorrect")
				vErr.Errors |= jwt.ValidationErrorAudience
			}
			if !claims.VerifyIssuer(AppleAudOrIss, true) {
				vErr.Inner = fmt.Errorf("issuer is incorrect")
				vErr.Errors |= jwt.ValidationErrorIssuer
			}
			if vErr.Errors > 0 {
				return nil, vErr
			}

			// per OpenID Connect Core 1.0 §3.2.2.9, Access Token Validation
			hash := sha256.Sum256([]byte(s.AccessToken))
			halfHash := hash[0:(len(hash) / 2)]
			encodedHalfHash := base64.RawURLEncoding.EncodeToString(halfHash)
			if encodedHalfHash != claims.AccessTokenHash {
				vErr.Inner = fmt.Errorf(`identity token invalid`)
				vErr.Errors |= jwt.ValidationErrorClaimsInvalid
				return nil, vErr
			}

			// get the public key for verifying the identity token signature
			set, err := jwk.FetchHTTP(idTokenVerificationKeyEndpoint, jwk.WithHTTPClient(p.Client()))
			if err != nil {
				return nil, err
			}
			selectedKey := set.Keys[0]
			for _, key := range set.Keys {
				if key.KeyID() == kid {
					selectedKey = key
					break
				}
			}
			var pubKeyIface interface{}
			_ = selectedKey.Raw(&pubKeyIface)
			pubKey, ok := pubKeyIface.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf(`expected RSA public key from %s`, idTokenVerificationKeyEndpoint)
			}
			return pubKey, nil
		})
		if err != nil {
			return "", err
		}
		s.ID = ID{
			Sub:            idToken.Claims.(*IDTokenClaims).Subject,
			Email:          idToken.Claims.(*IDTokenClaims).Email,
			IsPrivateEmail: idToken.Claims.(*IDTokenClaims).IsPrivateEmail,
		}
	}

	return token.AccessToken, err
}

func (s Session) String() string {
	return s.Marshal()
}
