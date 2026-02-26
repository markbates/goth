package shopify_test

import (
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/shopify"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("SHOPIFY_KEY"))
	a.Equal(p.Secret, os.Getenv("SHOPIFY_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), provider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()
	session, err := p.BeginAuth("test_state")
	s := session.(*shopify.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://test-shop.myshopify.com/admin/oauth/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://test-shop.myshopify.com/admin/oauth/authorize","AccessToken":"1234567890"}"`)
	a.NoError(err)

	s := session.(*shopify.Session)
	a.Equal(s.AuthURL, "https://test-shop.myshopify.com/admin/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *shopify.Provider {
	p := shopify.New(os.Getenv("SHOPIFY_KEY"), os.Getenv("SHOPIFY_SECRET"), "/foo")
	p.SetShopName("test-shop")
	return p
}
