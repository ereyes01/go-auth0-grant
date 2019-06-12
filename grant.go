// Package auth0grant helps you request and manage a client_credentials grant from Auth0. This type of grant is useful for something like a program or a device (referred to in Auth0 as a machine-to-machine application) to gain authorization to one of your secured APIs.
//
// A client_credentials grant uses your machine-to-machine app's ID and secret to obtain a JWT bearer token that authorizes your program to your API, and maybe more (i.e. scopes, claims, or whatever you configure). The access token has an expiration that you can manage in the Auth0 dashboard for your API.
//
// This library provides a simple interface that gives you the access token when you need it and transparently re-requests it when it expires.
//
// For more information, see:
//
// https://auth0.com/docs/flows/concepts/client-credentials
// https://auth0.com/docs/applications/concepts/app-types-auth0 (M2M application)
//
// The README.md file contains an example of how this package can be used.
package auth0grant

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pkg/errors"
)

// CredentialsRequest contains the information needed to request credentials from the Auth0 authorization server.
type CredentialsRequest struct {
	// ClientID is the Auth0 Client ID string for the M2M application
	ClientID string `json:"client_id"`

	// ClientSecret is the Auth0 Client Secret string for the M2M application
	ClientSecret string `json:"client_secret"`

	// Audience identifies the audience of the access token
	Audience string `json:"audience"`

	// GrantType should always be "client_credentials" (CLIENT_CREDS_GRANT_TYPE)
	GrantType string `json:"grant_type"`
}

// CLIENT_CREDS_GRANT_TYPE is what you should set the GrantType of a credentials request to
const CLIENT_CREDS_GRANT_TYPE = "client_credentials"

type clientCredsGrant struct {
	AccessToken string        `json:"access_token"`
	Scope       string        `json:"scope"`
	ExpiresIn   time.Duration `json:"expires_in"`
	TokenType   string        `json:"token_type"`
}

// Grant contains the credentials obtained from the Auth0 authorization server. Use the AccessToken method to obtain these credentials in string token form to authorize this application with your secured resources (i.e. secure API).
type Grant struct {
	grant       *clientCredsGrant
	issuedAt    time.Time
	tokenURL    string
	credRequest CredentialsRequest
	nowFn       func() time.Time
}

// NewGrant obtains credentials from the Auth0 authorization server for your application. The tokenURL is the URL of your Auth0 tenant, usually followed by "/oauth/token/". The credRequest struct should be filled in with the inputs needed to authenticate and request credentials from the Auth0 authorization server.
func NewGrant(tokenURL string, credRequest CredentialsRequest) *Grant {
	return &Grant{
		tokenURL:    tokenURL,
		credRequest: credRequest,
		nowFn:       time.Now,
	}
}

// GetAccessToken returns the credentials obtained from the Auth0 authorization server in string token form. You should immediately use the token returned by this function only once (it will expire), and obtain a new one each time you need to authenticate. If the access token is expired, GetAccessToken will request a new one; otherwise, a cached copy is returned.
func (g *Grant) GetAccessToken() (string, error) {
	if g.needsRenew() {
		if err := g.renewGrant(); err != nil {
			return "", errors.Wrap(err, "renew grant")
		}
	}

	return g.grant.AccessToken, nil
}

func (g *Grant) renewGrant() error {
	payload, err := json.Marshal(g.credRequest)
	if err != nil {
		return errors.Wrap(err, "json encode cred request")
	}

	resp, err := http.Post(g.tokenURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return errors.Wrap(err, "cred http request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return errors.Errorf("response status: %s, body: %s", resp.Status, string(body))
	}

	var grant clientCredsGrant
	if err := json.NewDecoder(resp.Body).Decode(&grant); err != nil {
		return errors.Wrap(err, "decode grant from response")
	}

	grant.ExpiresIn *= time.Second

	g.issuedAt = g.nowFn()
	g.grant = &grant

	return nil
}

func (g *Grant) needsRenew() bool {
	if g.grant == nil {
		return true
	}

	expires := g.issuedAt.Add(g.grant.ExpiresIn)
	return g.nowFn().After(expires)
}
