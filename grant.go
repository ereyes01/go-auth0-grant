package auth0grant

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pkg/errors"
)

type CredentialsRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Audience     string `json:"audience"`
	GrantType    string `json:"grant_type"`
}

const CLIENT_CREDS_GRANT_TYPE = "client_credentials"

type Grant interface {
	GetAccessToken() (string, error)
}

type clientCredsGrant struct {
	AccessToken string        `json:"access_token"`
	Scope       string        `json:"scope"`
	ExpiresIn   time.Duration `json:"expires_in"`
	TokenType   string        `json:"token_type"`
}

type grantRequest struct {
	grant       *clientCredsGrant
	issuedAt    time.Time
	tokenURL    string
	credRequest *CredentialsRequest
	nowFn       func() time.Time
}

func NewGrant(tokenURL string, credRequest *CredentialsRequest) Grant {
	return &grantRequest{
		tokenURL:    tokenURL,
		credRequest: credRequest,
		nowFn:       time.Now,
	}
}

func (g *grantRequest) GetAccessToken() (string, error) {
	if g.needsRenew() {
		if err := g.renewGrant(); err != nil {
			return "", errors.Wrap(err, "renew grant")
		}
	}

	return g.grant.AccessToken, nil
}

func (g *grantRequest) renewGrant() error {
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

func (g *grantRequest) needsRenew() bool {
	if g.grant == nil {
		return true
	}

	expires := g.issuedAt.Add(g.grant.ExpiresIn)
	return g.nowFn().After(expires)
}
