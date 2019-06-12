# Auth0 Client Credentials Grant Library for Go

This library helps you request and manage a [`client_credentials` grant](https://auth0.com/docs/api-auth/grant/client-credentials)
from Auth0. This type of grant is useful for something like a program or a device (referred to in Auth0 as a 
[machine-to-machine application](https://auth0.com/docs/applications/machine-to-machine)) to gain authorization to one of your
APIs.

A `client_credentials` grant uses your machine-to-machine app's ID and secret to obtain a JWT bearer token that authorizes your
program to your API, and maybe more (i.e. scopes, claims, or whatever you configure). The access token has an expiration that
you can manage in the Auth0 dashboard for your API.

This library provides a simple interface that gives you the access token when you need it and transparently re-requests it when
it expires.

## Example

```go
import "github.com/ereyes01/go-auth0-grant"

func someFunc() {
  // URL for the grant request is https://<your-auth0-domain>/oauth/token/
  grant := auth0grant.NewGrant("https://myapp.auth0.com/oauth/token/", auth0grant.CredentialsRequest{
    ClientID:     "my-app-id",
    ClientSecret: "my-app-secret",
    Audience:     "https://my-api.myapp.com/",
    GrantType:    auth0grant.CLIENT_CREDS_GRANT_TYPE,
  })
  
  // whenever you need an access token to talk with your API:
  accessToken, err := grant.GetAccessToken()
  if err != nil {
    panic(err)
  }
}
```

If the access token is expired, `GetAccessToken()` requests a new one. Otherwise, it caches the last one you used.

## Installation

```bash
go get github.com/ereyes01/go-auth0-grant
```

When you import, the package name is `auth0grant`, as you can see in the examples above.
