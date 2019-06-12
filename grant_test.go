package auth0grant

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

var (
	expectedGrant = clientCredsGrant{
		AccessToken: "open-sesame",
		Scope:       "u-cant-touch-dis",
		TokenType:   "Bearer",
		ExpiresIn:   time.Second,
	}

	testCredRequest = CredentialsRequest{
		ClientID:     "joe-blow-id",
		ClientSecret: "joe-blow-secret",
		Audience:     "https://api.blowcorp.co/",
		GrantType:    CLIENT_CREDS_GRANT_TYPE,
	}
)

const (
	testGrantResponse = `{"access_token":"open-sesame","scope":"u-cant-touch-dis","expires_in":1,"token_type":"Bearer"}`
	tokenPath         = "/oauth/token"
)

type testGrantServer struct {
	server *httptest.Server
	ncalls int
	t      *testing.T
}

func newTestGrantServer(t *testing.T, ncalls int) *testGrantServer {
	t.Helper()

	s := &testGrantServer{t: t, ncalls: ncalls}
	s.server = httptest.NewServer(http.HandlerFunc(s.handler))
	return s
}

func (s *testGrantServer) Close() {
	s.t.Helper()

	if s.ncalls != 0 {
		s.t.Fatalf("wrong # calls got: %d expected %d", s.ncalls, 0)
	}

	s.server.Close()
}

func (s *testGrantServer) TokenURL() string {
	s.t.Helper()

	return s.server.URL + tokenPath
}

func (s *testGrantServer) handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != tokenPath {
		s.t.Fatalf("url path got: %s expected: %s", r.URL.Path, tokenPath)
	}
	if r.Method != "POST" {
		s.t.Fatalf("http method got: %s expected: %s", r.Method, "POST")
	}
	mimeType := r.Header.Get("Content-Type")
	if mimeType != "application/json" {
		s.t.Fatalf("mime type got: %s expected: %s", mimeType, "application/json")
	}

	var request CredentialsRequest

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.t.Fatal("json decode body:", err)
	}
	if err := r.Body.Close(); err != nil {
		s.t.Fatal("close request body:", err)
	}
	if !cmp.Equal(request, testCredRequest) {
		s.t.Fatalf("cred request expected: %+v got: %+v", request, testCredRequest)
	}

	if _, err := w.Write([]byte(testGrantResponse)); err != nil {
		s.t.Fatal("write grant response:", err)
	}

	s.ncalls--
}

func testNewGrant(tokenURL string, credRequest *CredentialsRequest, nowFn func() time.Time) Grant {
	grant := NewGrant(tokenURL, &testCredRequest)
	grant.(*grantRequest).nowFn = nowFn
	return grant
}

func testNowFn(offset int64) func() time.Time {
	return func() time.Time {
		return time.Unix(offset, 0)
	}
}

func TestGrantAPI(t *testing.T) {
	t.Run("Retrieves the access token for the first time", func(t *testing.T) {
		server := newTestGrantServer(t, 1)
		defer server.Close()

		grant := testNewGrant(server.TokenURL(), &testCredRequest, testNowFn(1))

		token, err := grant.GetAccessToken()
		if err != nil {
			t.Fatal("get access token:", err)
		}
		if token != expectedGrant.AccessToken {
			t.Fatalf("wrong access token got: %s expected: %s", token, expectedGrant.AccessToken)
		}

		req, ok := grant.(*grantRequest)
		if !ok {
			t.Fatal("cast to *grantRequest")
		}
		if !cmp.Equal(*req.grant, expectedGrant) {
			t.Fatalf("wrong grant got: %+v expected: %+v", *req.grant, expectedGrant)
		}
	})

	t.Run("Renews and retrieves an access token when the previous one has expired", func(t *testing.T) {
		server := newTestGrantServer(t, 1)
		defer server.Close()

		grant := testNewGrant(server.TokenURL(), &testCredRequest, testNowFn(3))
		req, ok := grant.(*grantRequest)
		if !ok {
			t.Fatal("cast to *grantRequest")
		}

		req.grant = &expectedGrant
		req.issuedAt = time.Unix(1, 0)

		token, err := grant.GetAccessToken()
		if err != nil {
			t.Fatal("get access token:", err)
		}
		if token != expectedGrant.AccessToken {
			t.Fatalf("wrong access token got: %s expected: %s", token, expectedGrant.AccessToken)
		}

		expectedTime := time.Unix(3, 0)
		if !req.issuedAt.Equal(expectedTime) {
			t.Fatalf("wrong issue time got: %s, expected: %s", req.issuedAt.Format(time.RFC3339), expectedTime.Format(time.RFC3339))
		}
	})

	t.Run("Retrieves the cached access token if it isn't expired yet", func(t *testing.T) {
		server := newTestGrantServer(t, 0) // <-- server shouldn't get called!
		defer server.Close()

		grant := testNewGrant(server.TokenURL(), &testCredRequest, testNowFn(1))
		req, ok := grant.(*grantRequest)
		if !ok {
			t.Fatal("cast to *grantRequest")
		}

		req.grant = &expectedGrant
		req.issuedAt = time.Unix(1, 0)

		token, err := grant.GetAccessToken()
		if err != nil {
			t.Fatal("get access token:", err)
		}
		if token != expectedGrant.AccessToken {
			t.Fatalf("wrong access token got: %s expected: %s", token, expectedGrant.AccessToken)
		}
	})
}
