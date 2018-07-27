package auth0grant

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
)

var testGrantResponse = `{"access_token":"open-sesame","scope":"u-cant-touch-dis","expires_in":1,"token_type":"Bearer"}`

var testGrant = clientCredsGrant{
	AccessToken: "open-sesame",
	Scope:       "u-cant-touch-dis",
	TokenType:   "Bearer",
	ExpiresIn:   time.Second,
}

var testCredRequest = CredentialsRequest{
	ClientID:     "joe-blow-id",
	ClientSecret: "joe-blow-secret",
	Audience:     "https://api.blowcorp.co/",
	GrantType:    CLIENT_CREDS_GRANT_TYPE,
}

func testGetAccessToken() (http.HandlerFunc, *int) {
	var ncalls int

	return func(w http.ResponseWriter, r *http.Request) {
		Expect(r.URL.Path).To(Equal("/oauth/token"))
		Expect(r.Method).To(Equal("POST"))
		Expect(r.Header.Get("Content-Type")).To(Equal("application/json"))

		var request CredentialsRequest
		Expect(json.NewDecoder(r.Body).Decode(&request)).To(Succeed())
		Expect(r.Body.Close()).To(Succeed())
		Expect(request).To(Equal(testCredRequest))

		_, err := w.Write([]byte(testGrantResponse))
		Expect(err).To(BeNil())

		ncalls++
	}, &ncalls
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

var _ = Describe("Credentials Grant API", func() {
	var (
		tokenServer *httptest.Server
		nTokenCalls *int
		tokenURL    string
	)

	BeforeEach(func() {
		var h http.HandlerFunc
		h, nTokenCalls = testGetAccessToken()

		tokenServer = httptest.NewServer(h)
		tokenURL = tokenServer.URL + "/oauth/token"
	})

	AfterEach(func() {
		tokenServer.Close()
		tokenServer = nil
		nTokenCalls = nil
		tokenURL = ""
	})

	It("Retrieves the access token for the first time", func() {
		grant := testNewGrant(tokenURL, &testCredRequest, testNowFn(1))

		token, err := grant.GetAccessToken()
		Expect(err).To(BeNil())
		Expect(token).To(Equal(testGrant.AccessToken))
		Expect(*nTokenCalls).To(Equal(1))

		req, ok := grant.(*grantRequest)
		Expect(ok).To(BeTrue())
		Expect(*req.grant).To(Equal(testGrant))
	})

	It("Renews and retrieves an access token when the previous one has expired", func() {
		grant := testNewGrant(tokenURL, &testCredRequest, testNowFn(3))
		req, ok := grant.(*grantRequest)
		Expect(ok).To(BeTrue())

		req.grant = &testGrant
		req.issuedAt = time.Unix(1, 0)

		token, err := grant.GetAccessToken()
		Expect(err).To(BeNil())
		Expect(token).To(Equal(testGrant.AccessToken))
		Expect(*nTokenCalls).To(Equal(1))

		Expect(req.issuedAt).To(Equal(time.Unix(3, 0)))
	})

	It("Retrieves the cached access token if it isn't expired yet", func() {
		grant := testNewGrant(tokenURL, &testCredRequest, testNowFn(1))
		req, ok := grant.(*grantRequest)
		Expect(ok).To(BeTrue())

		req.grant = &testGrant
		req.issuedAt = time.Unix(1, 0)

		token, err := grant.GetAccessToken()
		Expect(err).To(BeNil())
		Expect(token).To(Equal(testGrant.AccessToken))
		Expect(*nTokenCalls).To(BeZero())
	})
})

func TestAuth(t *testing.T) {
	RegisterFailHandler(Fail)
	format.UseStringerRepresentation = true // don't print spammy time structs
	RunSpecs(t, "auth0grant package")
}
