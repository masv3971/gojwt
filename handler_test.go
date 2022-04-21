package gojwt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var mockJWTJSON = []byte(`
{
	"access_token": {
	  "value": "eyJhbGciOiJFUzI1NiJ9.eyJleHAiOjE2MzcyNTQ0MTYsImlhdCI6MTYzNzI1MDgxNiwiaXNzIjoiaHR0cHM6Ly9hdXRoLXRlc3Quc3VuZXQuc2UiLCJuYmYiOjE2MzcyNTA4MTYsInJlcXVlc3RlZF9hY2Nlc3MiOlt7InNjb3BlIjoiZWR1aWQuc2UiLCJ0eXBlIjoic2NpbS1hcGkifV0sInNjb3BlcyI6WyJlZHVpZC5zZSIsInN1bmV0LnNlIl0sInNvdXJjZSI6ImNvbmZpZyIsInN1YiI6Im1hc3ZfdGVzdF8xIiwidmVyc2lvbiI6MX0.ZoSx13qFoq00QI4xmngySnoVMMVOKiKzKFE8yiZgKqlh0nMFQuhwDD9VkTCaGFWbk4RprvxybfcAEl3Gcd4JQQ",
	  "access": [
		{
		  "type": "scim-api",
		  "scope": "eduid.se"
		}
	  ],
	  "flags": [
		"bearer"
	  ]
	}
  }
`)

var mockJWTError401 = []byte(`
{
	"detail": "permission denied"
  }
`)

func TestNewJWT(t *testing.T) {
	tts := []struct {
		name             string
		serverURL        string
		serverReply      []byte
		serverStatusCode int
		clientReply      interface{}
	}{
		{
			name:             "OK",
			serverURL:        "/transaction",
			serverReply:      mockJWTJSON,
			serverStatusCode: 200,
			clientReply:      &JWTReply{},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			mux, server, client := mockSetup(t)
			defer server.Close()

			mockGenericEndpointServer(t, mux, "POST", tt.serverURL, tt.serverReply, tt.serverStatusCode)

			err := json.Unmarshal(tt.serverReply, tt.clientReply)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			err = client.newJWT(context.TODO())
			if !assert.NoError(t, err) {
				t.FailNow()
			}
		})
	}
}

func mockGenericEndpointServer(t *testing.T, mux *http.ServeMux, verb, url string, serverReply []byte, statusCode int) {
	mux.HandleFunc(url,
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(statusCode)
			testMethod(t, r, verb)
			testURL(t, r, url)
			w.Write(serverReply)
		},
	)
}

func mockServer(t *testing.T, mux *http.ServeMux) *httptest.Server {
	return httptest.NewServer(mux)
}

func mockSetup(t *testing.T) (*http.ServeMux, *httptest.Server, *Client) {
	mux := http.NewServeMux()

	server := mockServer(t, mux)

	client := mockNew(t, server.URL)

	return mux, server, client
}

func mockNew(t *testing.T, url string) *Client {
	cfg := Config{
		Certificate: []byte{},
		PrivateKey:  []byte{},
		Password:    "testPassword",
		Scope:       "testScope",
		Type:        "testType",
		URL:         url,
		Key:         "testKey",
		Client:      "testClient",
	}
	client := New(cfg)
	return client
}

func testMethod(t *testing.T, r *http.Request, want string) {
	assert.Equal(t, want, r.Method)
}

func testURL(t *testing.T, r *http.Request, want string) {
	assert.Equal(t, want, r.RequestURI)
}

func testBody(t *testing.T, r *http.Request, want string) {
	buffer := new(bytes.Buffer)
	_, err := buffer.ReadFrom(r.Body)
	assert.NoError(t, err)

	got := buffer.String()
	require.JSONEq(t, want, got)
}

func TestParseJWT(t *testing.T) {
	var (
		rawJWT1 = "eyJhbGciOiJFUzI1NiJ9.eyJleHAiOjE2MzcyNTQ0MTYsImlhdCI6MTYzNzI1MDgxNiwiaXNzIjoiaHR0cHM6Ly9hdXRoLXRlc3Quc3VuZXQuc2UiLCJuYmYiOjE2MzcyNTA4MTYsInJlcXVlc3RlZF9hY2Nlc3MiOlt7InNjb3BlIjoiZWR1aWQuc2UiLCJ0eXBlIjoic2NpbS1hcGkifV0sInNjb3BlcyI6WyJlZHVpZC5zZSIsInN1bmV0LnNlIl0sInNvdXJjZSI6ImNvbmZpZyIsInN1YiI6Im1hc3ZfdGVzdF8xIiwidmVyc2lvbiI6MX0.ZoSx13qFoq00QI4xmngySnoVMMVOKiKzKFE8yiZgKqlh0nMFQuhwDD9VkTCaGFWbk4RprvxybfcAEl3Gcd4JQQ"
	)
	tts := []struct {
		name string
		have string
		want *JWT
	}{
		{
			name: "OK",
			have: rawJWT1,
			want: &JWT{
				RAW:       rawJWT1,
				ExpiresAt: 1637254416,
				IssuedAt:  1637250816,
				NotBefore: 1637250816,
			},
		},
		{
			name: "Not OK",
			have: rawJWT1,
			want: &JWT{
				RAW:       rawJWT1,
				ExpiresAt: 1637254416,
				IssuedAt:  1637250816,
				NotBefore: 1637250816,
			},
		},
	}

	for _, tt := range tts {
		_, _, client := mockSetup(t)
		err := client.parseJWT(tt.have)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		assert.Equal(t, tt.want, client.JWT)
	}
}

type MockRequestedAccess struct {
	Scope string `json:"scope"`
	Type  string `json:"type"`
}
type mockCostumClaim struct {
	RequestedAccess []MockRequestedAccess `json:"requested_access"`
	Scopes          []string              `json:"Scopes"`
	Source          string                `json:"source"`
	Version         int                   `json:"version"`
	jwt.RegisteredClaims
}

func mockJWT(t *testing.T, eat, iat, nbf int64) *JWT {

	customClaim := mockCostumClaim{
		RequestedAccess: []MockRequestedAccess{
			{
				Scope: "eduid.se",
				Type:  "scim-api",
			},
		},
		Scopes:  []string{"eduid.se", "sunet.se"},
		Source:  "config",
		Version: 1,
	}

	customClaim.Issuer = "testIss"
	customClaim.Subject = "testSub_1"
	customClaim.Audience = []string{}
	customClaim.ExpiresAt = jwt.NewNumericDate(time.Unix(eat, 0))
	customClaim.IssuedAt = jwt.NewNumericDate(time.Unix(iat, 0))
	customClaim.NotBefore = jwt.NewNumericDate(time.Unix(nbf, 0))

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, customClaim)
	signedToken, err := token.SignedString([]byte("testSigningKey"))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	jwt := &JWT{
		RAW:       signedToken,
		ExpiresAt: eat,
		IssuedAt:  iat,
		NotBefore: nbf,
	}
	return jwt
}

func TestValid(t *testing.T) {
	type have struct {
		eat int64
		iat int64
		nbf int64
	}
	tts := []struct {
		name string
		have have
		want bool
	}{
		{
			name: "OK",
			have: have{
				eat: time.Now().Add(1 * time.Hour).Unix(),
				iat: time.Now().Unix(),
				nbf: time.Now().Unix(),
			},
			want: true,
		},
		{
			name: "notbefore is in the future",
			have: have{
				eat: time.Now().Add(1 * time.Hour).Unix(),
				iat: time.Now().Unix(),
				nbf: time.Now().Add(1 * time.Hour).Unix(),
			},
			want: false,
		},
		{
			name: "issued in the future",
			have: have{
				eat: time.Now().Add(1 * time.Hour).Unix(),
				iat: time.Now().Add(1 * time.Hour).Unix(),
				nbf: time.Now().Unix(),
			},
			want: false,
		},
		{
			name: "Token has expired",
			have: have{
				eat: time.Now().Add(-1 * time.Hour).Unix(),
				iat: time.Now().Add(1 * time.Hour).Unix(),
				nbf: time.Now().Unix(),
			},
			want: false,
		},
		{
			name: "Token is valid for less than a minute",
			have: have{
				eat: time.Now().Add(-1 * time.Minute).Unix(),
				iat: time.Now().Add(1 * time.Hour).Unix(),
				nbf: time.Now().Unix(),
			},
			want: false,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			token := mockJWT(t, tt.have.eat, tt.have.iat, tt.have.nbf)
			got := token.Valid()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEnsureJWT(t *testing.T) {
	tts := []struct {
		name             string
		serverStatusCode int
		jwt              *JWT
	}{
		{
			name:             "No present jwt",
			serverStatusCode: 200,
			jwt:              &JWT{},
		},
		{
			name:             "No present jwt",
			serverStatusCode: 500,
			jwt:              &JWT{},
		},
		{
			name:             "Present jwt, valid",
			serverStatusCode: 200,
			jwt: &JWT{
				RAW:       "test raw",
				ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
				IssuedAt:  time.Now().Unix(),
				NotBefore: time.Now().Unix(),
			},
		},
		{
			name:             "Present jwt, expired",
			serverStatusCode: 200,
			jwt: &JWT{
				RAW:       "test raw",
				ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
				IssuedAt:  time.Now().Unix(),
				NotBefore: time.Now().Unix(),
			},
		},
	}

	for _, tt := range tts {
		t.Run(fmt.Sprintf("%s -- %d", tt.name, tt.serverStatusCode), func(t *testing.T) {
			mux, server, client := mockSetup(t)
			defer server.Close()

			client.JWT = tt.jwt

			mockGenericEndpointServer(t, mux, "POST", "/transaction", mockJWTJSON, tt.serverStatusCode)

			switch tt.serverStatusCode {
			case 200:
				err := client.EnsureJWT(context.TODO())
				if !assert.NoError(t, err) {
					t.FailNow()
				}
			case 500:
				err := client.EnsureJWT(context.TODO())
				assert.Equal(t, "error: []", err.Error()) //TODO(masv): fix better error handling
			}
		})
	}
}
