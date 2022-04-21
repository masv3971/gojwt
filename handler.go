package gojwt

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-playground/validator"
)

// Client holds the object of jwt
type Client struct {
	httpClient  *http.Client
	certificate []byte
	privateKey  []byte
	password    string
	scope       string
	jwtType     string
	URL         string
	key         string
	client      string
	JWT         *JWT
}

// Config holds the configuration for jwt
type Config struct {
	Certificate []byte
	PrivateKey  []byte
	Password    string
	Scope       string
	Type        string
	URL         string
	Key         string
	Client      string
}

// New creates a new instance of jwt
func New(config Config) *Client {
	c := &Client{
		URL:         config.URL,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		certificate: config.Certificate,
		privateKey:  config.PrivateKey,
		password:    config.Password,
		scope:       config.Scope,
		jwtType:     config.Type,
		key:         config.Key,
		client:      config.Client,
		JWT:         &JWT{},
	}

	return c
}

func (c *Client) newRequest(ctx context.Context, method, path string, body interface{}) (*http.Request, error) {
	rel, err := url.Parse(path)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(c.URL)
	if err != nil {
		return nil, err
	}
	url := u.ResolveReference(rel)

	var buf io.ReadWriter
	if body != nil {
		payload := struct {
			Data interface{} `json:"data"`
		}{
			Data: body,
		}
		buf = new(bytes.Buffer)
		err = json.NewEncoder(buf).Encode(payload)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url.String(), buf)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "gojwt")
	return req, nil
}

func (c *Client) do(req *http.Request, value interface{}) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := checkResponse(resp); err != nil {
		errorReply := &Errors{}
		buf := &bytes.Buffer{}
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(buf.Bytes(), errorReply); err != nil {
			return nil, err
		}
		return nil, errorReply
	}

	if err := json.NewDecoder(resp.Body).Decode(value); err != nil {
		return nil, err
	}

	return resp, nil
}

func checkResponse(r *http.Response) error {
	serviceName := "goeduidiam"

	switch r.StatusCode {
	case 200, 201, 202, 204, 304:
		return nil
	case 500:
		return fmt.Errorf("%s: not allowed", serviceName)
	default:
		return fmt.Errorf("%s: invalid request", serviceName)
	}
}

func (c *Client) call(ctx context.Context, method, url string, req, value interface{}) (*http.Response, error) {
	request, err := c.newRequest(
		ctx,
		method,
		url,
		req,
	)
	if err != nil {
		return nil, err
	}

	resp, err := c.do(request, value)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

// GetJWTRequest holds the request
type GetJWTRequest struct {
	Data JWTRequest `json:"data"`
}

// newJWT gets a jwt
func (c *Client) newJWT(ctx context.Context) error {
	c.JWT.Lock()
	defer c.JWT.Unlock()

	req := &GetJWTRequest{
		Data: JWTRequest{
			AccessToken: []JWTAccessToken{
				{
					Flags: []string{"bearer"},
					Access: []JWTAccess{
						{
							Scope: c.scope,
							Type:  c.jwtType,
						},
					},
				},
			},
			Client: JWTClient{
				Key: c.key,
			},
		},
	}

	reply := &JWTReply{}
	_, err := c.call(ctx, "POST", "transaction", req, reply)
	if err != nil {
		return err
	}

	if reply.AccessToken.Value == "" {
		return errors.New("ERROR, token is empty")
	}

	if err := c.parseJWT(reply.AccessToken.Value); err != nil {
		return err
	}

	return err
}

func (c *Client) parseJWT(jwtInputString string) error {
	jwtBase64 := strings.Split(jwtInputString, ".")
	if len(jwtBase64) < 3 {
		return errors.New("ERROR invalid JWT, corrupt split")
	}

	jwtDecoded, err := base64.RawURLEncoding.DecodeString(jwtBase64[1])
	if err != nil {
		return err
	}
	type jwtSpec struct {
		Exp             int64  `json:"exp"`
		Iat             int64  `json:"iat"`
		Iss             string `json:"iss"`
		Nbf             int64  `json:"nbf"`
		RequestedAccess []struct {
			Scope string `json:"scope"`
			Type  string `json:"type"`
		} `json:"requested_access"`
		Scopes  []string `json:"scopes"`
		Source  string   `json:"source"`
		Sub     string   `json:"sub"`
		Version int      `json:"version"`
	}

	jwtSpecS := &jwtSpec{}
	if err := json.Unmarshal(jwtDecoded, jwtSpecS); err != nil {
		return err
	}

	jwt := &JWT{
		RAW:       jwtInputString,
		ExpiresAt: jwtSpecS.Exp,
		IssuedAt:  jwtSpecS.Iat,
		NotBefore: jwtSpecS.Nbf,
	}
	c.JWT = jwt

	return nil
}

// Valid checks if jwt token i valid of not
func (jwt *JWT) Valid() bool {
	jwt.RLock()
	defer jwt.RUnlock()

	// token has expired
	unixNow := time.Now().Unix()
	if jwt.ExpiresAt < unixNow {
		return false
	}

	// token issued in the future
	if jwt.IssuedAt > unixNow {
		return false
	}

	// token starts to be valid in the future
	if jwt.NotBefore > unixNow {
		return false
	}

	// Token has too little time left
	if jwt.ExpiresAt < unixNow+360 {
		return false
	}
	return true
}

// EnsureJWT ensure that a jwt is present and valid
func (c *Client) EnsureJWT(ctx context.Context) error {
	if c.JWT != nil {
		if c.JWT.Valid() {
			return nil
		}
	}

	if err := c.newJWT(ctx); err != nil {
		return err
	}
	return nil
}

func validate(s interface{}) error {
	validate := validator.New()

	err := validate.Struct(s)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			fmt.Printf("ERR: Field %q of type %q violates rule: %q\n", err.Namespace(), err.Kind(), err.Tag())
		}
		return errors.New("Validation error")
	}
	return nil
}
