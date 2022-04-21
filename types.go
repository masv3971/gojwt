package gojwt

import (
	"fmt"
	"sync"
)

// JWTAccess type
type JWTAccess struct {
	Scope string `json:"scope"`
	Type  string `json:"type"`
}

// JWTClient type
type JWTClient struct {
	Key string `json:"key"`
}

// JWTAccessToken type
type JWTAccessToken struct {
	Flags  []string    `json:"flags"`
	Access []JWTAccess `json:"access"`
}

// JWTReply reply from jwt retrival endpoint
type JWTReply struct {
	AccessToken struct {
		Value  string `json:"value"`
		Access []struct {
			Type  string `json:"type"`
			Scope string `json:"scope"`
		} `json:"access"`
		Flags []string `json:"flags"`
	} `json:"access_token"`
}

// JWTRequest request type for ensureJWT
type JWTRequest struct {
	AccessToken []JWTAccessToken `json:"access_token"`
	Client      JWTClient        `json:"client"`
}

// EmptyStruct type
type EmptyStruct struct{}

// Errors is a general error reply
type Errors struct {
	Detail []struct {
		Loc  []string `json:"loc"`
		Msg  string   `json:"msg"`
		Type string   `json:"type"`
	} `json:"detail"`
}

// Error interface
type Error interface {
	Error() string
}

func (e *Errors) Error() string {
	return fmt.Sprintf("error: %v", e.Detail)
}

// JWT holds the raw token, mutex lock and expiration dates
type JWT struct {
	sync.RWMutex
	RAW       string
	ExpiresAt int64
	IssuedAt  int64
	NotBefore int64
}
