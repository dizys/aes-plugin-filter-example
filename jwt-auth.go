// This simple Plugin will transform POST requests to GET when proxied to the
// upstream.
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
)

var (
	jwtRSAPublicKey = "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAM40VspKcLBbf1zJZYVfTDZW+CSo4ur6\nPXsM4Qm6ZqbyVuZFu2PnCkPQ8Gi5GTWahgaNEkDtpssgazAjNVViiwUCAwEAAQ==\n-----END PUBLIC KEY-----\n"
	requestLogging  = true
	testCounter     = 0
)

type Claims struct {
	*jwt.StandardClaims
	Id       int64  `json:"id,omitempty"`
	Username string `json:"username,omitempty"`
}

func PluginMain(resp http.ResponseWriter, req *http.Request) {
	authStr := req.Header.Get("Authorization")

	if requestLogging {
		log.Printf("[Request] %s - %s (token: %s): %s\n", req.Method, req.RequestURI, authStr, req.PostForm.Encode())
	}

	if authStr == "" {
		rErr(resp, 401, "Unauthenticated")
		return
	}

	if !strings.HasPrefix(authStr, "Bearer ") {
		rErr(resp, 401, "Invalid access token type")
		return
	}

	unverifiedToken := strings.TrimPrefix(authStr, "Bearer ")

	pubKeyPEM := jwtRSAPublicKey

	pubKey, err := PEMStringToRSAPublicKey(pubKeyPEM)

	if err != nil {
		rErr(resp, 503, "Invalid public key")
		return
	}

	token, err := jwt.ParseWithClaims(unverifiedToken, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})

	if err != nil {
		rErr(resp, 401, "Unauthorized")
		return
	}

	claims := token.Claims.(*Claims)

	claimsStr, err := StructToJSON(claims)

	if err != nil {
		rErr(resp, 503, "Cannot convert claims to JSON")
		return
	}

	testCounter++

	resp.Header().Add("x-passport", claimsStr)
	resp.Header().Add("x-passport-issued-count", fmt.Sprint(testCounter))

	resp.Write([]byte("OK"))

	if requestLogging {
		log.Printf("[Response] 200: OK\n")
	}
}

func rErr(resp http.ResponseWriter, statusCode int, message string) {
	resp.WriteHeader(statusCode)
	resp.Write([]byte(message))

	if requestLogging {
		log.Printf("[Response] %d: %s\n", statusCode, message)
	}
}

func PEMStringToRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	p, _ := pem.Decode([]byte(pemStr))

	pub, err := x509.ParsePKIXPublicKey(p.Bytes)

	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break
	}

	return nil, fmt.Errorf("public key type is not RSA")
}

func StructToJSON(obj interface{}) (string, error) {
	jsonBytes, err := json.Marshal(obj)

	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}
