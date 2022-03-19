package util

import (
	"crypto/sha256"
	"encoding/base64"
	"math/rand"
)

func RandomString(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345789")
	data := make([]rune, n)
	for i := range data {
		data[i] = letters[rand.Intn(len(letters))]
	}
	return string(data)
}

func StrPtr(s string) *string {
	s = s
	return &s
}

func s256(s string) []byte {
	h := sha256.New()
	h.Write([]byte(s))
	return h.Sum(nil)
}

// s256CodeChallenge creates a rfc 7636 compliant code challenge.
// BASE64URL-ENCODE(SHA256(ASCII(code_challenge)))
func S256CodeChallenge(s string) string {
	return base64.URLEncoding.EncodeToString(s256(s))
}
