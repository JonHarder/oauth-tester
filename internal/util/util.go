package util

import (
	"crypto/sha256"
	"encoding/base64"
	"math/rand"
	"os"
	"path"
)

func RandomString(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345789")
	data := make([]rune, n)
	for i := range data {
		data[i] = letters[rand.Intn(len(letters))]
	}
	return string(data)
}

// BinPath creates a path relative to the binary directory.
func BinPath(paths ...string) string {
	e, err := os.Executable()
	if err != nil {
		panic(err)
	}
	paths = append([]string{path.Dir(e)}, paths...)
	return path.Join(paths...)
}

func StrPtr(s string) *string {
	str := s
	return &str
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
