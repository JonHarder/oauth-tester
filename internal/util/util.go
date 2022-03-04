package util

import "math/rand"

func RandomString(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345789")
	data := make([]rune, 12)
	for i := range data {
		data[i] = letters[rand.Intn(len(letters))]
	}
	return string(data)
}
