package backend

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

func randomHex(size int) string {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(data)
}

func randomUUID() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	data[6] = (data[6] & 0x0f) | 0x40
	data[8] = (data[8] & 0x3f) | 0x80
	result := make([]byte, 36)
	hex.Encode(result[0:8], data[0:4])
	result[8] = '-'
	hex.Encode(result[9:13], data[4:6])
	result[13] = '-'
	hex.Encode(result[14:18], data[6:8])
	result[18] = '-'
	hex.Encode(result[19:23], data[8:10])
	result[23] = '-'
	hex.Encode(result[24:36], data[10:16])
	return string(result), nil
}
