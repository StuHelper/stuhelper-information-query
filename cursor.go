package informationquery

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
)

// Service is assembled by value in existing hosts. Keep the fallback key stable
// across service copies and requests in the same process.
var processCursorKey = func() (key [32]byte) {
	rand.Read(key[:])
	return key
}()

func (s Service) cursorMAC(body []byte) []byte {
	key := s.CursorKey
	if key == nil {
		key = &processCursorKey
	}
	mac := hmac.New(sha256.New, key[:])
	mac.Write(body)
	return mac.Sum(nil)
}

func (s Service) encodeContinuation(c continuation) string {
	body, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(append(s.cursorMAC(body), body...))
}

func (s Service) parseContinuation(token string) (continuation, bool) {
	var c continuation
	data, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(data) <= sha256.Size || base64.RawURLEncoding.EncodeToString(data) != token {
		return c, false
	}
	body := data[sha256.Size:]
	if !hmac.Equal(data[:sha256.Size], s.cursorMAC(body)) {
		return c, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil || decoder.Decode(new(any)) != io.EOF {
		return c, false
	}
	return c, true
}
