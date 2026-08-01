package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	socksNoAuthMethod       = byte(0x00)
	socksUserPasswordMethod = byte(0x02)
)

type credentials struct {
	username string
	password string
}

func newCredentials(username, password string) (credentials, error) {
	if (username == "") != (password == "") {
		return credentials{}, errors.New("auth-user and auth-password must be configured together")
	}
	if strings.Contains(username, ":") {
		return credentials{}, errors.New("authentication username must not contain a colon")
	}
	if len(username) > 255 || len(password) > 255 {
		return credentials{}, errors.New("authentication username and password must be at most 255 bytes")
	}
	return credentials{username: username, password: password}, nil
}

func firstNonEmpty(primary, fallback string) string {
	if primary != "" {
		return primary
	}
	return fallback
}

func (c credentials) enabled() bool {
	return c.username != ""
}

func (c credentials) matches(username, password string) bool {
	wantUser := sha256.Sum256([]byte(c.username))
	gotUser := sha256.Sum256([]byte(username))
	wantPassword := sha256.Sum256([]byte(c.password))
	gotPassword := sha256.Sum256([]byte(password))

	return subtle.ConstantTimeCompare(wantUser[:], gotUser[:])&
		subtle.ConstantTimeCompare(wantPassword[:], gotPassword[:]) == 1
}

func authenticateHTTPProxy(w http.ResponseWriter, r *http.Request, auth credentials) bool {
	if !auth.enabled() {
		return true
	}

	username, password, ok := parseProxyBasicAuth(r.Header.Get("Proxy-Authorization"))
	if ok && auth.matches(username, password) {
		return true
	}

	w.Header().Set("Proxy-Authenticate", `Basic realm="simple-proxy"`)
	http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
	return false
}

func parseProxyBasicAuth(header string) (username, password string, ok bool) {
	scheme, encoded, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", "", false
	}
	username, password, found = strings.Cut(string(decoded), ":")
	return username, password, found
}

func negotiateSOCKS5Authentication(r io.Reader, w io.Writer, auth credentials) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	if header[0] != 0x05 {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(r, methods); err != nil {
		return err
	}

	method := socksNoAuthMethod
	if auth.enabled() {
		method = socksUserPasswordMethod
	}
	if !containsByte(methods, method) {
		_, _ = w.Write([]byte{0x05, 0xff})
		return errors.New("client does not support the required authentication method")
	}
	if _, err := w.Write([]byte{0x05, method}); err != nil {
		return err
	}
	if method == socksUserPasswordMethod {
		return authenticateSOCKS5UserPassword(r, w, auth)
	}
	return nil
}

func authenticateSOCKS5UserPassword(r io.Reader, w io.Writer, auth credentials) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	if header[0] != 0x01 {
		_, _ = w.Write([]byte{0x01, 0x01})
		return fmt.Errorf("unsupported username/password authentication version: %d", header[0])
	}

	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(r, username); err != nil {
		return err
	}
	passwordLength := []byte{0}
	if _, err := io.ReadFull(r, passwordLength); err != nil {
		return err
	}
	password := make([]byte, int(passwordLength[0]))
	if _, err := io.ReadFull(r, password); err != nil {
		return err
	}

	if len(username) == 0 || len(password) == 0 || !auth.matches(string(username), string(password)) {
		_, _ = w.Write([]byte{0x01, 0x01})
		return errors.New("invalid username or password")
	}
	_, err := w.Write([]byte{0x01, 0x00})
	return err
}

func containsByte(values []byte, target byte) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
