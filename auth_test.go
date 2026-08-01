package main

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewCredentials(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		wantErr  bool
	}{
		{name: "disabled"},
		{name: "enabled", username: "alice", password: "secret"},
		{name: "missing password", username: "alice", wantErr: true},
		{name: "missing username", password: "secret", wantErr: true},
		{name: "colon in username", username: "ali:ce", password: "secret", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := newCredentials(test.username, test.password)
			if (err != nil) != test.wantErr {
				t.Fatalf("newCredentials() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestHandleHTTPProxyRequiresAuthentication(t *testing.T) {
	auth, err := newCredentials("alice", "secret")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "http://example.com", nil)

	handleHTTPProxy(recorder, req, auth)

	if recorder.Code != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusProxyAuthRequired)
	}
}

func TestAuthenticateHTTPProxy(t *testing.T) {
	auth, err := newCredentials("alice", "secret")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		header     string
		wantOK     bool
		wantStatus int
	}{
		{name: "missing", wantStatus: http.StatusProxyAuthRequired},
		{name: "malformed", header: "Basic !!!", wantStatus: http.StatusProxyAuthRequired},
		{name: "wrong password", header: basicProxyAuth("alice", "wrong"), wantStatus: http.StatusProxyAuthRequired},
		{name: "valid", header: basicProxyAuth("alice", "secret"), wantOK: true, wantStatus: http.StatusOK},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			if test.header != "" {
				req.Header.Set("Proxy-Authorization", test.header)
			}
			recorder := httptest.NewRecorder()

			ok := authenticateHTTPProxy(recorder, req, auth)
			if ok != test.wantOK {
				t.Fatalf("authenticateHTTPProxy() = %v, want %v", ok, test.wantOK)
			}
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, test.wantStatus)
			}
			if !ok && recorder.Header().Get("Proxy-Authenticate") == "" {
				t.Fatal("missing Proxy-Authenticate response header")
			}
		})
	}
}

func TestAuthenticateHTTPProxyDisabled(t *testing.T) {
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)

	if !authenticateHTTPProxy(recorder, req, credentials{}) {
		t.Fatal("authentication should be skipped when credentials are disabled")
	}
}

func TestNegotiateSOCKS5Authentication(t *testing.T) {
	auth, err := newCredentials("alice", "secret")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		auth      credentials
		request   []byte
		wantReply []byte
		wantErr   bool
	}{
		{
			name:      "no authentication",
			request:   []byte{0x05, 0x01, socksNoAuthMethod},
			wantReply: []byte{0x05, socksNoAuthMethod},
		},
		{
			name:      "valid username and password",
			auth:      auth,
			request:   socksAuthRequest("alice", "secret"),
			wantReply: []byte{0x05, socksUserPasswordMethod, 0x01, 0x00},
		},
		{
			name:      "invalid password",
			auth:      auth,
			request:   socksAuthRequest("alice", "wrong"),
			wantReply: []byte{0x05, socksUserPasswordMethod, 0x01, 0x01},
			wantErr:   true,
		},
		{
			name:      "required method unsupported",
			auth:      auth,
			request:   []byte{0x05, 0x01, socksNoAuthMethod},
			wantReply: []byte{0x05, 0xff},
			wantErr:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var reply bytes.Buffer
			err := negotiateSOCKS5Authentication(bytes.NewReader(test.request), &reply, test.auth)
			if (err != nil) != test.wantErr {
				t.Fatalf("negotiateSOCKS5Authentication() error = %v, wantErr %v", err, test.wantErr)
			}
			if !bytes.Equal(reply.Bytes(), test.wantReply) {
				t.Fatalf("reply = %v, want %v", reply.Bytes(), test.wantReply)
			}
		})
	}
}

func basicProxyAuth(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

func socksAuthRequest(username, password string) []byte {
	request := []byte{0x05, 0x01, socksUserPasswordMethod, 0x01, byte(len(username))}
	request = append(request, username...)
	request = append(request, byte(len(password)))
	return append(request, password...)
}
