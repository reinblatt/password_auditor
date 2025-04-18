package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		want     string
	}{
		{
			name:     "simple password",
			password: "password123",
			want:     "CBFDAC6008F9CAB4083784CBD1874F76618D2A97",
		},
		{
			name:     "empty password",
			password: "",
			want:     "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hashPassword(tt.password)
			if got != tt.want {
				t.Errorf("hashPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckPasswordPwned(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if the request is properly formatted
		if len(r.URL.Path) < 6 {
			t.Errorf("Invalid request path: %s", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Get the hash prefix from the request
		hashPrefix := r.URL.Path[len("/range/"):]

		// Simulate a response from the Have I Been Pwned API
		var response string
		if hashPrefix == "0018A" {
			// Return a response that includes our test hash
			response = "45C4D1DEF81644B54AB7F969B88D65:1\n"
		} else {
			// Return an empty response for other prefixes
			response = ""
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))
	}))
	defer server.Close()

	// Create a password checker with the test server URL
	checker := &PasswordChecker{
		client:  &http.Client{Timeout: 5 * time.Second},
		baseURL: server.URL + "/range/",
		delay:   0, // No delay needed for tests
	}

	tests := []struct {
		name           string
		hashedPassword string
		want           bool
		wantErr        bool
	}{
		{
			name:           "pwned password",
			hashedPassword: "0018A45C4D1DEF81644B54AB7F969B88D65",
			want:           true,
			wantErr:        false,
		},
		{
			name:           "not pwned password",
			hashedPassword: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			want:           false,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := checker.checkPasswordPwned(tt.hashedPassword)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkPasswordPwned() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("checkPasswordPwned() = %v, want %v", got, tt.want)
			}
		})
	}
}
