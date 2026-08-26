package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		want       string
		wantErr    error
		wantErrMsg string
	}{
		{
			name:    "missing authorization header",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:       "valid api key",
			authHeader: "ApiKey my-secret-key",
			want:       "my-secret-key",
		},
		{
			name:       "wrong authorization type",
			authHeader: "Bearer my-token",
			wantErrMsg: "malformed authorization header",
		},
		{
			name:       "missing api key",
			authHeader: "ApiKey",
			wantErrMsg: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			got, err := GetAPIKey(headers)

			if got != tt.want {
				t.Errorf("GetAPIKey() = %q, want %q", got, tt.want)
			}

			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("GetAPIKey() error = %v, want %v", err, tt.wantErr)
				}

			case tt.wantErrMsg != "":
				if err == nil {
					t.Fatalf("GetAPIKey() error = nil, want %q", tt.wantErrMsg)
				}
				if err.Error() != tt.wantErrMsg {
					t.Errorf("GetAPIKey() error = %q, want %q", err.Error(), tt.wantErrMsg)
				}

			case err != nil:
				t.Errorf("GetAPIKey() unexpected error: %v", err)
			}
		})
	}
}
