package dialers

import "testing"

func TestProxyFromEnvironment(t *testing.T) {
	tests := []struct {
		name       string
		httpProxy  string
		httpsProxy string
		noProxy    string
		allProxy   string
		addr       string
		want       string
	}{
		{
			name:       "prefers HTTPS_PROXY over HTTP_PROXY",
			httpProxy:  "http://proxy-http:8080",
			httpsProxy: "http://proxy-https:8080",
			allProxy:   "http://proxy-all:8080",
			addr:       "example.com:443",
			want:       "http://proxy-https:8080",
		},
		{
			name:      "falls back to HTTP_PROXY",
			httpProxy: "http://proxy-http:8080",
			addr:      "example.com:443",
			want:      "http://proxy-http:8080",
		},
		{
			name:       "honors NO_PROXY",
			httpProxy:  "http://proxy-http:8080",
			httpsProxy: "http://proxy-https:8080",
			noProxy:    "example.com",
			allProxy:   "http://proxy-all:8080",
			addr:       "example.com:443",
			want:       "",
		},
		{
			name:     "ignores ALL_PROXY",
			allProxy: "http://proxy-all:8080",
			addr:     "example.com:443",
			want:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, k := range []string{"http_proxy", "https_proxy", "no_proxy", "all_proxy"} {
				t.Setenv(k, "")
			}
			t.Setenv("HTTP_PROXY", tt.httpProxy)
			t.Setenv("HTTPS_PROXY", tt.httpsProxy)
			t.Setenv("NO_PROXY", tt.noProxy)
			t.Setenv("ALL_PROXY", tt.allProxy)

			got, err := proxyFromEnvironment(tt.addr)
			if err != nil {
				t.Fatalf("proxyFromEnvironment(%q): %v", tt.addr, err)
			}
			var gotStr string
			if got != nil {
				gotStr = got.String()
			}
			if gotStr != tt.want {
				t.Fatalf("proxyFromEnvironment(%q) = %q, want %q", tt.addr, gotStr, tt.want)
			}
		})
	}
}
