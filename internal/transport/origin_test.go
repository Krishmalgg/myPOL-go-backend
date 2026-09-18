package transport

import "testing"

func TestOriginAllowed(t *testing.T) {
	allowed := []string{
		"http://localhost:3000",
		"http://192.168.*.*:3000",
		"http://10.*.*.*:3000",
	}

	cases := []struct {
		name   string
		origin string
		want   bool
	}{
		{"literal entry", "http://localhost:3000", true},
		{"lan address in range", "http://192.168.1.247:3000", true},
		{"lan address after a network change", "http://192.168.1.129:3000", true},
		{"other private range", "http://10.211.107.49:3000", true},
		{"wrong port", "http://192.168.1.247:3001", false},
		{"wrong scheme", "https://192.168.1.247:3000", false},
		{"outside the pattern", "http://evil.example:3000", false},
		// The wildcard must not span a slash, or a hostile origin could satisfy
		// a pattern with its path instead of its host.
		{"path cannot satisfy the wildcard", "http://192.168.evil.example/1.247:3000", false},
		{"empty origin", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := originAllowed(allowed, tc.origin); got != tc.want {
				t.Fatalf("originAllowed(%q) = %v, want %v", tc.origin, got, tc.want)
			}
		})
	}
}

// A lone "*" must not become an allow-all: the wildcard stops at "/", so it
// cannot match the "//" that every origin contains.
func TestOriginAllowedBareWildcardIsNotAllowAll(t *testing.T) {
	if originAllowed([]string{"*"}, "http://evil.example:3000") {
		t.Fatal(`"*" allowed an arbitrary origin`)
	}
}

func TestOriginAllowedEmptyList(t *testing.T) {
	if originAllowed(nil, "http://localhost:3000") {
		t.Fatal("an empty allow-list allowed an origin")
	}
	if originAllowed([]string{""}, "http://localhost:3000") {
		t.Fatal("an empty entry allowed an origin")
	}
}
