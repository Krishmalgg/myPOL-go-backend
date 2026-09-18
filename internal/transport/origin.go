package transport

import (
	"regexp"
	"strings"
	"sync"
)

// originAllowed reports whether origin matches any entry on the allow-list.
//
// An entry may contain `*`, which matches any run of characters except `/`.
// That exists for development, where the machine's LAN address changes with the
// network it joins and a literal list means editing configuration on every move:
// `http://192.168.*.*:3000` covers the whole private range instead. Because the
// wildcard never spans a slash, a pattern can never widen past the scheme and
// host it names — `http://192.168.*.*:3000` cannot be satisfied by
// `http://evil.com/192.168.1.1:3000`. Production allow-lists should still be
// literal origins.
func originAllowed(allowed []string, origin string) bool {
	if origin == "" {
		return false
	}
	for _, entry := range allowed {
		if entry == "" {
			continue
		}
		if entry == origin {
			return true
		}
		if strings.Contains(entry, "*") && originPattern(entry).MatchString(origin) {
			return true
		}
	}
	return false
}

// originPatterns caches the compiled form of each wildcard entry. The allow-list
// is fixed at startup but consulted on every request, so recompiling per call
// would put a regexp build on the hot path of every socket handshake.
var originPatterns sync.Map // string -> *regexp.Regexp

func originPattern(entry string) *regexp.Regexp {
	if cached, ok := originPatterns.Load(entry); ok {
		return cached.(*regexp.Regexp)
	}

	var b strings.Builder
	b.WriteString("^")
	for i, literal := range strings.Split(entry, "*") {
		if i > 0 {
			b.WriteString(`[^/]*`)
		}
		// Every literal segment is quoted, so the compile below cannot fail and
		// no character in an entry is ever treated as regexp syntax.
		b.WriteString(regexp.QuoteMeta(literal))
	}
	b.WriteString("$")

	re := regexp.MustCompile(b.String())
	originPatterns.Store(entry, re)
	return re
}
