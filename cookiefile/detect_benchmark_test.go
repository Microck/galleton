package cookiefile

import (
	"strings"
	"testing"
)

func BenchmarkDetectNetscapeExport(b *testing.B) {
	data := []byte("# Netscape HTTP Cookie File\n" + strings.Repeat("example.com\tFALSE\t/\tTRUE\t4102444800\tsession\tvalue\n", 4096))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if Detect(data) != Netscape {
			b.Fatal("wrong format")
		}
	}
}

func TestDetectLineBoundaries(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"", Header}, {"a=b; c=d", Header}, {"\xef\xbb\xbf [ ]", JSON},
		{"\r\n# comment\r\n# Netscape HTTP Cookie File\r\n", Netscape},
		{"# comment\nexample.com\tFALSE\t/\tTRUE\t4102444800\ta\tb", Netscape},
		{"# comment\n#HttpOnly_example.com\tFALSE\t/\tTRUE\t0\ta\tb\n", Netscape},
		{"# comment\n\nlast=value", Header},
	} {
		if got := Detect([]byte(tc.input)); got != tc.want {
			t.Errorf("Detect(%q) = %s, want %s", tc.input, got, tc.want)
		}
	}
}
