package geosite

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type maxChunkReader struct {
	reader *bytes.Reader
	max    int
}

func (r *maxChunkReader) Read(p []byte) (int, error) {
	if len(p) > r.max {
		return 0, fmt.Errorf("reader requested %d bytes at once (maximum %d)", len(p), r.max)
	}
	return r.reader.Read(p)
}

func TestStreamingParserSkipsUnselectedCategoryInBoundedChunks(t *testing.T) {
	largeRule := makeDomainRuleFixture(2, string(bytes.Repeat([]byte("x"), 4<<20)))
	unselectedCategory := bytesField(1, []byte("UNUSED"))
	unselectedCategory = append(unselectedCategory, bytesField(2, largeRule)...)
	unselected := bytesField(1, unselectedCategory)
	data := append(unselected, fixture()...)

	reader := &maxChunkReader{reader: bytes.NewReader(data), max: 32 << 10}
	matcher, err := parseStream(reader, int64(len(data)), []string{"TEST"})
	if err != nil {
		t.Fatal(err)
	}
	if !matcher.MatchAny("www.example.com") {
		t.Fatal("selected category was not loaded")
	}
	if _, ok := matcher.categories["UNUSED"]; ok {
		t.Fatal("unselected category was materialized")
	}
}

func TestLoadWithMetadataAndFingerprintAreStreamingConsistent(t *testing.T) {
	data := fixture()
	path := filepath.Join(t.TempDir(), "geosite.dat")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	matcher, info, digest, err := LoadWithMetadata(path, []string{"TEST"})
	if err != nil {
		t.Fatal(err)
	}
	if !matcher.MatchAny("example.com") {
		t.Fatal("stream-loaded matcher did not match")
	}
	want := sha256.Sum256(data)
	if digest != want {
		t.Fatalf("digest mismatch: got %x want %x", digest, want)
	}
	if info.Size() != int64(len(data)) {
		t.Fatalf("file size=%d want=%d", info.Size(), len(data))
	}

	_, fingerprint, err := Fingerprint(path)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != want {
		t.Fatalf("fingerprint mismatch: got %x want %x", fingerprint, want)
	}
	categories, err := ListCategories(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(categories) != 1 || categories[0] != "TEST" {
		t.Fatalf("categories=%v", categories)
	}
}

func TestStreamingParserRejectsTruncatedMessage(t *testing.T) {
	data := fixture()
	data = data[:len(data)-1]
	if _, err := parseStream(bytes.NewReader(data), int64(len(data)), []string{"TEST"}); err == nil {
		t.Fatal("expected truncated protobuf message to fail")
	}
}

func TestStreamingLoadSupportsAllXrayDomainRuleKinds(t *testing.T) {
	data := categoryFixture(
		makeDomainRuleFixture(0, "needle"),
		makeDomainRuleFixture(1, `^service-[0-9]+\.example\.net$`),
		makeDomainRuleFixture(2, "example.org"),
		makeDomainRuleFixture(3, "exact.example"),
	)
	path := filepath.Join(t.TempDir(), "geosite.dat")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	matcher, err := Load(path, []string{"TEST"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		qname string
		want bool
	}{
		{name: "Substr", qname: "prefix-needle-suffix.invalid", want: true},
		{name: "Substr miss", qname: "unrelated.invalid", want: false},
		{name: "Regex", qname: "service-42.example.net", want: true},
		{name: "Regex miss", qname: "service-x.example.net", want: false},
		{name: "Domain root", qname: "example.org", want: true},
		{name: "Domain subdomain", qname: "www.example.org", want: true},
		{name: "Domain label boundary", qname: "notexample.org", want: false},
		{name: "Full exact", qname: "exact.example", want: true},
		{name: "Full subdomain", qname: "www.exact.example", want: false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := matcher.MatchAny(test.qname); got != test.want {
				t.Fatalf("MatchAny(%q)=%t, want %t", test.qname, got, test.want)
			}
		})
	}
}
