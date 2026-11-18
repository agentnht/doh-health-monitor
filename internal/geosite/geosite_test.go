package geosite

import (
	"os"
	"path/filepath"
	"testing"
)

func varint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}
func bytesField(field int, value []byte) []byte {
	out := varint(uint64(field<<3 | 2))
	out = append(out, varint(uint64(len(value)))...)
	return append(out, value...)
}
func varintField(field int, value uint64) []byte {
	out := varint(uint64(field << 3))
	return append(out, varint(value)...)
}
func fixture() []byte {
	domain := append(varintField(1, 2), bytesField(2, []byte("example.com"))...)
	category := append(bytesField(1, []byte("TEST")), bytesField(2, domain)...)
	return bytesField(1, category)
}
func TestParseAndMatchDomainRules(t *testing.T) {
	m, err := Parse(fixture(), []string{"test"})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match("TEST", "example.com.") || !m.Match("test", "www.example.com") {
		t.Fatal("domain rule did not match")
	}
	if m.Match("TEST", "notexample.com") {
		t.Fatal("domain suffix matched without label boundary")
	}
}
func TestLoadRejectsMissingCategoryAndOversizedFile(t *testing.T) {
	if _, err := Parse(fixture(), []string{"MISSING"}); err == nil {
		t.Fatal("expected missing category error")
	}
	path := filepath.Join(t.TempDir(), "geosite.dat")
	if err := os.WriteFile(path, []byte{0}, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, []string{"TEST"}); err == nil {
		t.Fatal("expected invalid protobuf error")
	}
}
func TestParseRejectsEmptySelection(t *testing.T) {
	if _, err := Parse(fixture(), nil); err == nil {
		t.Fatal("expected empty selection error")
	}
}

func TestParseCategoriesAndMatchAny(t *testing.T) {
	categories, err := ParseCategories(fixture())
	if err != nil {
		t.Fatal(err)
	}
	if len(categories) != 1 || categories[0] != "TEST" {
		t.Fatalf("categories = %#v; want [TEST]", categories)
	}
	matcher, err := Parse(fixture(), categories)
	if err != nil {
		t.Fatal(err)
	}
	if !matcher.MatchAny("www.example.com") || matcher.MatchAny("notexample.com") {
		t.Fatal("MatchAny did not apply the selected category suffix boundary")
	}
}

func makeDomainRuleFixture(kind uint64, value string) []byte {
	rule := varintField(1, kind)
	return append(rule, bytesField(2, []byte(value))...)
}

func categoryFixture(rules ...[]byte) []byte {
	category := bytesField(1, []byte("TEST"))
	for _, rule := range rules {
		category = append(category, bytesField(2, rule)...)
	}
	return bytesField(1, category)
}

func TestParseSupportsAllXrayDomainRuleKinds(t *testing.T) {
	data := categoryFixture(
		makeDomainRuleFixture(0, "exact.example"),
		makeDomainRuleFixture(1, `^service-[0-9]+\.example\.net$`),
		makeDomainRuleFixture(2, "example.org"),
		makeDomainRuleFixture(3, "needle"),
	)
	matcher, err := Parse(data, []string{"TEST"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		want bool
	}{
		{name: "Full exact", want: matcher.Match("TEST", "exact.example")},
		{name: "Full rejects subdomain", want: !matcher.Match("TEST", "www.exact.example")},
		{name: "Regex", want: matcher.Match("TEST", "service-42.example.net")},
		{name: "Regex rejects non-match", want: !matcher.Match("TEST", "service-x.example.net")},
		{name: "Domain root", want: matcher.Match("TEST", "example.org")},
		{name: "Domain suffix", want: matcher.Match("TEST", "www.example.org")},
		{name: "Domain label boundary", want: !matcher.Match("TEST", "notexample.org")},
		{name: "Plain substring", want: matcher.Match("TEST", "prefix-needle-suffix.invalid")},
		{name: "Plain rejects unrelated", want: !matcher.Match("TEST", "unrelated.invalid")},
	}
	for _, test := range cases {
		if !test.want {
			t.Errorf("%s: matcher returned unexpected result", test.name)
		}
	}
}

func TestParseRejectsInvalidRegexAndUnknownRuleKind(t *testing.T) {
	if _, err := Parse(categoryFixture(makeDomainRuleFixture(1, "[")), []string{"TEST"}); err == nil {
		t.Fatal("expected invalid regular expression to be rejected")
	}
	if _, err := Parse(categoryFixture(makeDomainRuleFixture(4, "example.com")), []string{"TEST"}); err == nil {
		t.Fatal("expected unsupported Xray domain rule type to be rejected")
	}
}
