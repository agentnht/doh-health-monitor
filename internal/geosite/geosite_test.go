package geosite

import (
	"os"
	"path/filepath"
	"testing"
)

func varint(v uint64) []byte {
	var out []byte
	for v >= 0x80 { out = append(out, byte(v)|0x80); v >>= 7 }
	return append(out, byte(v))
}
func bytesField(field int, value []byte) []byte {
	out := varint(uint64(field<<3|2)); out = append(out, varint(uint64(len(value)))...); return append(out, value...)
}
func varintField(field int, value uint64) []byte {
	out := varint(uint64(field<<3)); return append(out, varint(value)...)
}
func fixture() []byte {
	domain := append(varintField(1, 2), bytesField(2, []byte("example.com"))...)
	category := append(bytesField(1, []byte("TEST")), bytesField(2, domain)...)
	return bytesField(1, category)
}
func TestParseAndMatchDomainRules(t *testing.T) {
	m, err := Parse(fixture(), []string{"test"})
	if err != nil { t.Fatal(err) }
	if !m.Match("TEST", "example.com.") || !m.Match("test", "www.example.com") { t.Fatal("domain rule did not match") }
	if m.Match("TEST", "notexample.com") { t.Fatal("domain suffix matched without label boundary") }
}
func TestLoadRejectsMissingCategoryAndOversizedFile(t *testing.T) {
	if _, err := Parse(fixture(), []string{"MISSING"}); err == nil { t.Fatal("expected missing category error") }
	path := filepath.Join(t.TempDir(), "geosite.dat")
	if err := os.WriteFile(path, []byte{0}, 0600); err != nil { t.Fatal(err) }
	if _, err := Load(path, []string{"TEST"}); err == nil { t.Fatal("expected invalid protobuf error") }
}
func TestParseRejectsEmptySelection(t *testing.T) {
	if _, err := Parse(fixture(), nil); err == nil { t.Fatal("expected empty selection error") }
}
