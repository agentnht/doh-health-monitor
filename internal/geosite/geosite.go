// Package geosite reads the protobuf-encoded GeoSiteList used by Xray's
// geosite.dat asset and builds an immutable, category-scoped domain matcher.
package geosite

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const maxGeoSiteFileSize = 128 << 20

type domainRule struct {
	kind  int
	value string
	re    *regexp.Regexp
}

type Matcher struct {
	categories map[string][]domainRule
}

func Load(path string, selected []string) (*Matcher, error) {
	matcher, _, _, err := LoadWithMetadata(path, selected)
	return matcher, err
}

// Parse decodes only selected categories. An empty selection is rejected to
// prevent accidentally turning an unconfigured matcher into a match-all rule.
func Parse(data []byte, selected []string) (*Matcher, error) {
	if len(data) == 0 || len(data) > maxGeoSiteFileSize {
		return nil, errors.New("invalid geosite.dat size")
	}
	wanted := make(map[string]bool, len(selected))
	for _, name := range selected {
		name = strings.ToUpper(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		wanted[name] = true
	}
	if len(wanted) == 0 {
		return nil, errors.New("no geosite categories selected")
	}
	m := &Matcher{categories: make(map[string][]domainRule, len(wanted))}
	for len(data) > 0 {
		field, wire, n, err := consumeTag(data)
		if err != nil {
			return nil, err
		}
		data = data[n:]
		if field == 1 && wire == 2 {
			payload, used, err := consumeBytes(data)
			if err != nil {
				return nil, err
			}
			data = data[used:]
			code, rules, err := parseCategory(payload, wanted)
			if err != nil {
				return nil, err
			}
			if code != "" {
				m.categories[code] = append(m.categories[code], rules...)
			}
			continue
		}
		used, err := skipValue(data, wire)
		if err != nil {
			return nil, err
		}
		data = data[used:]
	}
	for name := range wanted {
		if _, ok := m.categories[name]; !ok {
			return nil, fmt.Errorf("selected geosite category %q not found", name)
		}
	}
	return m, nil
}

func parseCategory(data []byte, wanted map[string]bool) (string, []domainRule, error) {
	var code string
	var rules []domainRule
	for len(data) > 0 {
		field, wire, n, err := consumeTag(data)
		if err != nil {
			return "", nil, err
		}
		data = data[n:]
		if field == 1 && wire == 2 {
			value, used, err := consumeBytes(data)
			if err != nil {
				return "", nil, err
			}
			code = strings.ToUpper(string(value))
			data = data[used:]
		} else if field == 2 && wire == 2 {
			value, used, err := consumeBytes(data)
			if err != nil {
				return "", nil, err
			}
			if wanted[code] {
				rule, err := parseDomain(value)
				if err != nil {
					return "", nil, fmt.Errorf("category %s: %w", code, err)
				}
				rules = append(rules, rule)
			}
			data = data[used:]
		} else {
			used, err := skipValue(data, wire)
			if err != nil {
				return "", nil, err
			}
			data = data[used:]
		}
	}
	if wanted[code] {
		return code, rules, nil
	}
	return "", nil, nil
}

func parseDomain(data []byte) (domainRule, error) {
	var rule domainRule
	for len(data) > 0 {
		field, wire, n, err := consumeTag(data)
		if err != nil {
			return rule, err
		}
		data = data[n:]
		switch {
		case field == 1 && wire == 0:
			value, used, err := consumeVarint(data)
			if err != nil {
				return rule, err
			}
			rule.kind = int(value)
			data = data[used:]
		case field == 2 && wire == 2:
			value, used, err := consumeBytes(data)
			if err != nil {
				return rule, err
			}
			rule.value = string(value)
			data = data[used:]
		default:
			used, err := skipValue(data, wire)
			if err != nil {
				return rule, err
			}
			data = data[used:]
		}
	}
	if rule.kind < 0 || rule.kind > 3 {
		return rule, fmt.Errorf("unsupported domain rule type %d", rule.kind)
	}
	if rule.kind != 1 {
		rule.value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rule.value), "."))
	}
	if rule.value == "" {
		return rule, errors.New("empty domain rule")
	}
	if rule.kind == 1 {
		compiled, err := regexp.Compile(rule.value)
		if err != nil {
			return rule, fmt.Errorf("invalid regex rule: %w", err)
		}
		rule.re = compiled
	}
	return rule, nil
}

func (m *Matcher) Match(category, qname string) bool {
	if m == nil {
		return false
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qname), "."))
	if name == "" {
		return false
	}
	for _, rule := range m.categories[strings.ToUpper(strings.TrimSpace(category))] {
		switch rule.kind {
		case 0: // Substr
			if strings.Contains(name, rule.value) {
				return true
			}
		case 1: // Regex
			if rule.re != nil && rule.re.MatchString(name) {
				return true
			}
		case 2: // Domain: exact domain and its subdomains
			if name == rule.value || strings.HasSuffix(name, "."+rule.value) {
				return true
			}
		case 3: // Full
			if name == rule.value {
				return true
			}
		}
	}
	return false
}

func consumeTag(data []byte) (int, int, int, error) {
	value, n, err := consumeVarint(data)
	if err != nil {
		return 0, 0, 0, err
	}
	field, wire := int(value>>3), int(value&7)
	if field <= 0 {
		return 0, 0, 0, errors.New("invalid protobuf field number")
	}
	return field, wire, n, nil
}

func consumeVarint(data []byte) (uint64, int, error) {
	var value uint64
	for i, b := range data {
		if i == 10 {
			return 0, 0, errors.New("protobuf varint overflow")
		}
		if b < 0x80 {
			if i == 9 && b > 1 {
				return 0, 0, errors.New("protobuf varint overflow")
			}
			return value | uint64(b)<<uint(7*i), i + 1, nil
		}
		value |= uint64(b&0x7f) << uint(7*i)
	}
	return 0, 0, errors.New("truncated protobuf varint")
}

func consumeBytes(data []byte) ([]byte, int, error) {
	size, n, err := consumeVarint(data)
	if err != nil {
		return nil, 0, err
	}
	if size > uint64(len(data)-n) {
		return nil, 0, errors.New("truncated protobuf bytes field")
	}
	end := n + int(size)
	return data[n:end], end, nil
}

func skipValue(data []byte, wire int) (int, error) {
	switch wire {
	case 0:
		_, n, err := consumeVarint(data)
		return n, err
	case 1:
		if len(data) < 8 {
			return 0, errors.New("truncated fixed64 field")
		}
		return 8, nil
	case 2:
		_, n, err := consumeBytes(data)
		return n, err
	case 5:
		if len(data) < 4 {
			return 0, errors.New("truncated fixed32 field")
		}
		return 4, nil
	default:
		return 0, fmt.Errorf("unsupported protobuf wire type %d", wire)
	}
}

// ListCategories returns the category codes present in a GeoSiteList.
func ListCategories(path string) ([]string, error) {
	return listCategories(path)
}
func ParseCategories(data []byte) ([]string, error) {
	if len(data) == 0 || len(data) > maxGeoSiteFileSize {
		return nil, errors.New("invalid geosite.dat size")
	}
	seen := make(map[string]struct{})
	for len(data) > 0 {
		field, wire, n, err := consumeTag(data)
		if err != nil {
			return nil, err
		}
		data = data[n:]
		if field == 1 && wire == 2 {
			payload, used, err := consumeBytes(data)
			if err != nil {
				return nil, err
			}
			data = data[used:]
			code, err := parseCategoryCode(payload)
			if err != nil {
				return nil, err
			}
			seen[code] = struct{}{}
			continue
		}
		used, err := skipValue(data, wire)
		if err != nil {
			return nil, err
		}
		data = data[used:]
	}
	if len(seen) == 0 {
		return nil, errors.New("geosite.dat contains no categories")
	}
	categories := make([]string, 0, len(seen))
	for code := range seen {
		categories = append(categories, code)
	}
	sort.Strings(categories)
	return categories, nil
}

func parseCategoryCode(data []byte) (string, error) {
	var code string
	for len(data) > 0 {
		field, wire, n, err := consumeTag(data)
		if err != nil {
			return "", err
		}
		data = data[n:]
		if field == 1 && wire == 2 {
			value, used, err := consumeBytes(data)
			if err != nil {
				return "", err
			}
			code = strings.ToUpper(strings.TrimSpace(string(value)))
			data = data[used:]
			continue
		}
		used, err := skipValue(data, wire)
		if err != nil {
			return "", err
		}
		data = data[used:]
	}
	if code == "" {
		return "", errors.New("geosite category has an empty code")
	}
	return code, nil
}

// MatchAny reports whether a QNAME matches at least one selected category.
func (m *Matcher) MatchAny(qname string) bool {
	if m == nil {
		return false
	}
	for category := range m.categories {
		if m.Match(category, qname) {
			return true
		}
	}
	return false
}
