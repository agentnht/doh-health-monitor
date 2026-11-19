package geosite

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// LoadWithMetadata streams geosite.dat and retains only rules belonging to the
// selected categories. The digest covers the exact bytes parsed.
func LoadWithMetadata(path string, selected []string) (*Matcher, os.FileInfo, [32]byte, error) {
	var zero [32]byte
	file, before, err := openGeoSite(path)
	if err != nil {
		return nil, nil, zero, err
	}
	defer file.Close()

	hasher := sha256.New()
	stream := io.TeeReader(io.LimitReader(file, before.Size()), hasher)
	matcher, err := parseStream(stream, before.Size(), selected)
	if err != nil {
		return nil, nil, zero, fmt.Errorf("parse geosite.dat: %w", err)
	}
	after, err := verifyStableFile(path, file, before)
	if err != nil {
		return nil, nil, zero, err
	}
	var digest [32]byte
	copy(digest[:], hasher.Sum(nil))
	return matcher, after, digest, nil
}

// Fingerprint computes the file digest with bounded memory. It detects atomic
// replacements even when size and modification time have been preserved.
func Fingerprint(path string) (os.FileInfo, [32]byte, error) {
	var zero [32]byte
	file, before, err := openGeoSite(path)
	if err != nil {
		return nil, zero, err
	}
	defer file.Close()

	hasher := sha256.New()
	read, err := io.CopyN(hasher, file, before.Size())
	if err != nil {
		return nil, zero, fmt.Errorf("read geosite.dat for fingerprint: %w", err)
	}
	if read != before.Size() {
		return nil, zero, errors.New("geosite.dat changed while it was being read")
	}
	after, err := verifyStableFile(path, file, before)
	if err != nil {
		return nil, zero, err
	}
	var digest [32]byte
	copy(digest[:], hasher.Sum(nil))
	return after, digest, nil
}

func openGeoSite(path string) (*os.File, os.FileInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open geosite.dat: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("stat open geosite.dat: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxGeoSiteFileSize {
		_ = file.Close()
		return nil, nil, errors.New("geosite.dat is not a regular file or exceeds size limit")
	}
	return file, info, nil
}

func verifyStableFile(path string, file *os.File, before os.FileInfo) (os.FileInfo, error) {
	after, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("restat open geosite.dat: %w", err)
	}
	current, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("restat geosite.dat path: %w", err)
	}
	position, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, fmt.Errorf("check geosite.dat read position: %w", err)
	}
	if !os.SameFile(before, current) || before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) || position != after.Size() {
		return nil, errors.New("geosite.dat changed while it was being read")
	}
	return after, nil
}

func parseStream(source io.Reader, size int64, selected []string) (*Matcher, error) {
	if size <= 0 || size > maxGeoSiteFileSize {
		return nil, errors.New("invalid geosite.dat size")
	}
	wanted := make(map[string]struct{}, len(selected))
	for _, name := range selected {
		name = strings.ToUpper(strings.TrimSpace(name))
		if name != "" {
			wanted[name] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		return nil, errors.New("no geosite categories selected")
	}

	root := &streamReader{r: bufio.NewReaderSize(io.LimitReader(source, size), 32<<10), remaining: size}
	matcher := &Matcher{categories: make(map[string][]domainRule, len(wanted))}
	for root.remaining > 0 {
		field, wire, err := root.readTag()
		if err != nil {
			return nil, err
		}
		if field == 1 && wire == 2 {
			category, err := root.readMessage()
			if err != nil {
				return nil, err
			}
			code, rules, err := parseCategoryStream(category, wanted)
			if err != nil {
				return nil, err
			}
			if code != "" {
				matcher.categories[code] = append(matcher.categories[code], rules...)
			}
			continue
		}
		if err := root.skipValue(wire); err != nil {
			return nil, err
		}
	}
	for name := range wanted {
		if _, ok := matcher.categories[name]; !ok {
			return nil, fmt.Errorf("selected geosite category %q not found", name)
		}
	}
	return matcher, nil
}

// Xray's generated protobuf writer emits country_code (field 1) before domain
// entries (field 2). Knowing the category first lets us skip unselected domain
// messages without buffering their payloads.
func parseCategoryStream(message *streamReader, wanted map[string]struct{}) (string, []domainRule, error) {
	var code string
	var rules []domainRule
	for message.remaining > 0 {
		field, wire, err := message.readTag()
		if err != nil {
			return "", nil, err
		}
		switch {
		case field == 1 && wire == 2:
			value, err := message.readBytes(1024)
			if err != nil {
				return "", nil, err
			}
			code = strings.ToUpper(string(value))
		case field == 2 && wire == 2:
			domain, err := message.readMessage()
			if err != nil {
				return "", nil, err
			}
			if _, ok := wanted[code]; ok {
				rule, err := parseDomainStream(domain)
				if err != nil {
					return "", nil, fmt.Errorf("category %s: %w", code, err)
				}
				rules = append(rules, rule)
			} else if err := domain.skipRemaining(); err != nil {
				return "", nil, err
			}
		default:
			if err := message.skipValue(wire); err != nil {
				return "", nil, err
			}
		}
	}
	if _, ok := wanted[code]; ok {
		return code, rules, nil
	}
	return "", nil, nil
}

func parseDomainStream(message *streamReader) (domainRule, error) {
	var rule domainRule
	for message.remaining > 0 {
		field, wire, err := message.readTag()
		if err != nil {
			return rule, err
		}
		switch {
		case field == 1 && wire == 0:
			value, err := message.readVarint()
			if err != nil {
				return rule, err
			}
			if value > 3 {
				return rule, fmt.Errorf("unsupported domain rule type %d", value)
			}
			rule.kind = int(value)
		case field == 2 && wire == 2:
			value, err := message.readBytes(64 << 10)
			if err != nil {
				return rule, err
			}
			rule.value = string(value)
		default:
			if err := message.skipValue(wire); err != nil {
				return rule, err
			}
		}
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

type streamReader struct {
	r         io.Reader
	remaining int64
}

func (r *streamReader) readByte() (byte, error) {
	if r.remaining <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	var one [1]byte
	if _, err := io.ReadFull(r.r, one[:]); err != nil {
		r.remaining = 0
		return 0, fmt.Errorf("truncated protobuf field: %w", err)
	}
	r.remaining--
	return one[0], nil
}

func (r *streamReader) readVarint() (uint64, error) {
	var value uint64
	for i := 0; i < 10; i++ {
		b, err := r.readByte()
		if err != nil {
			return 0, err
		}
		if i == 9 && b > 1 {
			return 0, errors.New("protobuf varint overflow")
		}
		value |= uint64(b&0x7f) << uint(7*i)
		if b < 0x80 {
			return value, nil
		}
	}
	return 0, errors.New("protobuf varint overflow")
}

func (r *streamReader) readTag() (int, int, error) {
	value, err := r.readVarint()
	if err != nil {
		return 0, 0, err
	}
	field, wire := int(value>>3), int(value&7)
	if field <= 0 {
		return 0, 0, errors.New("invalid protobuf field number")
	}
	return field, wire, nil
}

func (r *streamReader) readBytes(limit int64) ([]byte, error) {
	size, err := r.readVarint()
	if err != nil {
		return nil, err
	}
	if size > uint64(r.remaining) || size > uint64(limit) {
		return nil, errors.New("truncated or oversized protobuf bytes field")
	}
	value := make([]byte, int(size))
	if _, err := io.ReadFull(r.r, value); err != nil {
		r.remaining = 0
		return nil, fmt.Errorf("truncated protobuf bytes field: %w", err)
	}
	r.remaining -= int64(size)
	return value, nil
}

func (r *streamReader) readMessage() (*streamReader, error) {
	size, err := r.readVarint()
	if err != nil {
		return nil, err
	}
	if size > uint64(r.remaining) || size > maxGeoSiteFileSize {
		return nil, errors.New("truncated or oversized protobuf message")
	}
	r.remaining -= int64(size)
	return &streamReader{r: &io.LimitedReader{R: r.r, N: int64(size)}, remaining: int64(size)}, nil
}

func (r *streamReader) skipBytes(size int64) error {
	if size < 0 || size > r.remaining {
		return errors.New("truncated protobuf field")
	}
	read, err := io.CopyN(io.Discard, r.r, size)
	r.remaining -= read
	if err != nil || read != size {
		return fmt.Errorf("truncated protobuf field: %w", io.ErrUnexpectedEOF)
	}
	return nil
}

func (r *streamReader) skipValue(wire int) error {
	switch wire {
	case 0:
		_, err := r.readVarint()
		return err
	case 1:
		return r.skipBytes(8)
	case 2:
		size, err := r.readVarint()
		if err != nil {
			return err
		}
		if size > uint64(r.remaining) {
			return errors.New("truncated protobuf bytes field")
		}
		return r.skipBytes(int64(size))
	case 5:
		return r.skipBytes(4)
	default:
		return fmt.Errorf("unsupported protobuf wire type %d", wire)
	}
}

func (r *streamReader) skipRemaining() error {
	return r.skipBytes(r.remaining)
}

func listCategories(path string) ([]string, error) {
	file, before, err := openGeoSite(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	categories, err := parseCategoriesStream(file, before.Size())
	if err != nil {
		return nil, err
	}
	if _, err := verifyStableFile(path, file, before); err != nil {
		return nil, err
	}
	return categories, nil
}

func parseCategoriesStream(source io.Reader, size int64) ([]string, error) {
	if size <= 0 || size > maxGeoSiteFileSize {
		return nil, errors.New("invalid geosite.dat size")
	}
	root := &streamReader{r: bufio.NewReaderSize(io.LimitReader(source, size), 32<<10), remaining: size}
	seen := make(map[string]struct{})
	for root.remaining > 0 {
		field, wire, err := root.readTag()
		if err != nil {
			return nil, err
		}
		if field == 1 && wire == 2 {
			category, err := root.readMessage()
			if err != nil {
				return nil, err
			}
			code, err := parseCategoryCodeStream(category)
			if err != nil {
				return nil, err
			}
			seen[code] = struct{}{}
			continue
		}
		if err := root.skipValue(wire); err != nil {
			return nil, err
		}
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

func parseCategoryCodeStream(message *streamReader) (string, error) {
	var code string
	for message.remaining > 0 {
		field, wire, err := message.readTag()
		if err != nil {
			return "", err
		}
		if field == 1 && wire == 2 {
			value, err := message.readBytes(1024)
			if err != nil {
				return "", err
			}
			code = strings.ToUpper(strings.TrimSpace(string(value)))
			continue
		}
		if err := message.skipValue(wire); err != nil {
			return "", err
		}
	}
	if code == "" {
		return "", errors.New("geosite category has an empty code")
	}
	return code, nil
}
