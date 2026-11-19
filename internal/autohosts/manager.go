package autohosts

// This package owns Auto Hosts persistence and its immutable DNS read snapshot.
// Probing and active-server selection are performed by the runtime controller.
import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const SchemaVersion = 1
const maxStoredEndpoints = 64
const maxStoredProbeResults = 512

var ErrPinnedServer = errors.New("active server is pinned to a different DoH server")

type Config struct {
	Enabled           bool          `json:"enabled"`
	EmergencyOff      bool          `json:"emergency_off"`
	Mode              string        `json:"mode"`
	PinnedServerID    string        `json:"pinned_server_id,omitempty"`
	CheckInterval     time.Duration `json:"check_interval"`
	GracePeriod       time.Duration `json:"grace_period"`
	TTL               time.Duration `json:"ttl"`
	EndpointMaxAge    time.Duration `json:"endpoint_max_age"`
	MaxDomains        int           `json:"max_domains"`
	GeositeCategories []string      `json:"geosite_categories,omitempty"`
}
type Endpoint struct {
	ServerID  string    `json:"server_id"`
	URL       string    `json:"url"`
	Hostname  string    `json:"hostname"`
	IPv4      []string  `json:"ipv4,omitempty"`
	IPv6      []string  `json:"ipv6,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}
type ProbeResult struct {
	ServerID   string    `json:"server_id"`
	Domain     string    `json:"domain"`
	Success    bool      `json:"success"`
	CheckedAt  time.Time `json:"checked_at"`
	WebsiteIPs []string  `json:"website_ips,omitempty"`
	DurationMS int64     `json:"duration_ms,omitempty"`
	Error      string    `json:"error,omitempty"`
}
type DomainRecord struct {
	Domain      string    `json:"domain"`
	ServerID    string    `json:"server_id,omitempty"`
	Source      string    `json:"source,omitempty"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
}

const (
	DomainSourceProbe = "probe"
	DomainSourceQuery = "query"
)

type State struct {
	SchemaVersion int                     `json:"schema_version"`
	Config        Config                  `json:"config"`
	ActiveServer  string                  `json:"active_server,omitempty"`
	Endpoints     map[string]Endpoint     `json:"endpoints"`
	ProbeResults  map[string]ProbeResult  `json:"probe_results"`
	Domains       map[string]DomainRecord `json:"domains"`
	UpdatedAt     time.Time               `json:"updated_at"`
}
type Snapshot struct {
	Enabled        bool
	EmergencyOff   bool
	ActiveServer   string
	Endpoint       Endpoint
	Domains        map[string]DomainRecord
	TTL            time.Duration
	EndpointMaxAge time.Duration
	MaxDomains     int
}
type CleanupStatus struct {
	LastRun     time.Time `json:"last_run,omitempty"`
	LastDeleted int       `json:"last_deleted"`
	LastError   string    `json:"last_error,omitempty"`
}

type Manager struct {
	path          string
	mu            sync.Mutex
	state         State
	view          atomic.Pointer[Snapshot]
	cleanupStatus CleanupStatus
}

func DefaultConfig() Config {
	return Config{Mode: "auto", CheckInterval: 5 * time.Minute, GracePeriod: 30 * time.Minute, TTL: 60 * time.Second, EndpointMaxAge: 24 * time.Hour, MaxDomains: 64}
}
func New(path string) (*Manager, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("Auto Hosts state path is empty")
	}
	m := &Manager{path: path}
	b, err := os.ReadFile(path)
	missing := errors.Is(err, os.ErrNotExist)
	if err != nil && !missing {
		return nil, fmt.Errorf("read Auto Hosts state: %w", err)
	}
	if !missing {
		if err = json.Unmarshal(b, &m.state); err != nil {
			return nil, fmt.Errorf("decode Auto Hosts state: %w", err)
		}
	} else {
		m.state = State{SchemaVersion: SchemaVersion, Config: DefaultConfig(), Endpoints: map[string]Endpoint{}, ProbeResults: map[string]ProbeResult{}, Domains: map[string]DomainRecord{}}
	}
	if err = normalizeState(&m.state); err != nil {
		return nil, err
	}
	if err = m.validate(m.state); err != nil {
		return nil, err
	}
	if missing {
		if err = m.persist(m.state); err != nil {
			return nil, err
		}
	}
	m.publish()
	return m, nil
}
func normalizeState(s *State) error {
	if s.SchemaVersion == 0 {
		s.SchemaVersion = SchemaVersion
	}
	if s.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported Auto Hosts schema version %d", s.SchemaVersion)
	}
	if s.Endpoints == nil {
		s.Endpoints = map[string]Endpoint{}
	}
	if s.ProbeResults == nil {
		s.ProbeResults = map[string]ProbeResult{}
	}
	if s.Domains == nil {
		s.Domains = map[string]DomainRecord{}
	}
	if s.Config.Mode == "" {
		s.Config.Mode = "auto"
	}
	d := DefaultConfig()
	if s.Config.CheckInterval == 0 {
		s.Config.CheckInterval = d.CheckInterval
	}
	if s.Config.GracePeriod == 0 {
		s.Config.GracePeriod = d.GracePeriod
	}
	if s.Config.TTL == 0 {
		s.Config.TTL = d.TTL
	}
	if s.Config.EndpointMaxAge == 0 {
		s.Config.EndpointMaxAge = d.EndpointMaxAge
	}
	if s.Config.MaxDomains == 0 {
		s.Config.MaxDomains = d.MaxDomains
	}
	normalized := make(map[string]DomainRecord, len(s.Domains))
	for _, rec := range s.Domains {
		name, err := NormalizeDomain(rec.Domain)
		if err != nil {
			return fmt.Errorf("invalid persisted domain: %w", err)
		}
		rec.Domain = name
		if rec.Source == "" {
			rec.Source = DomainSourceProbe // schema-v1 records were probe-owned
		}
		if rec.Source != DomainSourceProbe && rec.Source != DomainSourceQuery {
			return fmt.Errorf("invalid source for persisted domain %q", name)
		}
		normalized[name] = rec
	}
	s.Domains = normalized
	categories, err := normalizeGeositeCategories(s.Config.GeositeCategories)
	if err != nil {
		return err
	}
	s.Config.GeositeCategories = categories
	return nil
}
func (m *Manager) validate(s State) error {
	c := s.Config
	if c.Mode != "auto" && c.Mode != "pinned" {
		return errors.New("Auto Hosts mode must be auto or pinned")
	}
	if c.Mode == "pinned" && strings.TrimSpace(c.PinnedServerID) == "" {
		return errors.New("pinned DoH server ID is required")
	}
	if c.CheckInterval < 10*time.Second || c.CheckInterval > 24*time.Hour || c.GracePeriod < c.CheckInterval || c.GracePeriod > 30*24*time.Hour || c.TTL < 5*time.Second || c.TTL > 10*time.Minute || c.EndpointMaxAge < time.Minute || c.EndpointMaxAge > 7*24*time.Hour || c.MaxDomains < 1 || c.MaxDomains > 4096 {
		return errors.New("invalid Auto Hosts interval, TTL, grace period or domain limit")
	}
	if len(c.GeositeCategories) > 128 {
		return errors.New("too many selected Geosite categories")
	}
	if len(s.Domains) > c.MaxDomains {
		return errors.New("Auto Hosts domain limit exceeded")
	}
	if len(s.Endpoints) > maxStoredEndpoints {
		return errors.New("Auto Hosts endpoint limit exceeded")
	}
	if len(s.ProbeResults) > maxStoredProbeResults {
		return errors.New("Auto Hosts probe result limit exceeded")
	}
	for id, ep := range s.Endpoints {
		if id == "" || ep.ServerID != id || ep.URL == "" || ep.Hostname == "" {
			return fmt.Errorf("invalid DoH endpoint %q", id)
		}
		if _, err := validateEndpoint(ep); err != nil {
			return fmt.Errorf("invalid DoH endpoint %q: %w", id, err)
		}
	}
	return nil
}
func NormalizeDomain(raw string) (string, error) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if d == "" || len(d) > 253 || strings.ContainsAny(d, " /\\\t\r\n") {
		return "", errors.New("invalid domain")
	}
	for _, label := range strings.Split(d, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid domain label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("domain must be ASCII/IDNA encoded")
			}
		}
	}
	return d, nil
}
func validateEndpoint(ep Endpoint) (Endpoint, error) {
	if ep.ServerID == "" || len(ep.ServerID) > 128 || ep.URL == "" || len(ep.URL) > 2048 || ep.Hostname == "" || len(ep.Hostname) > 253 {
		return Endpoint{}, errors.New("endpoint ID, URL and hostname are required and bounded")
	}
	parsed, parseErr := url.Parse(ep.URL)
	if parseErr != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || !strings.EqualFold(strings.TrimSuffix(parsed.Hostname(), "."), strings.TrimSuffix(ep.Hostname, ".")) {
		return Endpoint{}, errors.New("DoH endpoint URL must be HTTPS and match its hostname")
	}
	if net.ParseIP(ep.Hostname) == nil {
		if _, err := NormalizeDomain(ep.Hostname); err != nil {
			return Endpoint{}, errors.New("invalid DoH endpoint hostname")
		}
	}
	if len(ep.IPv4) > 16 || len(ep.IPv6) > 16 {
		return Endpoint{}, errors.New("too many resolved DoH endpoint IPs")
	}
	v4, v6 := []string{}, []string{}
	seen := map[string]bool{}
	for _, raw := range ep.IPv4 {
		ip := net.ParseIP(raw)
		if ip == nil || ip.To4() == nil {
			return Endpoint{}, errors.New("invalid IPv4 endpoint IP")
		}
		v := ip.To4().String()
		if !seen[v] {
			seen[v] = true
			v4 = append(v4, v)
		}
	}
	seen = map[string]bool{}
	for _, raw := range ep.IPv6 {
		ip := net.ParseIP(raw)
		if ip == nil || ip.To4() != nil {
			return Endpoint{}, errors.New("invalid IPv6 endpoint IP")
		}
		v := ip.String()
		if !seen[v] {
			seen[v] = true
			v6 = append(v6, v)
		}
	}
	if len(v4)+len(v6) == 0 {
		return Endpoint{}, errors.New("DoH endpoint has no resolved IP")
	}
	ep.IPv4, ep.IPv6 = v4, v6
	return ep, nil
}
func (m *Manager) publish() {
	s := &Snapshot{Enabled: m.state.Config.Enabled, EmergencyOff: m.state.Config.EmergencyOff, ActiveServer: m.state.ActiveServer, Endpoint: m.state.Endpoints[m.state.ActiveServer], Domains: make(map[string]DomainRecord, len(m.state.Domains)), TTL: m.state.Config.TTL, EndpointMaxAge: m.state.Config.EndpointMaxAge, MaxDomains: m.state.Config.MaxDomains}
	for d, r := range m.state.Domains {
		s.Domains[d] = r
	}
	m.view.Store(s)
}
func (m *Manager) Snapshot() *Snapshot { return m.view.Load() }

// CanRecordQuery reports whether a new user QNAME can be accepted without
// writing state. It uses the same immutable snapshot read by DNS handlers.
func (s *Snapshot) CanRecordQuery(qname string) bool {
	if s == nil || !s.Enabled || s.EmergencyOff {
		return false
	}
	name, err := NormalizeDomain(qname)
	if err != nil {
		return false
	}
	if _, exists := s.Domains[name]; exists {
		return true
	}
	return len(s.Domains) < s.MaxDomains
}

// EndpointForQuery returns the active DoH endpoint mapping for a Geosite HIT.
// Unlike Lookup, it does not require a persisted per-domain record.
func (s *Snapshot) EndpointForQuery(qtype uint16, now time.Time) ([]string, time.Duration, bool) {
	if s == nil || !s.Enabled || s.EmergencyOff {
		return nil, 0, false
	}
	if s.Endpoint.UpdatedAt.IsZero() || now.Sub(s.Endpoint.UpdatedAt) > s.EndpointMaxAge {
		return nil, 0, false
	}
	ttl := s.TTL
	if ttl < time.Second {
		ttl = time.Second
	}
	switch qtype {
	case 1:
		return append([]string(nil), s.Endpoint.IPv4...), ttl, true
	case 28:
		return append([]string(nil), s.Endpoint.IPv6...), ttl, true
	case 64, 65:
		return nil, ttl, true
	default:
		return nil, 0, false
	}
}

// Lookup returns matched=true with no IPs for family-specific NODATA.
func (s *Snapshot) Lookup(qname string, qtype uint16, now time.Time) ([]string, time.Duration, bool) {
	if s == nil || !s.Enabled || s.EmergencyOff {
		return nil, 0, false
	}
	if s.Endpoint.UpdatedAt.IsZero() || now.Sub(s.Endpoint.UpdatedAt) > s.EndpointMaxAge {
		return nil, 0, false
	}
	d, err := NormalizeDomain(qname)
	if err != nil {
		return nil, 0, false
	}
	rec, ok := s.Domains[d]
	if !ok || rec.ExpiresAt.IsZero() || !now.Before(rec.ExpiresAt) {
		return nil, 0, false
	}
	ttl := s.TTL
	if remain := rec.ExpiresAt.Sub(now); remain < ttl {
		ttl = remain
	}
	if ttl < 0 {
		ttl = 0
	}
	switch qtype {
	case 1:
		return append([]string(nil), s.Endpoint.IPv4...), ttl, true
	case 28:
		return append([]string(nil), s.Endpoint.IPv6...), ttl, true
	case 64, 65:
		return nil, ttl, true
	}
	return nil, 0, false
}
func normalizeGeositeCategories(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, raw := range values {
		name := strings.ToUpper(strings.TrimSpace(raw))
		if name == "" || len(name) > 64 {
			return nil, errors.New("invalid Geosite category")
		}
		for _, char := range name {
			if !(char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '-' || char == '!') {
				return nil, fmt.Errorf("invalid Geosite category %q", raw)
			}
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	sort.Strings(result)
	if len(result) == 0 {
		return nil, errors.New("at least one Geosite category must remain selected")
	}
	if len(result) > 128 {
		return nil, errors.New("too many selected Geosite categories")
	}
	return result, nil
}

func (m *Manager) Configure(enabled, emergencyOff *bool, pinnedServerID *string) error {
	return m.ConfigureWithGeosite(enabled, emergencyOff, pinnedServerID, nil)
}

func (m *Manager) ConfigureWithGeosite(enabled, emergencyOff *bool, pinnedServerID *string, geositeCategories *[]string) error {
	var categories []string
	var err error
	if geositeCategories != nil {
		categories, err = normalizeGeositeCategories(*geositeCategories)
		if err != nil {
			return err
		}
	}
	return m.update(func(s *State) error {
		if geositeCategories != nil {
			s.Config.GeositeCategories = append([]string(nil), categories...)
		}
		if enabled != nil {
			s.Config.Enabled = *enabled
		}
		if emergencyOff != nil {
			s.Config.EmergencyOff = *emergencyOff
		}
		if pinnedServerID != nil {
			id := strings.TrimSpace(*pinnedServerID)
			if id == "" {
				s.Config.Mode = "auto"
				s.Config.PinnedServerID = ""
			} else {
				if _, ok := s.Endpoints[id]; !ok {
					return fmt.Errorf("unknown DoH server %q", id)
				}
				s.Config.Mode = "pinned"
				s.Config.PinnedServerID = id
			}
		}
		return nil
	})
}

func (m *Manager) SetGeositeCategories(values []string) error {
	return m.ConfigureWithGeosite(nil, nil, nil, &values)
}

func (m *Manager) SetEnabled(v bool) error {
	return m.update(func(s *State) error { s.Config.Enabled = v; return nil })
}
func (m *Manager) SetEmergencyOff(v bool) error {
	return m.update(func(s *State) error { s.Config.EmergencyOff = v; return nil })
}
func (m *Manager) SetPinned(id string) error {
	return m.update(func(s *State) error {
		id = strings.TrimSpace(id)
		if id == "" {
			s.Config.Mode = "auto"
			s.Config.PinnedServerID = ""
			return nil
		}
		if _, ok := s.Endpoints[id]; !ok {
			return fmt.Errorf("unknown DoH server %q", id)
		}
		s.Config.Mode = "pinned"
		s.Config.PinnedServerID = id
		return nil
	})
}

// ApplyCycle commits endpoint, per-domain probe results and published domain set together.
// Call only from the single background controller, never from DNS request handlers.
func (m *Manager) ApplyCycle(activeID string, ep Endpoint, results []ProbeResult, now time.Time) error {
	copyResults := append([]ProbeResult(nil), results...)
	for i := range copyResults {
		if strings.TrimSpace(copyResults[i].ServerID) == "" {
			copyResults[i].ServerID = activeID
		}
	}
	return m.ApplyFullCycle(activeID, []Endpoint{ep}, copyResults, now)
}

// ApplyFullCycle atomically records every endpoint and every server×domain result,
// while publishing only successful/current-or-grace domains for the selected server.
// It is intended to be called once by the single background controller per cycle.
func (m *Manager) ApplyFullCycle(activeID string, endpoints []Endpoint, results []ProbeResult, now time.Time) error {
	return m.update(func(s *State) error {
		activeID = strings.TrimSpace(activeID)
		if activeID == "" {
			return errors.New("active server ID is empty")
		}
		seenEndpoints := make(map[string]bool, len(endpoints))
		for _, ep := range endpoints {
			checked, err := validateEndpoint(ep)
			if err != nil {
				return err
			}
			if seenEndpoints[checked.ServerID] {
				return fmt.Errorf("duplicate endpoint %q", checked.ServerID)
			}
			seenEndpoints[checked.ServerID] = true
			// Keep a zero timestamp when no successful endpoint DNS resolution was recorded.
			s.Endpoints[checked.ServerID] = checked
		}
		for id := range s.Endpoints {
			if !seenEndpoints[id] && !(s.Config.Mode == "pinned" && s.Config.PinnedServerID == id) {
				delete(s.Endpoints, id)
			}
		}
		if _, ok := s.Endpoints[activeID]; !ok {
			return fmt.Errorf("active endpoint %q is missing", activeID)
		}
		if s.Config.Mode == "pinned" && s.Config.PinnedServerID != activeID {
			return ErrPinnedServer
		}
		for _, r := range results {
			serverID := strings.TrimSpace(r.ServerID)
			if serverID == "" {
				return errors.New("probe result server ID is required")
			}
			if _, ok := s.Endpoints[serverID]; !ok {
				return fmt.Errorf("probe result references unknown server %q", serverID)
			}
			d, err := NormalizeDomain(r.Domain)
			if err != nil {
				return err
			}
			r.Domain = d
			r.ServerID = serverID
			if r.CheckedAt.IsZero() {
				r.CheckedAt = now.UTC()
			}
			if len(r.WebsiteIPs) > 32 {
				return errors.New("too many probe target IPs")
			}
			for _, ip := range r.WebsiteIPs {
				if net.ParseIP(ip) == nil {
					return errors.New("invalid temporary website IP")
				}
			}
			if len(r.Error) > 512 {
				r.Error = r.Error[:512]
			}
			s.ProbeResults[serverID+"\x00"+d] = r
			if serverID == activeID && r.Success {
				s.Domains[d] = DomainRecord{
					Domain: d, ServerID: activeID, Source: DomainSourceProbe,
					LastSuccess: r.CheckedAt.UTC(),
					ExpiresAt:   r.CheckedAt.Add(s.Config.GracePeriod).UTC(),
				}
			}
		}
		// Probe cycles may refresh fixed control domains, but must never discard
		// user-query records or records belonging to the previously active server.
		for d, record := range s.Domains {
			if record.ExpiresAt.IsZero() || !now.Before(record.ExpiresAt) {
				delete(s.Domains, d)
			}
		}
		s.ActiveServer = activeID
		for key, result := range s.ProbeResults {
			if now.Sub(result.CheckedAt) > 30*24*time.Hour {
				delete(s.ProbeResults, key)
			}
		}
		for len(s.ProbeResults) > maxStoredProbeResults {
			oldestKey := ""
			var oldest time.Time
			for key, result := range s.ProbeResults {
				if oldestKey == "" || result.CheckedAt.Before(oldest) {
					oldestKey, oldest = key, result.CheckedAt
				}
			}
			if oldestKey == "" {
				break
			}
			delete(s.ProbeResults, oldestKey)
		}
		return nil
	})
}

// RecordQuery adds or refreshes a user QNAME after the caller has confirmed a
// Geosite match. Probe-owned control domains remain governed by probe success.
func (m *Manager) RecordQuery(rawDomain string, now time.Time) error {
	domain, err := NormalizeDomain(rawDomain)
	if err != nil {
		return err
	}
	return m.update(func(s *State) error {
		if !s.Config.Enabled || s.Config.EmergencyOff {
			return errors.New("Auto Hosts is disabled")
		}
		if existing, ok := s.Domains[domain]; ok && existing.Source == DomainSourceProbe {
			return nil
		}
		if _, exists := s.Domains[domain]; !exists && len(s.Domains) >= s.Config.MaxDomains {
			return errors.New("Auto Hosts domain limit exceeded")
		}
		s.Domains[domain] = DomainRecord{
			Domain: domain, Source: DomainSourceQuery,
			LastSeen: now.UTC(), ExpiresAt: now.Add(s.Config.GracePeriod).UTC(),
		}
		return nil
	})
}

// PruneExpired performs garbage collection independently of probe success.
// Diagnostics remain in memory: an empty one-minute pass does not rewrite state.
func (m *Manager) PruneExpired(now time.Time) error {
	m.mu.Lock()
	hasExpired := false
	for _, record := range m.state.Domains {
		if record.ExpiresAt.IsZero() || !now.Before(record.ExpiresAt) {
			hasExpired = true
			break
		}
	}
	m.mu.Unlock()

	deleted := 0
	var err error
	if hasExpired {
		err = m.update(func(s *State) error {
			for domain, record := range s.Domains {
				if record.ExpiresAt.IsZero() || !now.Before(record.ExpiresAt) {
					delete(s.Domains, domain)
					deleted++
				}
			}
			return nil
		})
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		deleted = 0
	}
	status := CleanupStatus{LastRun: now.UTC(), LastDeleted: deleted}
	if err != nil {
		status.LastError = err.Error()
	}
	m.cleanupStatus = status
	return err
}

func (m *Manager) CleanupStatus() CleanupStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cleanupStatus
}

func (m *Manager) RecordProbeFailures(serverID string, domains []string, message string, now time.Time) error {
	serverID = strings.TrimSpace(serverID)
	if serverID == "" {
		return errors.New("probe failure server ID is empty")
	}
	if len(message) > 512 {
		message = message[:512]
	}
	return m.update(func(s *State) error {
		for _, raw := range domains {
			domain, err := NormalizeDomain(raw)
			if err != nil {
				return err
			}
			s.ProbeResults[serverID+"\x00"+domain] = ProbeResult{ServerID: serverID, Domain: domain, Success: false, CheckedAt: now.UTC(), Error: message}
		}
		for key, result := range s.ProbeResults {
			if now.Sub(result.CheckedAt) > 30*24*time.Hour {
				delete(s.ProbeResults, key)
			}
		}
		for len(s.ProbeResults) > maxStoredProbeResults {
			oldestKey := ""
			var oldest time.Time
			for key, result := range s.ProbeResults {
				if oldestKey == "" || result.CheckedAt.Before(oldest) {
					oldestKey, oldest = key, result.CheckedAt
				}
			}
			if oldestKey == "" {
				break
			}
			delete(s.ProbeResults, oldestKey)
		}
		return nil
	})
}

func (m *Manager) DryRun(activeID string, ep Endpoint, results []ProbeResult, now time.Time) (map[string]DomainRecord, error) {
	state := m.State()
	if activeID == "" || ep.ServerID != activeID {
		return nil, errors.New("dry-run active server and endpoint mismatch")
	}
	if state.Config.Mode == "pinned" && state.Config.PinnedServerID != activeID {
		return nil, ErrPinnedServer
	}
	if _, err := validateEndpoint(ep); err != nil {
		return nil, err
	}
	if ep.UpdatedAt.IsZero() {
		if saved, ok := state.Endpoints[activeID]; ok {
			ep.UpdatedAt = saved.UpdatedAt
		}
	}
	if ep.UpdatedAt.IsZero() || now.Sub(ep.UpdatedAt) > state.Config.EndpointMaxAge {
		return nil, errors.New("DoH endpoint IP resolution is stale")
	}
	proposed := map[string]DomainRecord{}
	for _, r := range results {
		if r.ServerID != "" && r.ServerID != activeID {
			return nil, errors.New("probe result belongs to a different server")
		}
		d, err := NormalizeDomain(r.Domain)
		if err != nil {
			return nil, err
		}
		if r.Success {
			t := r.CheckedAt
			if t.IsZero() {
				t = now
			}
			proposed[d] = DomainRecord{Domain: d, ServerID: activeID, LastSuccess: t.UTC(), ExpiresAt: t.Add(state.Config.GracePeriod).UTC()}
		}
	}
	for d, r := range state.Domains {
		// All live records are shared across active-server switches; Dry Run
		// must include the same retained set as ApplyFullCycle.
		if now.Before(r.ExpiresAt) {
			if _, ok := proposed[d]; !ok {
				proposed[d] = r
			}
		}
	}
	if len(proposed) > state.Config.MaxDomains {
		return nil, errors.New("Auto Hosts domain limit exceeded")
	}
	return proposed, nil
}
func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, _ := json.Marshal(m.state)
	var out State
	_ = json.Unmarshal(b, &out)
	return out
}
func (m *Manager) update(fn func(*State) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, err := json.Marshal(m.state)
	if err != nil {
		return err
	}
	var next State
	if err = json.Unmarshal(b, &next); err != nil {
		return err
	}
	if err = fn(&next); err != nil {
		return err
	}
	next.UpdatedAt = time.Now().UTC()
	if err = m.validate(next); err != nil {
		return err
	}
	if err = m.persist(next); err != nil {
		return err
	}
	m.state = next
	m.publish()
	return nil
}
func (m *Manager) persist(s State) error {
	if err := os.MkdirAll(filepath.Dir(m.path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(m.path), ".auto-hosts-*.tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if _, err = f.Write(append(b, '\n')); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, m.path); err != nil {
		return err
	}
	if dir, e := os.Open(filepath.Dir(m.path)); e == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	ok = true
	return nil
}
