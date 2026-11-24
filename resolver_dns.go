package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	mode2MaxCacheTTL          = 300 * time.Second
	mode2ResolverAttemptLimit = 5 * time.Second
)

func (r *Runtime) resolverDNSResponse(query []byte, snapshot *Snapshot) []byte {
	if snapshot == nil {
		return r.resolverDNSResponseUncoalesced(query, snapshot)
	}
	key := fmt.Sprintf("mode2-flight:%d:%s", snapshot.resolverGeneration, cacheKey(query))
	return r.coalesceDNSResponse(key, query, func() []byte {
		return r.resolverDNSResponseUncoalesced(query, snapshot)
	})
}

func (r *Runtime) resolverDNSResponseUncoalesced(query []byte, snapshot *Snapshot) []byte {
	if snapshot == nil || len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return formerrResponse(query)
	}
	_, qtype, questionEnd, err := parseQuestion(query)
	if err != nil || questionEnd < 2 || questionEnd > len(query) {
		return formerrResponse(query)
	}
	if binary.BigEndian.Uint16(query[questionEnd-2:questionEnd]) != 1 || (qtype != 1 && qtype != 28) {
		return emptyNoErrorDNSResponse(query)
	}

	key := fmt.Sprintf("mode2:%d:%s", snapshot.resolverGeneration, cacheKey(query))
	if snapshot.cfg.Cache.Enabled {
		if cached, found := r.cacheGet(key, packetID(query), snapshot.cfg.Cache.StaleTTL); found {
			r.cacheHits.Add(1)
			return cached
		}
	}

	totalTimeout := 15 * time.Second
	if snapshot.cfg.DNSQueryTimeoutSeconds > 0 {
		totalTimeout = time.Duration(snapshot.cfg.DNSQueryTimeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	response, _, queryErr := r.queryResolverUpstreams(ctx, snapshot, query)
	cancel()
	if queryErr != nil {
		if stale, found := r.cacheGetStale(key, packetID(query), snapshot.cfg.Cache.StaleTTL); found {
			r.cacheHits.Add(1)
			return stale
		}
		r.failures.Add(1)
		return servfailResponse(query)
	}

	maxTTL := mode2MaxCacheTTL
	if snapshot.cfg.Cache.MaxTTL > 0 && time.Duration(snapshot.cfg.Cache.MaxTTL)*time.Second < maxTTL {
		maxTTL = time.Duration(snapshot.cfg.Cache.MaxTTL) * time.Second
	}
	cacheResponse := append([]byte(nil), response...)
	cacheable := prepareMode2ResponseForCache(cacheResponse, uint32(maxTTL/time.Second))
	current := r.currentSnapshot()
	if cacheable && snapshot.cfg.Cache.Enabled && current != nil &&
		current.cfg.DNSMode == "resolver" &&
		current.resolverGeneration == snapshot.resolverGeneration {
		cacheConfig := snapshot.cfg.Cache
		cacheConfig.MinTTL = 0
		cacheConfig.NegativeTTL = 0
		cacheConfig.MaxTTL = int(maxTTL / time.Second)
		r.cachePut(key, cacheResponse, cacheConfig)
	}
	return response
}

func (r *Runtime) queryResolverUpstreams(ctx context.Context, snapshot *Snapshot, query []byte) ([]byte, string, error) {
	if snapshot == nil {
		return nil, "", errors.New("mode-2 DNS snapshot is unavailable")
	}
	if len(snapshot.resolverUpstreams) == 0 {
		return nil, "", errors.New("mode-2 resolver list is empty")
	}

	resolverByID := make(map[string]*ResolverRuntime, len(snapshot.resolverUpstreams))
	order := make([]string, 0, len(snapshot.resolverUpstreams))
	for _, resolver := range snapshot.resolverUpstreams {
		if resolver == nil {
			continue
		}
		id := strings.TrimSpace(resolver.cfg.ID)
		if id == "" {
			continue
		}
		if _, exists := resolverByID[id]; exists {
			continue
		}
		resolverByID[id] = resolver
		order = append(order, id)
	}
	if len(order) == 0 {
		return nil, "", errors.New("mode-2 resolver list has no usable upstreams")
	}

	// Reuse the shared upstream cooldown. If all resolvers are cooling down,
	// upstreamsToAttempt probes only the resolver whose cooldown expires first.
	attemptOrder := r.upstreamsToAttempt(order, time.Now())
	failures := make([]string, 0, len(attemptOrder))
	for _, id := range attemptOrder {
		resolver := resolverByID[id]
		if resolver == nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			failures = append(failures, err.Error())
			break
		}

		attemptTimeout := mode2ResolverAttemptLimit
		if snapshot.cfg.DNSQueryTimeoutSeconds > 0 {
			total := time.Duration(snapshot.cfg.DNSQueryTimeoutSeconds) * time.Second
			if total < attemptTimeout {
				attemptTimeout = total
			}
		}
		if resolver.cfg.Type == "doh" && snapshot.cfg.DoHTimeoutSeconds > 0 {
			dohTimeout := time.Duration(snapshot.cfg.DoHTimeoutSeconds) * time.Second
			if dohTimeout < attemptTimeout {
				attemptTimeout = dohTimeout
			}
		}

		attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
		response, err := queryMode2Upstream(attemptCtx, resolver, query)
		cancel()
		// A SERVFAIL/REFUSED/truncated answer is specific to this QNAME (lame
		// delegation, broken DNSSEC, attacker-controlled zone). It must let this
		// one query fall through to the next upstream, but it must NOT put the
		// upstream into cooldown, otherwise any external domain can force all
		// subsequent traffic onto the fallback resolver. Only transport errors
		// and timeouts prove the upstream itself is unavailable.
		softFailure := false
		if err == nil {
			switch dnsRCode(response) {
			case 2:
				err, softFailure = errors.New("upstream returned SERVFAIL"), true
			case 5:
				err, softFailure = errors.New("upstream returned REFUSED"), true
			default:
				if dnsTruncated(response) {
					err, softFailure = errors.New("upstream response remains truncated after transport retry"), true
				} else {
					r.markUpstreamSuccess(id)
					return response, id, nil
				}
			}
		}
		if !softFailure {
			r.markUpstreamFailure(id, time.Now())
		}
		failures = append(failures, id+": "+err.Error())
	}
	return nil, "", fmt.Errorf("all mode-2 resolver upstreams failed: %s", strings.Join(failures, "; "))
}

func queryMode2Upstream(ctx context.Context, resolver *ResolverRuntime, query []byte) ([]byte, error) {
	if resolver == nil {
		return nil, errors.New("nil mode-2 resolver")
	}
	switch resolver.cfg.Type {
	case "system":
		if resolver.systemDNS == nil {
			return nil, errors.New("system resolver runtime is unavailable")
		}
		return resolver.systemDNS.query(ctx, query)
	case "udp":
		if resolver.address == "" {
			return nil, errors.New("UDP resolver address is empty")
		}
		return exchangeSystemDNS(ctx, resolver.address, query)
	case "tcp":
		if resolver.address == "" {
			return nil, errors.New("TCP resolver address is empty")
		}
		response, err := exchangeSystemDNSNetwork(ctx, resolver.address, "tcp", query)
		if err != nil {
			return nil, err
		}
		if err := validateSystemDNSResponse(query, response); err != nil {
			return nil, err
		}
		return response, nil
	case "doh":
		if resolver.upstream == nil {
			return nil, errors.New("DoH resolver runtime is unavailable")
		}
		return sendDoH(ctx, resolver.upstream, query)
	default:
		return nil, fmt.Errorf("unsupported resolver type %q", resolver.cfg.Type)
	}
}

func prepareMode2ResponseForCache(response []byte, maxTTL uint32) bool {
	if len(response) < 12 || maxTTL == 0 {
		return false
	}
	rcode := dnsRCode(response)
	answerCount := dnsAnswerCount(response)
	if rcode != 0 && rcode != 3 {
		return false
	}
	negative := rcode == 3
	if rcode == 0 {
		var err error
		negative, err = mode2NoErrorResponseIsNODATA(response)
		if err != nil {
			return false
		}
	}
	if negative {
		negativeTTL, ok := negativeSOATTL(response)
		if !ok || negativeTTL == 0 {
			return false
		}
		if negativeTTL > maxTTL {
			negativeTTL = maxTTL
		}
		if !setSOARRTTLs(response, negativeTTL) {
			return false
		}
	} else if answerCount == 0 {
		return false
	}

	positions, err := rrTTLPositions(response)
	if err != nil || len(positions) == 0 {
		return false
	}
	for _, offset := range positions {
		ttl := binary.BigEndian.Uint32(response[offset : offset+4])
		if ttl > maxTTL {
			binary.BigEndian.PutUint32(response[offset:offset+4], maxTTL)
		}
	}
	ttl, ok := minResponseTTL(response)
	return ok && ttl > 0
}

// mode2NoErrorResponseIsNODATA recognizes NOERROR responses that do not
// contain the requested RR type in Answer, including responses with CNAME
// records but no terminal A/AAAA. Such responses are cacheable only when
// prepareMode2ResponseForCache can derive a valid negative TTL from SOA.
func mode2NoErrorResponseIsNODATA(response []byte) (bool, error) {
	if len(response) < 12 || binary.BigEndian.Uint16(response[4:6]) != 1 {
		return false, errors.New("mode-2 DNS response must contain exactly one question")
	}
	_, qtype, _, err := parseQuestion(response)
	if err != nil {
		return false, err
	}
	answers, err := dnsRRsInSection(response, 0)
	if err != nil {
		return false, err
	}
	for _, answer := range answers {
		if answer.typeCode == qtype {
			return false, nil
		}
	}
	return true, nil
}

type dnsRRView struct {
	typeCode  uint16
	ttlOffset int
	rdata     int
	end       int
}

func dnsRRsInSection(packet []byte, wantedSection int) ([]dnsRRView, error) {
	if len(packet) < 12 || wantedSection < 0 || wantedSection > 2 {
		return nil, errors.New("invalid DNS message or section")
	}
	offset := 12
	questionCount := int(binary.BigEndian.Uint16(packet[4:6]))
	for i := 0; i < questionCount; i++ {
		next, err := skipName(packet, offset)
		if err != nil || next+4 > len(packet) {
			return nil, errors.New("truncated DNS question")
		}
		offset = next + 4
	}
	counts := []int{
		int(binary.BigEndian.Uint16(packet[6:8])),
		int(binary.BigEndian.Uint16(packet[8:10])),
		int(binary.BigEndian.Uint16(packet[10:12])),
	}
	records := make([]dnsRRView, 0)
	for section, count := range counts {
		for i := 0; i < count; i++ {
			next, err := skipName(packet, offset)
			if err != nil || next+10 > len(packet) {
				return nil, errors.New("truncated DNS resource record")
			}
			typeCode := binary.BigEndian.Uint16(packet[next : next+2])
			dataLength := int(binary.BigEndian.Uint16(packet[next+8 : next+10]))
			dataOffset := next + 10
			end := dataOffset + dataLength
			if end > len(packet) {
				return nil, errors.New("truncated DNS resource record data")
			}
			if section == wantedSection {
				records = append(records, dnsRRView{
					typeCode: typeCode, ttlOffset: next + 4, rdata: dataOffset, end: end,
				})
			}
			offset = end
		}
	}
	return records, nil
}

func negativeSOATTL(packet []byte) (uint32, bool) {
	records, err := dnsRRsInSection(packet, 1)
	if err != nil {
		return 0, false
	}
	var best uint32
	found := false
	for _, record := range records {
		if record.typeCode != 6 {
			continue
		}
		mnameEnd, err := skipName(packet, record.rdata)
		if err != nil {
			continue
		}
		rnameEnd, err := skipName(packet, mnameEnd)
		if err != nil || rnameEnd+20 != record.end {
			continue
		}
		soaTTL := binary.BigEndian.Uint32(packet[record.ttlOffset : record.ttlOffset+4])
		minimum := binary.BigEndian.Uint32(packet[rnameEnd+16 : rnameEnd+20])
		ttl := soaTTL
		if minimum < ttl {
			ttl = minimum
		}
		if !found || ttl < best {
			best, found = ttl, true
		}
	}
	return best, found
}

func setSOARRTTLs(packet []byte, ttl uint32) bool {
	records, err := dnsRRsInSection(packet, 1)
	if err != nil {
		return false
	}
	found := false
	for _, record := range records {
		if record.typeCode == 6 {
			binary.BigEndian.PutUint32(packet[record.ttlOffset:record.ttlOffset+4], ttl)
			found = true
		}
	}
	return found
}

func (r *Runtime) clearResolverCache() {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	for key, item := range r.cache {
		if strings.HasPrefix(key, "mode2:") {
			delete(r.cache, key)
			r.cacheBytes -= item.size
		}
	}
	if r.cacheBytes < 0 {
		r.cacheBytes = 0
	}
	maxEntries := 8192
	if snapshot := r.currentSnapshot(); snapshot != nil && snapshot.cfg.Cache.MaxEntries > 0 {
		maxEntries = snapshot.cfg.Cache.MaxEntries
	}
	r.compactCacheOrderLocked(maxEntries)
}

func (r *systemDNSResolver) pointsBackToPluginListener(server string) bool {
	host, _, _ := strings.Cut(strings.TrimSpace(server), "%")
	serverIP := net.ParseIP(host)
	if serverIP == nil {
		return false
	}
	for _, raw := range r.listenerAddresses {
		listenerHost, listenerPort, err := net.SplitHostPort(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(listenerPort)
		if err != nil || port != 53 {
			continue
		}
		listenerHost = strings.Trim(listenerHost, "[]")
		if listenerHost == "" {
			return true
		}
		if strings.EqualFold(listenerHost, "localhost") {
			if serverIP.IsLoopback() {
				return true
			}
			continue
		}
		listenerIP := net.ParseIP(listenerHost)
		if listenerIP != nil && (listenerIP.IsUnspecified() || listenerIP.Equal(serverIP)) {
			return true
		}
	}
	return false
}
