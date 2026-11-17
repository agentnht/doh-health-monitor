package dohintegration

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	tunnelRemarkPrefix       = "doh-health-monitor-selftest-"
	lucXRestartApplyInterval = 30 * time.Second
	// Allow one LucX-UI polling interval plus 45 seconds for Xray apply/startup.
	diagnosticTunnelStartTimeout = lucXRestartApplyInterval + 45*time.Second
)

type diagnosticResource struct {
	Expected map[string]any
	ID       int64
	Port     int
	Tag      string
	RuleMode string
}

func directOutbound(cfg map[string]any) (map[string]any, error) {
	outbounds, _ := listValue(cfg["outbounds"])
	matches := []map[string]any{}
	all := []map[string]any{}
	for _, v := range outbounds {
		o := mapValue(v)
		if str(o["tag"]) == "direct" {
			all = append(all, o)
			if str(o["protocol"]) == "freedom" {
				matches = append(matches, o)
			}
		}
	}
	if len(matches) != 1 || len(all) != 1 {
		return nil, problem("Temporary DNS finalRule requires exactly one direct freedom outbound")
	}
	settings := mapValue(matches[0]["settings"])
	if settings == nil {
		settings = map[string]any{}
		matches[0]["settings"] = settings
	}
	return matches[0], nil
}
func finalRules(cfg map[string]any) (map[string]any, []any, error) {
	direct, err := directOutbound(cfg)
	if err != nil {
		return nil, nil, err
	}
	settings := mapValue(direct["settings"])
	rules, ok := listValue(settings["finalRules"])
	if !ok && settings["finalRules"] != nil {
		return nil, nil, problem("direct.settings.finalRules must be an array")
	}
	if !ok {
		rules = []any{}
	}
	for _, v := range rules {
		if _, ok := v.(map[string]any); !ok {
			return nil, nil, problem("direct.settings.finalRules must contain objects")
		}
	}
	return settings, rules, nil
}
func exactFinalRule(v any) bool { return canonical(v) == canonical(tempDNSFinalRule) }
func finalRuleCount(cfg map[string]any) (int, error) {
	_, rules, err := finalRules(cfg)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rules {
		if exactFinalRule(r) {
			n++
		}
	}
	return n, nil
}
func portMayMatch(v any, wanted int) bool { return portSelectorMayMatch(v, wanted) }
func ipMayMatchLoopback(v any) bool {
	values := ipValues(v)
	if len(values) == 0 {
		return true
	}
	target := net.ParseIP(dnsAddress)
	for _, item := range values {
		low := strings.ToLower(strings.TrimSpace(item))
		if strings.HasPrefix(low, "geoip:") || strings.HasPrefix(low, "ext:") {
			return true
		}
		if ip := net.ParseIP(item); ip != nil {
			if ip.Equal(target) {
				return true
			}
			continue
		}
		_, network, err := net.ParseCIDR(item)
		if err != nil {
			return true
		}
		if network.Contains(target) {
			return true
		}
	}
	return false
}
func finalRuleMayBlock(rule map[string]any) bool {
	if rule["action"] != "block" {
		return false
	}
	n := stringTokens(rule["network"])
	if len(n) > 0 && !n["tcp"] && !n["udp"] {
		return false
	}
	if rule["port"] != nil {
		if !portMayMatch(rule["port"], dnsPort) {
			if value, ok := rule["port"].(string); ok && validPortSelector(value) {
				return false
			}
			if _, ok := rule["port"].(json.Number); ok {
				return false
			}
			if _, ok := rule["port"].(int); ok {
				return false
			}
		}
	}
	if rule["ip"] == nil {
		return true
	}
	return ipMayMatchLoopback(rule["ip"])
}
func temporaryAllowUsable(rules []any) bool {
	idx := -1
	count := 0
	for i, v := range rules {
		if exactFinalRule(v) {
			idx = i
			count++
		}
	}
	if count != 1 {
		return false
	}
	for i := 0; i < idx; i++ {
		if finalRuleMayBlock(mapValue(rules[i])) {
			return false
		}
	}
	return true
}
func temporaryAllowInsertIndex(rules []any) int {
	for i, v := range rules {
		if finalRuleMayBlock(mapValue(v)) {
			return i
		}
	}
	return len(rules)
}

func addTemporaryFinalRule(api *PanelAPI, logger Logger) error {
	state, err := api.ReadState()
	if err != nil {
		return err
	}
	settings, rules, err := finalRules(state.Config)
	if err != nil {
		return err
	}
	indices := []int{}
	for i, v := range rules {
		if exactFinalRule(v) {
			indices = append(indices, i)
		}
	}
	if len(indices) > 1 {
		return problem("Multiple identical temporary DNS finalRules exist; refusing ambiguous repair")
	}
	if len(indices) == 1 {
		if temporaryAllowUsable(rules) {
			return nil
		}
		idx := indices[0]
		rule := rules[idx]
		rules = append(rules[:idx], rules[idx+1:]...)
		insert := temporaryAllowInsertIndex(rules)
		rules = append(rules, nil)
		copy(rules[insert+1:], rules[insert:])
		rules[insert] = rule
	} else {
		insert := temporaryAllowInsertIndex(rules)
		rules = append(rules, nil)
		copy(rules[insert+1:], rules[insert:])
		rules[insert] = cloneMap(tempDNSFinalRule)
	}
	settings["finalRules"] = rules
	if err := applyPanelUpdate(api, state, state.Config, "temporary DNS allow addition", logger); err != nil {
		return err
	}
	if logger != nil {
		logger.Printf("PASS: diagnostic DNS finalRule is active before matching block rules")
	}
	return nil
}
func removeTemporaryFinalRule(api *PanelAPI, logger Logger) error {
	state, err := api.ReadState()
	if err != nil {
		return err
	}
	settings, rules, err := finalRules(state.Config)
	if err != nil {
		return err
	}
	indices := []int{}
	for i, v := range rules {
		if exactFinalRule(v) {
			indices = append(indices, i)
		}
	}
	if len(indices) == 0 {
		return nil
	}
	if len(indices) != 1 {
		return problem("Multiple identical temporary DNS finalRules exist; refusing ambiguous deletion")
	}
	rules = append(rules[:indices[0]], rules[indices[0]+1:]...)
	if len(rules) == 0 {
		delete(settings, "finalRules")
	} else {
		settings["finalRules"] = rules
	}
	if err := applyPanelUpdate(api, state, state.Config, "temporary DNS allow removal", logger); err != nil {
		return err
	}
	count, err := finalRuleCountAfter(api)
	if err != nil {
		return err
	}
	if count != 0 {
		return problem("Panel read-back still contains the temporary DNS finalRule")
	}
	if logger != nil {
		logger.Printf("PASS: diagnostic finalRule removed and verified by panel API read-back")
	}
	return nil
}
func finalRuleCountAfter(api *PanelAPI) (int, error) {
	s, e := api.ReadState()
	if e != nil {
		return 0, e
	}
	return finalRuleCount(s.Config)
}

func parseTemporaryRemark(remark string) (string, string, error) {
	if !strings.HasPrefix(remark, tunnelRemarkPrefix) {
		return "", "", problem("Not a reserved temporary Tunnel remark")
	}
	suffix := strings.TrimPrefix(remark, tunnelRemarkPrefix)
	for _, mode := range []string{"added", "reused"} {
		prefix := mode + "-"
		if strings.HasPrefix(suffix, prefix) {
			token := strings.TrimPrefix(suffix, prefix)
			if len(token) < 8 || len(token) > 32 {
				return "", "", problem("Temporary Tunnel marker is malformed")
			}
			if _, err := hex.DecodeString(token); err != nil {
				return "", "", problem("Temporary Tunnel marker is malformed")
			}
			return mode, token, nil
		}
	}
	if len(suffix) >= 8 && len(suffix) <= 32 {
		if _, err := hex.DecodeString(suffix); err == nil {
			return "added", suffix, nil
		}
	}
	return "", "", problem("Temporary Tunnel marker is malformed")
}
func buildTemporaryTunnel(port int, mode string) (map[string]any, error) {
	if port < 1 || port > 65535 {
		return nil, problem("Invalid temporary Tunnel port")
	}
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return nil, problem("Could not create a temporary Tunnel marker")
	}
	marker := hex.EncodeToString(random)
	if mode != "added" && mode != "reused" {
		return nil, problem("Invalid temporary DNS rule mode")
	}
	settings, _ := json.Marshal(map[string]any{"rewriteAddress": dnsAddress, "rewritePort": 53, "allowedNetwork": "tcp,udp", "followRedirect": false, "portMap": map[string]any{}})
	return map[string]any{"remark": tunnelRemarkPrefix + mode + "-" + marker, "protocol": "tunnel", "listen": "127.0.0.1", "port": port, "settings": string(settings), "enable": true}, nil
}
func verifyTemporaryTunnel(item map[string]any, expected map[string]any, id int64) error {
	actualID, ok := asInt(item["id"])
	if !ok || actualID != id {
		return problem("Temporary Tunnel ID does not match")
	}
	for _, k := range []string{"remark", "protocol", "listen", "port"} {
		if canonical(item[k]) != canonical(expected[k]) {
			return problem("Temporary Tunnel identity changed; refusing to modify or delete it")
		}
	}
	settings, err := parseObject(item["settings"], "temporary Tunnel settings")
	if err != nil {
		return err
	}
	if str(settings["rewriteAddress"]) != dnsAddress {
		return problem("Temporary Tunnel settings do not match the expected DNS target")
	}
	port, ok := asInt(settings["rewritePort"])
	if !ok || port != 53 || str(settings["allowedNetwork"]) != "tcp,udp" || settings["followRedirect"] != false || canonical(settings["portMap"]) != "{}" {
		return problem("Temporary Tunnel settings do not match the expected DNS target")
	}
	return nil
}
func discoverTemporary(api *PanelAPI) ([]diagnosticResource, error) {
	inbounds, err := api.ListInbounds()
	if err != nil {
		return nil, err
	}
	out := []diagnosticResource{}
	seen := map[int64]bool{}
	for _, item := range inbounds {
		remark := str(item["remark"])
		if !strings.HasPrefix(remark, tunnelRemarkPrefix) {
			continue
		}
		mode, token, err := parseTemporaryRemark(remark)
		if err != nil {
			return nil, err
		}
		id, ok := asInt(item["id"])
		port, portOK := asInt(item["port"])
		if !ok || !portOK || id <= 0 || port < 1 || port > 65535 || seen[id] {
			return nil, problem("Reserved temporary Tunnel has invalid or ambiguous identity")
		}
		seen[id] = true
		settings, err := parseObject(item["settings"], "temporary Tunnel settings")
		if err != nil {
			return nil, err
		}
		expected := map[string]any{"remark": remark, "protocol": "tunnel", "listen": "127.0.0.1", "port": port, "settings": item["settings"], "enable": true}
		_ = settings
		if err := verifyTemporaryTunnel(item, expected, id); err != nil {
			return nil, err
		}
		out = append(out, diagnosticResource{Expected: expected, ID: id, Port: int(port), Tag: str(item["tag"]), RuleMode: mode})
		_ = token
	}
	return out, nil
}
func portFree(port int) bool {
	tcp, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer udp.Close()
	return true
}
func chooseTunnelPort(inbounds []map[string]any) (int, error) {
	reserved := map[int64]bool{}
	for _, item := range inbounds {
		port, ok := asInt(item["port"])
		if !ok {
			continue
		}
		listen := strings.ToLower(strings.TrimSpace(str(item["listen"])))
		if listen == "" || listen == "0.0.0.0" || listen == "::" || listen == "[::]" || listen == "127.0.0.1" || listen == "::1" || listen == "[::1]" {
			reserved[port] = true
		}
	}
	for port := 15353; port <= 15453; port++ {
		if !reserved[int64(port)] && portFree(port) {
			return port, nil
		}
	}
	return 0, problem("No free loopback TCP+UDP port is available for temporary Tunnel test")
}
func listenerHasLoopbackPort(output string, port int) bool { return listenerHasLoopback(output, port) }
func listenerHasPort(output string, port int) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && strings.HasSuffix(fields[3], ":"+strconv.Itoa(port)) {
			return true
		}
	}
	return false
}
func ssHasPort(port int, loopbackOnly bool, tcp bool) (bool, error) {
	ss, err := exec.LookPath("ss")
	if err != nil {
		return false, problem("The ss utility is required to verify diagnostic Tunnel listeners")
	}
	flag := "-lun"
	if tcp {
		flag = "-ltn"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, ss, "-H", flag).Output()
	if err != nil {
		return false, problem("Could not inspect diagnostic Tunnel listeners")
	}
	if loopbackOnly {
		return listenerHasLoopbackPort(string(out), port), nil
	}
	return listenerHasPort(string(out), port), nil
}
func waitTunnelListeners(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	lastTCP, lastUDP := false, false
	for time.Now().Before(deadline) {
		tcp, e1 := ssHasPort(port, true, true)
		udp, e2 := ssHasPort(port, true, false)
		if e1 != nil {
			return e1
		}
		if e2 != nil {
			return e2
		}
		lastTCP, lastUDP = tcp, udp
		if tcp && udp {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return problem("Temporary Tunnel TCP/UDP loopback listeners did not become active on port %d (TCP=%t, UDP=%t)", port, lastTCP, lastUDP)
}
func waitTunnelClosed(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		tcp, e1 := ssHasPort(port, false, true)
		udp, e2 := ssHasPort(port, false, false)
		if e1 != nil {
			return e1
		}
		if e2 != nil {
			return e2
		}
		if !tcp && !udp {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return problem("Temporary Tunnel was deleted but a listener remains on port %d", port)
}
func ensureDiagnosticTunnel(api *PanelAPI, logger Logger) (diagnosticResource, error) {
	inbounds, err := api.ListInbounds()
	if err != nil {
		return diagnosticResource{}, err
	}
	port, err := chooseTunnelPort(inbounds)
	if err != nil {
		return diagnosticResource{}, err
	}
	count, err := func() (int, error) {
		s, e := api.ReadState()
		if e != nil {
			return 0, e
		}
		return finalRuleCount(s.Config)
	}()
	if err != nil {
		return diagnosticResource{}, err
	}
	if count > 1 {
		return diagnosticResource{}, problem("Multiple matching temporary finalRules exist; refusing ambiguous Tunnel creation")
	}
	mode := "added"
	if count == 1 {
		mode = "reused"
	}
	ruleState, err := api.ReadState()
	if err != nil {
		return diagnosticResource{}, err
	}
	_, rules, err := finalRules(ruleState.Config)
	if err != nil {
		return diagnosticResource{}, err
	}
	if count == 0 || !temporaryAllowUsable(rules) {
		if err := addTemporaryFinalRule(api, logger); err != nil {
			return diagnosticResource{}, err
		}
	}
	expected, err := buildTemporaryTunnel(port, mode)
	if err != nil {
		return diagnosticResource{}, err
	}
	created, err := api.AddInbound(expected)
	if err != nil {
		return diagnosticResource{}, err
	}
	id, ok := asInt(created["id"])
	if !ok || id <= 0 {
		return diagnosticResource{}, problem("Created temporary Tunnel has no valid ID")
	}
	live, err := api.ListInbounds()
	if err != nil {
		return diagnosticResource{}, err
	}
	matches := 0
	for _, item := range live {
		if v, ok := asInt(item["id"]); ok && v == id {
			matches++
			if err := verifyTemporaryTunnel(item, expected, id); err != nil {
				return diagnosticResource{}, err
			}
		}
	}
	if matches != 1 {
		return diagnosticResource{}, problem("Created temporary Tunnel cannot be uniquely verified")
	}
	return diagnosticResource{Expected: expected, ID: id, Port: port, Tag: str(created["tag"]), RuleMode: mode}, nil
}

func routingRuleMayUseDiagnostic(rule map[string]any) bool {
	n := stringTokens(rule["network"])
	if len(n) > 0 && !n["tcp"] && !n["udp"] {
		return false
	}
	if rule["port"] != nil && !portMayMatch(rule["port"], dnsPort) {
		return false
	}
	if rule["ip"] != nil && !ipMayMatchLoopback(rule["ip"]) {
		return false
	}
	return true
}
func diagnosticExternalUses(cfg map[string]any, resources []diagnosticResource, inbounds []map[string]any) (map[int64][]string, []string, error) {
	ids := map[int64]bool{}
	for _, r := range resources {
		ids[r.ID] = true
	}
	routing := mapValue(cfg["routing"])
	if routing == nil {
		return nil, nil, problem("routing must be an object before diagnostic dependency analysis")
	}
	rules, ok := listValue(routing["rules"])
	if !ok && routing["rules"] != nil {
		return nil, nil, problem("routing.rules must be an array")
	}
	inboundRefs := map[int64][]string{}
	for _, inbound := range inbounds {
		tag := str(inbound["tag"])
		if tag == "" {
			continue
		}
		id, ok := asInt(inbound["id"])
		if !ok || !ids[id] {
			continue
		}
		for i, v := range rules {
			r := mapValue(v)
			if containsString(tagList(r["inboundTag"]), tag) {
				inboundRefs[id] = append(inboundRefs[id], fmt.Sprintf("routing.rules[%d].inboundTag", i))
			}
		}
	}
	finalRefs := []string{}
	for i, v := range rules {
		r := mapValue(v)
		if str(r["ruleTag"]) == dnsAllowTag || str(r["outboundTag"]) != "direct" {
			continue
		}
		if routingRuleMayUseDiagnostic(r) {
			finalRefs = append(finalRefs, fmt.Sprintf("routing.rules[%d].outboundTag", i))
		}
	}
	return inboundRefs, finalRefs, nil
}
func cleanupDiagnostic(api *PanelAPI, logger Logger) error {
	var cleanupErrors []string
	resources, err := discoverTemporary(api)
	discoveryFailed := err != nil
	if discoveryFailed {
		cleanupErrors = append(cleanupErrors, "Tunnel discovery: "+err.Error())
	}
	state, stateErr := api.ReadState()
	if stateErr != nil {
		cleanupErrors = append(cleanupErrors, "Xray settings read: "+stateErr.Error())
	}
	inbounds, inboundErr := api.ListInbounds()
	if inboundErr != nil {
		cleanupErrors = append(cleanupErrors, "inbound list read: "+inboundErr.Error())
	}
	if stateErr == nil && inboundErr == nil && !discoveryFailed {
		inboundRefs, finalRefs, refErr := diagnosticExternalUses(state.Config, resources, inbounds)
		if refErr != nil {
			cleanupErrors = append(cleanupErrors, refErr.Error())
		} else {
			ruleCount, countErr := finalRuleCount(state.Config)
			if countErr != nil {
				cleanupErrors = append(cleanupErrors, countErr.Error())
			} else if discoveryFailed {
				if logger != nil {
					logger.Printf("NOTICE: diagnostic finalRule preserved because Tunnel discovery failed")
				}
			} else if ruleCount > 1 {
				if logger != nil {
					logger.Printf("NOTICE: multiple matching diagnostic finalRules exist; preserving ambiguous rules")
				}
			} else if ruleCount == 1 && len(finalRefs) == 0 {
				if err := removeTemporaryFinalRule(api, logger); err != nil {
					cleanupErrors = append(cleanupErrors, "finalRule cleanup: "+err.Error())
				}
			} else if ruleCount == 1 && logger != nil {
				logger.Printf("NOTICE: diagnostic finalRule retained because of external use: %s", strings.Join(finalRefs, ", "))
			}
			sort.Slice(resources, func(i, j int) bool { return resources[i].ID < resources[j].ID })
			for _, res := range resources {
				refs := inboundRefs[res.ID]
				if len(refs) > 0 {
					if logger != nil {
						logger.Printf("NOTICE: diagnostic Tunnel ID %d retained due to external references: %s", res.ID, strings.Join(refs, ", "))
					}
					continue
				}
				current, e := api.ListInbounds()
				if e != nil {
					cleanupErrors = append(cleanupErrors, fmt.Sprintf("Tunnel %d list: %v", res.ID, e))
					continue
				}
				found := false
				identityMismatch := false
				for _, item := range current {
					if id, ok := asInt(item["id"]); ok && id == res.ID {
						found = true
						if e := verifyTemporaryTunnel(item, res.Expected, res.ID); e != nil {
							identityMismatch = true
							cleanupErrors = append(cleanupErrors, fmt.Sprintf("Tunnel %d identity: %v", res.ID, e))
						}
					}
				}
				if identityMismatch || !found {
					continue
				}
				if e := api.DeleteInbound(res.ID); e != nil {
					cleanupErrors = append(cleanupErrors, fmt.Sprintf("Tunnel %d delete: %v", res.ID, e))
					continue
				}
				remaining, e := api.ListInbounds()
				if e != nil {
					cleanupErrors = append(cleanupErrors, fmt.Sprintf("Tunnel %d read-back: %v", res.ID, e))
					continue
				}
				stillPresent := false
				for _, item := range remaining {
					if id, ok := asInt(item["id"]); ok && id == res.ID {
						stillPresent = true
					}
				}
				if stillPresent {
					cleanupErrors = append(cleanupErrors, fmt.Sprintf("Tunnel %d removal could not be verified", res.ID))
					continue
				}
				if e := waitTunnelClosed(res.Port, 10*time.Second); e != nil {
					cleanupErrors = append(cleanupErrors, e.Error())
					continue
				}
				if logger != nil {
					logger.Printf("PASS: diagnostic Tunnel inbound ID %d removed and verified", res.ID)
				}
			}
		}
	}
	if len(cleanupErrors) > 0 {
		return problem("Diagnostic cleanup incomplete: %s", strings.Join(cleanupErrors, "; "))
	}
	if logger != nil {
		logger.Printf("PASS: diagnostic Tunnel/finalRule cleanup completed from live external-reference analysis")
	}
	return nil
}

func dnsQueryPacket(name string) (uint16, []byte, error) {
	if strings.TrimSpace(name) == "" || len(name) > 253 {
		return 0, nil, problem("Invalid DNS self-test hostname")
	}
	idBytes := make([]byte, 2)
	if _, err := rand.Read(idBytes); err != nil {
		return 0, nil, problem("Could not generate DNS self-test transaction ID")
	}
	id := binary.BigEndian.Uint16(idBytes)
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[0:2], id)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" || len(label) > 63 {
			return 0, nil, problem("Invalid DNS self-test hostname label")
		}
		packet = append(packet, byte(len(label)))
		packet = append(packet, []byte(label)...)
	}
	packet = append(packet, 0, 0, 1, 0, 1)
	return id, packet, nil
}
func skipDNSName(packet []byte, offset int) (int, error) {
	for {
		if offset >= len(packet) {
			return 0, problem("DNS response contains a truncated name")
		}
		size := int(packet[offset])
		if size&0xc0 == 0xc0 {
			if offset+1 >= len(packet) {
				return 0, problem("DNS response contains a truncated compression pointer")
			}
			return offset + 2, nil
		}
		if size&0xc0 != 0 {
			return 0, problem("DNS response contains invalid label encoding")
		}
		offset++
		if size == 0 {
			return offset, nil
		}
		if size > 63 || offset+size > len(packet) {
			return 0, problem("DNS response contains invalid label length")
		}
		offset += size
	}
}
func parseDNSA(packet []byte, expected uint16) ([]string, error) {
	if len(packet) < 12 {
		return nil, problem("DNS self-test response is shorter than a header")
	}
	id := binary.BigEndian.Uint16(packet[:2])
	flags := binary.BigEndian.Uint16(packet[2:4])
	qd := binary.BigEndian.Uint16(packet[4:6])
	an := binary.BigEndian.Uint16(packet[6:8])
	if id != expected || flags&0x8000 == 0 {
		return nil, problem("DNS self-test response does not match the query")
	}
	if flags&0xf != 0 {
		return nil, problem("DNS self-test returned RCODE %d", flags&0xf)
	}
	if qd != 1 {
		return nil, problem("DNS self-test response has an unexpected question count")
	}
	offset, err := skipDNSName(packet, 12)
	if err != nil {
		return nil, err
	}
	if offset+4 > len(packet) {
		return nil, problem("DNS self-test question is truncated")
	}
	offset += 4
	answers := []string{}
	for i := 0; i < int(an); i++ {
		offset, err = skipDNSName(packet, offset)
		if err != nil {
			return nil, err
		}
		if offset+10 > len(packet) {
			return nil, problem("DNS self-test resource record is truncated")
		}
		typ := binary.BigEndian.Uint16(packet[offset : offset+2])
		class := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		length := int(binary.BigEndian.Uint16(packet[offset+8 : offset+10]))
		offset += 10
		if offset+length > len(packet) {
			return nil, problem("DNS self-test resource data is truncated")
		}
		if typ == 1 && class == 1 && length == 4 {
			ip := net.IP(packet[offset : offset+4])
			answers = append(answers, ip.String())
		}
		offset += length
	}
	if len(answers) == 0 {
		return nil, problem("DNS self-test returned no positive A record")
	}
	return answers, nil
}
func readExact(conn net.Conn, size int) ([]byte, error) {
	buf := make([]byte, size)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, problem("DNS TCP self-test response was truncated")
	}
	return buf, nil
}
func queryDNSA(port int, tcp bool, name string) ([]string, error) {
	id, query, err := dnsQueryPacket(name)
	if err != nil {
		return nil, err
	}
	endpoint := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if tcp {
		conn, err := net.DialTimeout("tcp", endpoint, 4*time.Second)
		if err != nil {
			return nil, problem("TCP DNS self-test could not connect to %s", endpoint)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		frame := make([]byte, 2)
		binary.BigEndian.PutUint16(frame, uint16(len(query)))
		frame = append(frame, query...)
		if _, err := conn.Write(frame); err != nil {
			return nil, problem("TCP DNS self-test query write failed")
		}
		length, err := readExact(conn, 2)
		if err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(length))
		if n < 12 {
			return nil, problem("DNS TCP self-test returned an invalid response length")
		}
		response, err := readExact(conn, n)
		if err != nil {
			return nil, err
		}
		return parseDNSA(response, id)
	}
	conn, err := net.DialTimeout("udp", endpoint, 4*time.Second)
	if err != nil {
		return nil, problem("UDP DNS self-test could not connect to %s", endpoint)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil, problem("UDP DNS self-test query write failed")
	}
	response := make([]byte, 65535)
	n, err := conn.Read(response)
	if err != nil {
		return nil, problem("UDP DNS self-test timed out or failed")
	}
	return parseDNSA(response[:n], id)
}
func runTunnelDNSSelfTest(port int, logger Logger) error {
	udp, err := queryDNSA(port, false, "example.com")
	if err != nil {
		return problem("UDP Tunnel DNS self-test failed: %v", err)
	}
	logger.Printf("PASS: UDP Tunnel DNS self-test returned a positive A answer: %s", strings.Join(udp, ", "))
	tcp, err := queryDNSA(port, true, "www.example.com")
	if err != nil {
		return problem("TCP Tunnel DNS self-test failed: %v", err)
	}
	logger.Printf("PASS: TCP Tunnel DNS self-test returned a positive A answer: %s", strings.Join(tcp, ", "))
	return nil
}

func applyPanelUpdate(api *PanelAPI, before State, config map[string]any, label string, logger Logger) error {
	expected := panelNormalize(config)
	apiErr := api.Update(config, before.OutboundTestURL)
	after, readErr := api.ReadState()
	if readErr != nil {
		return problem("%s could not be verified by a fresh panel API read: %v", label, readErr)
	}
	if canonical(after.Config) != canonical(expected) {
		if apiErr != nil {
			return problem("%s read-back mismatch (panel update also reported an API error); no previous config was restored: %v", label, apiErr)
		}
		return problem("%s read-back does not match the planned state; no previous config was restored", label)
	}
	if logger != nil {
		if apiErr != nil {
			logger.Printf("NOTICE: %s returned an API error, but live read-back confirms the requested state", label)
		} else {
			logger.Printf("PASS: %s verified by panel API read-back", label)
		}
	}
	return nil
}
func notifyRestart(logger Logger, action string) {
	logger.Printf("NOTICE: %s may cause LucX-UI to automatically restart Xray; this plugin does not restart Xray directly", action)
}

func Integrate(api *PanelAPI, opts Options, logger Logger) error {
	logger.Printf("Directive: INTEGRATE")
	state, err := api.ReadState()
	if err != nil {
		return err
	}
	plan := buildPlan(state.Config, true)
	for _, c := range plan.Changes {
		logger.Printf("PLAN: %s", c)
	}
	for _, w := range plan.Warnings {
		logger.Printf("NOTE: %s", w)
	}
	for _, b := range plan.Blockers {
		logger.Printf("BLOCK: %s", b)
	}
	if len(plan.Blockers) > 0 {
		return problem("Integrate stopped: desired-state plan contains blockers; no panel mutation was sent")
	}
	needUpdate := canonical(state.Config) != canonical(plan.Expected)
	existing, err := discoverTemporary(api)
	if err != nil {
		return err
	}
	if len(existing) > 1 {
		return problem("Multiple diagnostic Tunnel inbounds exist; refusing ambiguous test setup")
	}
	if needUpdate {
		notifyRestart(logger, "Integrate panel changes")
		if err := applyPanelUpdate(api, state, plan.Proposed, "permanent DNS integration", logger); err != nil {
			return err
		}
	} else {
		logger.Printf("PASS: permanent DNS integration already matches the desired live state")
	}
	logger.Printf("PASS: permanent DNS integration is applied; starting UDP/TCP diagnostics")
	var testErr error
	if len(existing) == 0 {
		var resource diagnosticResource
		resource, testErr = ensureDiagnosticTunnel(api, logger)
		if testErr == nil {
			existing = []diagnosticResource{resource}
		}
	}
	if testErr == nil {
		if len(existing) != 1 {
			testErr = problem("Expected one diagnostic Tunnel, found %d", len(existing))
		} else {
			logger.Printf("NOTICE: waiting up to %s for LucX-UI to apply the temporary Tunnel", diagnosticTunnelStartTimeout)
			testErr = waitTunnelListeners(existing[0].Port, diagnosticTunnelStartTimeout)
			if testErr == nil {
				logger.Printf("PASS: diagnostic Tunnel TCP/UDP loopback listeners are active on port %d", existing[0].Port)
				testErr = runTunnelDNSSelfTest(existing[0].Port, logger)
			}
		}
	}
	cleanupErr := cleanupDiagnostic(api, logger)
	if testErr != nil && cleanupErr != nil {
		return problem("Permanent DNS integration remains applied. DNS self-test failed: %v; diagnostic cleanup also failed: %v", testErr, cleanupErr)
	}
	if testErr != nil {
		return problem("Permanent DNS integration remains applied, but DNS self-test failed: %v", testErr)
	}
	if cleanupErr != nil {
		return problem("UDP/TCP DNS self-tests succeeded, but diagnostic cleanup failed: %v", cleanupErr)
	}
	logger.Printf("PASS: Integrate completed and UDP/TCP DNS self-tests succeeded")
	return nil
}

func Remove(api *PanelAPI, logger Logger) error {
	logger.Printf("Directive: REMOVE")
	state, err := api.ReadState()
	if err != nil {
		return err
	}
	plan := buildRemovePlan(state.Config)
	for _, i := range plan.RouteIndexes {
		logger.Printf("PLAN: remove routing.rules[%d] (global TCP/UDP port 53)", i)
	}
	for _, tag := range plan.OutboundTags {
		logger.Printf("PLAN: remove unshared DNS outbound %q", tag)
	}
	for _, i := range plan.ServerIndexes {
		logger.Printf("PLAN: remove dns.servers[%d] (127.0.0.1:5355)", i)
	}
	for _, w := range plan.Warnings {
		logger.Printf("NOTE: %s", w)
	}
	for _, b := range plan.Blockers {
		logger.Printf("KEEP: %s", b)
	}
	if plan.Blocked {
		return problem("Remove stopped: the desired Integrate plan has blockers; no panel mutation was sent")
	}
	if len(plan.RouteIndexes)+len(plan.OutboundTags)+len(plan.ServerIndexes) == 0 {
		logger.Printf("PASS: Remove found no unshared permanent DNS resources to remove")
		return nil
	}
	config := cloneMap(state.Config)
	routing := mapValue(config["routing"])
	rules, _ := listValue(routing["rules"])
	sort.Sort(sort.Reverse(sort.IntSlice(plan.RouteIndexes)))
	for _, i := range plan.RouteIndexes {
		if i < 0 || i >= len(rules) {
			return problem("Routing rules changed after Remove planning")
		}
		rules = append(rules[:i], rules[i+1:]...)
	}
	routing["rules"] = rules
	outbounds, _ := listValue(config["outbounds"])
	for _, tag := range plan.OutboundTags {
		matches := []int{}
		for i, v := range outbounds {
			o := mapValue(v)
			if str(o["tag"]) == tag && outboundMatchesDNS(o) {
				matches = append(matches, i)
			}
		}
		if len(matches) != 1 {
			return problem("Planned outbound %q changed after Remove planning", tag)
		}
		refs := outboundReferenceReasons(config, tag, map[int]bool{})
		if len(refs) > 0 {
			return problem("Planned outbound %q gained external references: %s", tag, strings.Join(refs, ", "))
		}
		outbounds = append(outbounds[:matches[0]], outbounds[matches[0]+1:]...)
	}
	config["outbounds"] = outbounds
	dns := mapValue(config["dns"])
	if len(plan.ServerIndexes) > 0 {
		servers, _ := listValue(dns["servers"])
		sort.Sort(sort.Reverse(sort.IntSlice(plan.ServerIndexes)))
		for _, i := range plan.ServerIndexes {
			if i < 0 || i >= len(servers) {
				return problem("DNS servers changed after Remove planning")
			}
			ip, port, ok := serverEndpoint(servers[i])
			if !ok || ip != dnsAddress || port != dnsPort || !serverGeneral(servers[i]) || len(dnsServerReferenceReasons(config, servers[i])) > 0 {
				return problem("Planned local DNS server changed or gained external use")
			}
			servers = append(servers[:i], servers[i+1:]...)
		}
		dns["servers"] = servers
	}
	notifyRestart(logger, "Remove panel changes")
	if err := applyPanelUpdate(api, state, config, "permanent DNS integration removal", logger); err != nil {
		return err
	}
	after, err := api.ReadState()
	if err != nil {
		return err
	}
	final := buildRemovePlan(after.Config)
	for _, b := range final.Blockers {
		logger.Printf("KEEP: %s", b)
	}
	logger.Printf("PASS: Remove removed only unshared permanent DNS resources selected by the live desired-state plan")
	return nil
}
