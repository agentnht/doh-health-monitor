package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
)

const dnsListenerStateVersion = 1
const dnsListenerBindAttempts = 32

type dnsListenerState struct {
	Version int    `json:"version"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
}

func bindDNSListeners(cfg Config, dataDir string) (*net.UDPConn, net.Listener, string, string, error) {
	if cfg.DNSPortMode != "auto" {
		udpAddr, err := net.ResolveUDPAddr("udp", cfg.DNSListenUDP)
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("resolve UDP address %q: %w", cfg.DNSListenUDP, err)
		}
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("listen UDP %q: %w", cfg.DNSListenUDP, err)
		}
		tcpListener, err := net.Listen("tcp", cfg.DNSListenTCP)
		if err != nil {
			_ = udpConn.Close()
			return nil, nil, "", "", fmt.Errorf("listen TCP %q: %w", cfg.DNSListenTCP, err)
		}
		return udpConn, tcpListener, udpConn.LocalAddr().String(), tcpListener.Addr().String(), nil
	}

	udpHost, udpPort, err := net.SplitHostPort(cfg.DNSListenUDP)
	if err != nil {
		return nil, nil, "", "", err
	}
	tcpHost, tcpPort, err := net.SplitHostPort(cfg.DNSListenTCP)
	if err != nil {
		return nil, nil, "", "", err
	}
	ip := net.ParseIP(udpHost)
	if udpHost == "" || udpHost != tcpHost || udpPort != "0" || tcpPort != "0" || ip == nil || !ip.Equal(net.ParseIP("127.0.0.1")) {
		return nil, nil, "", "", errors.New("auto DNS mode requires matching loopback IP listeners on port 0")
	}
	if dataDir == "" {
		return nil, nil, "", "", errors.New("auto DNS mode requires a persistent plugin data directory")
	}
	statePath := filepath.Join(dataDir, "dns-listener.json")
	state, exists, err := readDNSListenerState(statePath)
	if err != nil {
		return nil, nil, "", "", err
	}
	if exists {
		if state.Host != udpHost {
			return nil, nil, "", "", fmt.Errorf("saved DNS listener host %q differs from configured host %q; reconcile the Xray endpoint and dns-listener.json before restarting", state.Host, udpHost)
		}
		udpConn, tcpListener, err := bindSavedDNSListeners(state)
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("cannot restore saved DNS listener %s:%d: %w; refusing to choose a different port because Xray may still reference this endpoint", state.Host, state.Port, err)
		}
		return udpConn, tcpListener, udpConn.LocalAddr().String(), tcpListener.Addr().String(), nil
	}

	var lastErr error
	for attempt := 0; attempt < dnsListenerBindAttempts; attempt++ {
		udpConn, bindErr := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: 0})
		if bindErr != nil {
			return nil, nil, "", "", fmt.Errorf("reserve UDP loopback socket: %w", bindErr)
		}
		udpAddr, ok := udpConn.LocalAddr().(*net.UDPAddr)
		if !ok || udpAddr.Port < 1 {
			_ = udpConn.Close()
			return nil, nil, "", "", errors.New("UDP listener returned an invalid ephemeral port")
		}
		tcpAddress := net.JoinHostPort(udpHost, strconv.Itoa(udpAddr.Port))
		tcpListener, tcpErr := net.Listen("tcp", tcpAddress)
		if tcpErr != nil {
			_ = udpConn.Close()
			lastErr = tcpErr
			continue
		}
		state := dnsListenerState{Version: dnsListenerStateVersion, Host: udpHost, Port: udpAddr.Port}
		data, marshalErr := json.MarshalIndent(state, "", "  ")
		if marshalErr == nil {
			marshalErr = writeAtomicFile(statePath, append(data, '\n'), 0600)
		}
		if marshalErr != nil {
			_ = udpConn.Close()
			_ = tcpListener.Close()
			return nil, nil, "", "", fmt.Errorf("persist selected DNS listener endpoint: %w", marshalErr)
		}
		return udpConn, tcpListener, udpConn.LocalAddr().String(), tcpListener.Addr().String(), nil
	}
	return nil, nil, "", "", fmt.Errorf("could not reserve matching UDP/TCP DNS listener after %d attempts: %w", dnsListenerBindAttempts, lastErr)
}

func readDNSListenerState(path string) (dnsListenerState, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return dnsListenerState{}, false, nil
	}
	if err != nil {
		return dnsListenerState{}, false, fmt.Errorf("read saved DNS listener state: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state dnsListenerState
	if err := decoder.Decode(&state); err != nil {
		return dnsListenerState{}, false, fmt.Errorf("decode saved DNS listener state: %w", err)
	}
	if state.Version != dnsListenerStateVersion || state.Host == "" || state.Port < 1 || state.Port > 65535 {
		return dnsListenerState{}, false, errors.New("saved DNS listener state has an unsupported version or invalid endpoint")
	}
	ip := net.ParseIP(state.Host)
	if ip == nil || !ip.Equal(net.ParseIP("127.0.0.1")) {
		return dnsListenerState{}, false, errors.New("saved DNS listener state must contain 127.0.0.1")
	}
	return state, true, nil
}

func bindSavedDNSListeners(state dnsListenerState) (*net.UDPConn, net.Listener, error) {
	address := net.JoinHostPort(state.Host, strconv.Itoa(state.Port))
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, nil, err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, nil, err
	}
	tcpListener, err := net.Listen("tcp", address)
	if err != nil {
		_ = udpConn.Close()
		return nil, nil, err
	}
	return udpConn, tcpListener, nil
}

func effectiveDNSListenerAddresses(dataDir string, cfg Config) (string, string, error) {
	cfg = normalizeDNSPortMode(cfg)
	if cfg.DNSPortMode != "auto" {
		return cfg.DNSListenUDP, cfg.DNSListenTCP, nil
	}
	udpHost, udpPort, err := net.SplitHostPort(cfg.DNSListenUDP)
	if err != nil {
		return "", "", fmt.Errorf("configured UDP DNS listener: %w", err)
	}
	tcpHost, tcpPort, err := net.SplitHostPort(cfg.DNSListenTCP)
	if err != nil {
		return "", "", fmt.Errorf("configured TCP DNS listener: %w", err)
	}
	if udpHost != "127.0.0.1" || tcpHost != udpHost || udpPort != "0" || tcpPort != "0" {
		return "", "", errors.New("auto DNS mode requires matching 127.0.0.1 listeners on port 0")
	}
	state, exists, err := readDNSListenerState(filepath.Join(dataDir, "dns-listener.json"))
	if err != nil {
		return "", "", err
	}
	if !exists {
		return "", "", errors.New("auto DNS listener has not selected a port yet; restart the plugin before running DNS checks")
	}
	if state.Host != udpHost {
		return "", "", fmt.Errorf("saved DNS listener host %q differs from configured host %q", state.Host, udpHost)
	}
	address := net.JoinHostPort(state.Host, strconv.Itoa(state.Port))
	return address, address, nil
}
