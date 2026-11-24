package main

import (
	"encoding/binary"
)

// dnsFlight represents one in-progress upstream lookup. The response is
// published before done is closed, so waiters observe a fully initialized copy.
type dnsFlight struct {
	done     chan struct{}
	response []byte
}

// coalesceDNSResponse ensures that identical concurrent DNS cache misses share
// one upstream operation. The key must include the DNS mode and its generation.

func runDNSFlight(query []byte, run func() []byte) (response []byte) {
	defer func() {
		if recovered := recover(); recovered != nil {
			logLine("ERROR", "DNS singleflight operation panicked; returning SERVFAIL: %v", recovered)
			response = servfailResponse(query)
		}
	}()
	return run()
}

func (r *Runtime) coalesceDNSResponse(key string, query []byte, run func() []byte) []byte {
	if r == nil || len(query) < 2 || run == nil {
		if run == nil {
			return nil
		}
		return run()
	}

	candidate := &dnsFlight{done: make(chan struct{})}
	actual, loaded := r.dnsFlights.LoadOrStore(key, candidate)
	if loaded {
		r.dnsCoalesced.Add(1)
		flight := actual.(*dnsFlight)
		<-flight.done
		response := append([]byte(nil), flight.response...)
		if len(response) >= 2 {
			binary.BigEndian.PutUint16(response[:2], binary.BigEndian.Uint16(query[:2]))
		}
		return response
	}

	response := runDNSFlight(query, run)
	candidate.response = append([]byte(nil), response...)
	close(candidate.done)
	r.dnsFlights.Delete(key)
	return response
}
