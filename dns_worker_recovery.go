package main

import "runtime/debug"

// invokeDNSHandlerSafely contains panics at the DNS worker boundary. A broken
// request must not permanently consume one of the bounded UDP/TCP workers.
func invokeDNSHandlerSafely(protocol string, handler func([]byte) []byte, packet []byte) (response []byte) {
	defer func() {
		if recovered := recover(); recovered != nil {
			logLine("ERROR", "DNS %s worker recovered panic: %v\n%s", protocol, recovered, debug.Stack())
			response = nil
		}
	}()
	return handler(packet)
}
