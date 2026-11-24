package main

import (
	"errors"
	"testing"
)

func TestInvokeDNSHandlerSafelyRecoversPanic(t *testing.T) {
	called := false
	response := invokeDNSHandlerSafely("test", func([]byte) []byte {
		called = true
		panic(errors.New("simulated handler panic"))
	}, []byte{1, 2, 3})
	if !called {
		t.Fatal("handler was not called")
	}
	if len(response) != 0 {
		t.Fatalf("panic response = %v, want nil", response)
	}
}

func TestInvokeDNSHandlerSafelyReturnsResponse(t *testing.T) {
	want := []byte{1, 2, 3}
	got := invokeDNSHandlerSafely("test", func([]byte) []byte {
		return want
	}, nil)
	if string(got) != string(want) {
		t.Fatalf("response = %v, want %v", got, want)
	}
}
