package dohintegration

import (
	"strings"
	"testing"
)

func TestRunCommandRejectsPanelMutationDirectives(t *testing.T) {
	for _, action := range []string{"integrate", "remove"} {
		err := RunCommand([]string{action}, nil)
		if err == nil {
			t.Fatalf("%s unexpectedly accepted; panel mutation must remain disabled", action)
		}
		if !strings.Contains(err.Error(), "disabled for the approved Geosite DNS design") {
			t.Fatalf("%s returned an unexpected error: %v", action, err)
		}
	}
}
