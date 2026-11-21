package plugincheck

import (
	"strings"
	"testing"
)

func TestRunCommandRejectsRemovedPanelMutationDirectives(t *testing.T) {
	for _, action := range []string{"integrate", "remove"} {
		err := RunCommand([]string{action}, nil)
		if err == nil {
			t.Fatalf("%s unexpectedly accepted; panel mutation is not supported", action)
		}
		if !strings.Contains(err.Error(), "Panel integration commands are not part of this plugin") {
			t.Fatalf("%s returned an unexpected error: %v", action, err)
		}
	}
}
