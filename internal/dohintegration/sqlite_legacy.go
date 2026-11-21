//go:build legacy_integration

package dohintegration

// The SQLite driver is needed only by opt-in legacy panel integration tools.
// Keep its init side effects out of the production sidecar binary.
import _ "modernc.org/sqlite"
