//go:build legacy_integration

package dohintegration

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSQLiteEndpointSettingsReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x-ui.db")
	db, err := sql.Open("sqlite", path)
	if err != nil { t.Fatal(err) }
	if _, err := db.Exec("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)"); err != nil { t.Fatal(err) }
	if _, err := db.Exec("INSERT INTO settings(key,value) VALUES (?,?), (?,?)", "webPort", "33976", "webBasePath", "/panel"); err != nil { t.Fatal(err) }
	if err := db.Close(); err != nil { t.Fatal(err) }
	settings, err := readPanelSettings(path)
	if err != nil { t.Fatal(err) }
	if settings["webPort"] != "33976" || settings["webBasePath"] != "/panel" {
		t.Fatalf("unexpected endpoint settings: %#v", settings)
	}
}
