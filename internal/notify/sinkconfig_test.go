package notify_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/outbox"
)

func writeSinksFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sinks.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write sinks file: %v", err)
	}
	return path
}

func testSinkDeps(env map[string]string) notify.SinkDeps {
	return notify.SinkDeps{
		Telegram:      &fakeTG{},
		MainChatID:    fakeMainChatID,
		AnalystChatID: fakeAnalystChatID,
		Getenv:        func(k string) string { return env[k] },
	}
}

const fullSinksFile = `{
  "sinks": {
    "telegram": {"type": "telegram"},
    "gotify":   {"type": "gotify",
                 "url": "https://gotify.invalid",
                 "token_env": "TEST_GOTIFY_TOKEN",
                 "titles":   {"main": "Heimdall", "analyst": "Heimdall hypothesis"},
                 "priority": {"main": 8, "analyst": 2}},
    "synochat": {"type": "synology", "webhook_url_env": "TEST_SYNO_WEBHOOK"}
  },
  "routes": {
    "main":    ["telegram", "gotify"],
    "analyst": ["telegram", "synochat"]
  }
}`

func TestLoadAndBuildFullRouting(t *testing.T) {
	path := writeSinksFile(t, fullSinksFile)
	f, err := notify.LoadSinksFile(path)
	if err != nil {
		t.Fatalf("LoadSinksFile: %v", err)
	}
	routes, err := f.Build(testSinkDeps(map[string]string{
		"TEST_GOTIFY_TOKEN": "tok",
		"TEST_SYNO_WEBHOOK": "https://nas.invalid/webhook?token=%22abc%22",
	}))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	var mainIDs []string
	for _, s := range routes.SinksFor(outbox.ChannelMain) {
		mainIDs = append(mainIDs, s.ID())
	}
	// Route order is preserved as written — it is the delivery order.
	if diff := cmp.Diff([]string{"telegram", "gotify"}, mainIDs); diff != "" {
		t.Errorf("main route mismatch (-want +got):\n%s", diff)
	}

	var analystIDs []string
	for _, s := range routes.SinksFor(outbox.ChannelAnalyst) {
		analystIDs = append(analystIDs, s.ID())
	}
	if diff := cmp.Diff([]string{"telegram", "synochat"}, analystIDs); diff != "" {
		t.Errorf("analyst route mismatch (-want +got):\n%s", diff)
	}
}

// A typo'd key must be a boot error, never a setting that silently does
// nothing.
func TestLoadRejectsUnknownFields(t *testing.T) {
	path := writeSinksFile(t, `{"sinks":{"telegram":{"type":"telegram","chat":123}},"routes":{"main":["telegram"],"analyst":["telegram"]}}`)
	if _, err := notify.LoadSinksFile(path); err == nil {
		t.Fatal("LoadSinksFile: want error for an unknown field, got nil")
	}
}

func TestLoadReportsMissingFile(t *testing.T) {
	if _, err := notify.LoadSinksFile(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("LoadSinksFile: want error for a missing file, got nil")
	}
}

// Every one of these corresponds to a way messages would otherwise be
// discarded in silence, which is why each is fatal at boot.
func TestBuildRejectsConfigurationsThatWouldSilentlyDropMessages(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		env     map[string]string
		wantErr string
	}{
		{
			name:    "channel with no route",
			file:    `{"sinks":{"telegram":{"type":"telegram"}},"routes":{"main":["telegram"]}}`,
			wantErr: "has no route",
		},
		{
			name:    "route names an undeclared sink",
			file:    `{"sinks":{"telegram":{"type":"telegram"}},"routes":{"main":["telegram","ghost"],"analyst":["telegram"]}}`,
			wantErr: "undeclared sink",
		},
		{
			name:    "declared but never routed",
			file:    `{"sinks":{"telegram":{"type":"telegram"},"synochat":{"type":"synology","webhook_url_env":"W"}},"routes":{"main":["telegram"],"analyst":["telegram"]}}`,
			env:     map[string]string{"W": "https://nas.invalid/hook"},
			wantErr: "never routed",
		},
		{
			name:    "empty route list",
			file:    `{"sinks":{"telegram":{"type":"telegram"}},"routes":{"main":[],"analyst":["telegram"]}}`,
			wantErr: "names no sinks",
		},
		{
			name:    "duplicate sink in one route",
			file:    `{"sinks":{"telegram":{"type":"telegram"}},"routes":{"main":["telegram","telegram"],"analyst":["telegram"]}}`,
			wantErr: "twice",
		},
		{
			name:    "unknown channel",
			file:    `{"sinks":{"telegram":{"type":"telegram"}},"routes":{"main":["telegram"],"analyst":["telegram"],"urgent":["telegram"]}}`,
			wantErr: "unknown channel",
		},
		{
			name:    "unknown sink type",
			file:    `{"sinks":{"pager":{"type":"pagerduty"}},"routes":{"main":["pager"],"analyst":["pager"]}}`,
			wantErr: "unknown type",
		},
		{
			name:    "missing type",
			file:    `{"sinks":{"pager":{"url":"https://x.invalid"}},"routes":{"main":["pager"],"analyst":["pager"]}}`,
			wantErr: "missing \"type\"",
		},
		{
			name:    "gotify without url",
			file:    `{"sinks":{"gotify":{"type":"gotify","token_env":"T"}},"routes":{"main":["gotify"],"analyst":["gotify"]}}`,
			env:     map[string]string{"T": "tok"},
			wantErr: "requires a non-empty \"url\"",
		},
		{
			name:    "gotify without token_env",
			file:    `{"sinks":{"gotify":{"type":"gotify","url":"https://g.invalid"}},"routes":{"main":["gotify"],"analyst":["gotify"]}}`,
			wantErr: "requires \"token_env\"",
		},
		{
			name:    "gotify credential env unset",
			file:    `{"sinks":{"gotify":{"type":"gotify","url":"https://g.invalid","token_env":"MISSING"}},"routes":{"main":["gotify"],"analyst":["gotify"]}}`,
			wantErr: "unset or empty",
		},
		{
			name:    "synology without webhook_url_env",
			file:    `{"sinks":{"synochat":{"type":"synology"}},"routes":{"main":["synochat"],"analyst":["synochat"]}}`,
			wantErr: "requires \"webhook_url_env\"",
		},
		{
			name:    "field meaningless for the type",
			file:    `{"sinks":{"telegram":{"type":"telegram","priority":{"main":8}}},"routes":{"main":["telegram"],"analyst":["telegram"]}}`,
			wantErr: "take no",
		},
		{
			name:    "priority names an unknown channel",
			file:    `{"sinks":{"gotify":{"type":"gotify","url":"https://g.invalid","token_env":"T","priority":{"urgent":9}}},"routes":{"main":["gotify"],"analyst":["gotify"]}}`,
			env:     map[string]string{"T": "tok"},
			wantErr: "unknown channel",
		},
		{
			name:    "bad sink id",
			file:    `{"sinks":{"Telegram Main":{"type":"telegram"}},"routes":{"main":["Telegram Main"],"analyst":["Telegram Main"]}}`,
			wantErr: "id must match",
		},
		{
			name:    "no sinks at all",
			file:    `{"sinks":{},"routes":{"main":["telegram"],"analyst":["telegram"]}}`,
			wantErr: "declares no sinks",
		},
		{
			name:    "no routes at all",
			file:    `{"sinks":{"telegram":{"type":"telegram"}},"routes":{}}`,
			wantErr: "declares no routes",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeSinksFile(t, tc.file)
			f, err := notify.LoadSinksFile(path)
			if err != nil {
				t.Fatalf("LoadSinksFile: %v", err)
			}
			_, err = f.Build(testSinkDeps(tc.env))
			if err == nil {
				t.Fatalf("Build: want error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Build error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// The routing file is IaC-rendered and committable: it must name the env
// var carrying a credential, never the credential itself.
func TestSecretsAreReferencedByEnvVarNameNotValue(t *testing.T) {
	path := writeSinksFile(t, fullSinksFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	f, err := notify.LoadSinksFile(path)
	if err != nil {
		t.Fatalf("LoadSinksFile: %v", err)
	}
	const secret = "s3cr3t-value-never-in-the-file"
	if _, err := f.Build(testSinkDeps(map[string]string{
		"TEST_GOTIFY_TOKEN": secret,
		"TEST_SYNO_WEBHOOK": "https://nas.invalid/hook?token=" + secret,
	})); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if strings.Contains(string(raw), secret) {
		t.Error("the sinks file must never contain a credential value")
	}
}

func TestDefaultTelegramRoutesCoversEveryChannel(t *testing.T) {
	routes := notify.DefaultTelegramRoutes(&fakeTG{}, fakeMainChatID, fakeAnalystChatID)
	for _, c := range outbox.Channels() {
		if len(routes.SinksFor(c)) != 1 {
			t.Errorf("channel %q: want exactly one default sink, got %d", c, len(routes.SinksFor(c)))
		}
	}
	if len(routes.All()) != 1 {
		t.Errorf("want a single shared Telegram sink, got %d", len(routes.All()))
	}
}

// The shipped example must actually load and build. An example that fails
// validation is worse than none: it is copied verbatim and then debugged as
// if the operator's environment were at fault.
func TestShippedExampleSinksFileIsValid(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "sinks.example.json")
	f, err := notify.LoadSinksFile(path)
	if err != nil {
		t.Fatalf("LoadSinksFile(%s): %v", path, err)
	}
	routes, err := f.Build(testSinkDeps(map[string]string{
		"HEIMDALL_GOTIFY_TOKEN":         "example-token",
		"HEIMDALL_SYNOLOGY_WEBHOOK_URL": "https://nas.invalid/hook?token=%22x%22",
	}))
	if err != nil {
		t.Fatalf("Build(%s): %v", path, err)
	}
	for _, c := range outbox.Channels() {
		if len(routes.SinksFor(c)) == 0 {
			t.Errorf("example leaves channel %q unrouted", c)
		}
	}
}
