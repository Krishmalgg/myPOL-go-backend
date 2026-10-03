package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDotEnvFillsOnlyUnsetVariables(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	content := "# comment\n\nDOTENV_TEST_PLAIN=plain\nexport DOTENV_TEST_EXPORTED=exported\n" +
		"DOTENV_TEST_QUOTED=\"a,b\"\nDOTENV_TEST_PRESET=from-file\nnot a pair\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOTENV_TEST_PRESET", "from-env")
	for _, key := range []string{"DOTENV_TEST_PLAIN", "DOTENV_TEST_EXPORTED", "DOTENV_TEST_QUOTED"} {
		t.Setenv(key, "")
		os.Unsetenv(key)
	}

	if err := loadDotEnv(path); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"DOTENV_TEST_PLAIN":    "plain",
		"DOTENV_TEST_EXPORTED": "exported",
		"DOTENV_TEST_QUOTED":   "a,b",
		"DOTENV_TEST_PRESET":   "from-env",
	}
	for key, value := range want {
		if got := os.Getenv(key); got != value {
			t.Errorf("%s = %q, want %q", key, got, value)
		}
	}
}

func TestLoadDotEnvIgnoresMissingFile(t *testing.T) {
	if err := loadDotEnv(filepath.Join(t.TempDir(), "absent.env")); err != nil {
		t.Fatalf("missing file should be ignored, got %v", err)
	}
}
