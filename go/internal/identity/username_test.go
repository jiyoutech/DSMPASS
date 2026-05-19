package identity

import "testing"

func TestGenerateSequentialReadableUsername(t *testing.T) {
	if got := GenerateSequentialReadableUsername("张三", "_", 1, "user", 32); got != "张三" {
		t.Fatalf("first username got %q", got)
	}
	if got := GenerateSequentialReadableUsername("张三", "_", 2, "user", 32); got != "张三_2" {
		t.Fatalf("duplicate username got %q", got)
	}
}

func TestGenerateSequentialReadableUsernameSanitizesDelimiterAndLength(t *testing.T) {
	got := GenerateSequentialReadableUsername("abcdefghijklmnopqrstuvwxyz1234567890", "#", 12, "user", 32)
	if got != "abcdefghijklmnopqrstuvwxyz123_12" {
		t.Fatalf("username got %q", got)
	}
	if len([]rune(got)) > 32 {
		t.Fatalf("username is too long: %q", got)
	}
}

func TestRequiredNamesDoNotFallback(t *testing.T) {
	if _, err := GenerateRequiredSequentialReadableUsername("###", "_", 1, 32); err == nil {
		t.Fatal("expected unusable username to fail")
	}
	if _, err := SanitizeGroupName("###"); err == nil {
		t.Fatal("expected unusable group name to fail")
	}
}
