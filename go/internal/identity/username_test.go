package identity

import (
	"strings"
	"testing"
)

func TestGenerateSequentialReadableUsername(t *testing.T) {
	if got := GenerateSequentialReadableUsername("张三", "_", 1, "user", DSMUsernameMaxLength); got != "张三" {
		t.Fatalf("first username got %q", got)
	}
	if got := GenerateSequentialReadableUsername("张三", "_", 2, "user", DSMUsernameMaxLength); got != "张三_2" {
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
	if _, err := GenerateRequiredSequentialReadableUsername("###", "_", 1, DSMUsernameMaxLength); err == nil {
		t.Fatal("expected unusable username to fail")
	}
	if _, err := SanitizeGroupName("!!!"); err == nil {
		t.Fatal("expected unusable group name to fail")
	}
}

func TestSanitizeNamesKeepsDSMAllowedUnicode(t *testing.T) {
	usernameInput := ".研发 一组_-."
	username, err := SanitizeRequiredNameBase(usernameInput, DSMUsernameMaxLength)
	if err != nil {
		t.Fatal(err)
	}
	if username != usernameInput {
		t.Fatalf("username got %q want %q", username, usernameInput)
	}

	groupInput := "研发 一组_-."
	groupname, err := SanitizeGroupName(groupInput)
	if err != nil {
		t.Fatal(err)
	}
	if groupname != groupInput {
		t.Fatalf("group name got %q want %q", groupname, groupInput)
	}
}

func TestSanitizeNamesRemovesDSMForbiddenCharacters(t *testing.T) {
	username, err := SanitizeRequiredNameBase("a!\"#$%&'()*+,/:;<=>?@[\\]^`{|}~b", DSMUsernameMaxLength)
	if err != nil {
		t.Fatal(err)
	}
	if username != "ab" {
		t.Fatalf("username got %q", username)
	}

	groupname, err := SanitizeGroupName("a!\"#$%&'()*+,/:;<=>?@[\\]^`{|}~b")
	if err != nil {
		t.Fatal(err)
	}
	if groupname != "a___b" {
		t.Fatalf("group name got %q", groupname)
	}
}

func TestDSMNameLengthLimits(t *testing.T) {
	username, err := GenerateRequiredSequentialReadableUsername(strings.Repeat("名", DSMUsernameMaxLength+1), "_", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len([]rune(username)) != DSMUsernameMaxLength {
		t.Fatalf("username length got %d", len([]rune(username)))
	}

	groupname, err := SanitizeGroupName(strings.Repeat("组", DSMGroupnameMaxLength+1))
	if err != nil {
		t.Fatal(err)
	}
	if len([]rune(groupname)) != DSMGroupnameMaxLength {
		t.Fatalf("group name length got %d", len([]rune(groupname)))
	}
}

func TestSanitizeNamesRemovesInvalidBoundaryAndControlCharacters(t *testing.T) {
	username, err := SanitizeRequiredNameBase(" - -alice\nbob ", DSMUsernameMaxLength)
	if err != nil {
		t.Fatal(err)
	}
	if username != "alicebob" {
		t.Fatalf("username got %q", username)
	}
}

func TestSanitizeGroupNameKeepsDepartmentPathReadable(t *testing.T) {
	got, err := SanitizeGroupName("matrix/sup1/sup2/sup5")
	if err != nil {
		t.Fatal(err)
	}
	if got != "matrix_sup1_sup2_sup5" {
		t.Fatalf("SanitizeGroupName got %q", got)
	}
}
