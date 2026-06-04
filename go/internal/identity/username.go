package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

var dsmForbidden = map[rune]bool{}

func init() {
	for _, r := range "{}|^[]?=:+/*()$!\"#%&',;<>@`~\\" {
		dsmForbidden[r] = true
	}
}

func Normalize(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func GenerateHashUsername(identityID, pepper string) string {
	mac := hmac.New(sha256.New, []byte(pepper))
	_, _ = mac.Write([]byte(identityID))
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(mac.Sum(nil))
	return "u_" + strings.ToLower(encoded[:16])
}

func GenerateReadableUsername(displayName, delimiter string, suffixDigits int, fallback string, maxBaseLength int) string {
	return GenerateSequentialReadableUsername(displayName, delimiter, 1, fallback, maxBaseLength)
}

func GenerateSequentialReadableUsername(displayName, delimiter string, sequence int, fallback string, maxLength int) string {
	username, err := GenerateRequiredSequentialReadableUsername(displayName, delimiter, sequence, maxLength)
	if err == nil {
		return username
	}
	base := SanitizeNameBase(fallback, "user", maxLength)
	if sequence <= 1 {
		return base
	}
	delimiter = usernameDelimiter(delimiter)
	return base + delimiter + strconv.Itoa(sequence)
}

func GenerateRequiredSequentialReadableUsername(displayName, delimiter string, sequence int, maxLength int) (string, error) {
	if maxLength <= 0 {
		maxLength = 32
	}
	base, err := SanitizeRequiredNameBase(displayName, maxLength)
	if err != nil {
		return "", err
	}
	if sequence <= 1 {
		return base, nil
	}
	delimiter = usernameDelimiter(delimiter)
	suffix := delimiter + strconv.Itoa(sequence)
	baseLimit := maxLength - len([]rune(suffix))
	if baseLimit < 1 {
		baseLimit = 1
	}
	runes := []rune(base)
	if len(runes) > baseLimit {
		base = string(runes[:baseLimit])
		base = strings.Trim(base, "._-")
		if base == "" {
			return "", fmt.Errorf("DSM 用户名不可用：原始姓名 %q 清洗后为空", displayName)
		}
	}
	return base + suffix, nil
}

func SanitizeNameBase(value, fallback string, maxLength int) string {
	if fallback == "" {
		fallback = "user"
	}
	if maxLength <= 0 {
		maxLength = 32
	}
	var builder strings.Builder
	for _, r := range strings.TrimSpace(value) {
		if unicode.IsSpace(r) || unicode.IsControl(r) || dsmForbidden[r] {
			continue
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.' {
			builder.WriteRune(r)
		}
	}
	base := strings.Trim(builder.String(), "._-")
	if base == "" {
		base = fallback
	}
	runes := []rune(base)
	if len(runes) > maxLength {
		base = string(runes[:maxLength])
	}
	return base
}

func SanitizeRequiredNameBase(value string, maxLength int) (string, error) {
	if maxLength <= 0 {
		maxLength = 32
	}
	var builder strings.Builder
	for _, r := range strings.TrimSpace(value) {
		if unicode.IsSpace(r) || unicode.IsControl(r) || dsmForbidden[r] {
			continue
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.' {
			builder.WriteRune(r)
		}
	}
	base := strings.Trim(builder.String(), "._-")
	if base == "" {
		return "", fmt.Errorf("DSM 名称不可用：原始名称 %q 清洗后为空", value)
	}
	runes := []rune(base)
	if len(runes) > maxLength {
		base = string(runes[:maxLength])
	}
	return base, nil
}

func SanitizeGroupName(value string) (string, error) {
	value = strings.NewReplacer("/", "_", "\\", "_", ">", "_").Replace(value)
	groupName, err := SanitizeRequiredNameBase(value, 32)
	if err != nil {
		return "", fmt.Errorf("DSM 群组名不可用：飞书部门名称 %q 清洗后为空，请修改部门名称或开启正确字段权限后重试", value)
	}
	return groupName, nil
}

func usernameDelimiter(delimiter string) string {
	if delimiter == "" {
		return "_"
	}
	var builder strings.Builder
	for _, r := range delimiter {
		if r == '_' || r == '-' || r == '.' {
			builder.WriteRune(r)
		}
	}
	clean := builder.String()
	if clean == "" {
		return "_"
	}
	return clean
}
