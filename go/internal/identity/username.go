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

const (
	DSMUsernameMaxLength  = 64
	DSMGroupnameMaxLength = 32
)

// DSM 7 rejects these symbols for both users and groups. Keep separate maps so
// the two validation paths remain explicit if DSM changes either rule later.
var dsmUsernameForbidden = forbiddenRunes("!\"#$%&'()*+,/:;<=>?@[\\]^`{|}~")
var dsmGroupnameForbidden = forbiddenRunes("!\"#$%&'()*+,/:;<=>?@[\\]^`{|}~")

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
		maxLength = DSMUsernameMaxLength
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
		base = strings.TrimRightFunc(base, unicode.IsSpace)
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
		maxLength = DSMUsernameMaxLength
	}
	base := sanitizeDSMName(value, maxLength, dsmUsernameForbidden)
	if base == "" {
		base = sanitizeDSMName(fallback, maxLength, dsmUsernameForbidden)
		if base == "" {
			base = "user"
		}
	}
	return base
}

func SanitizeRequiredNameBase(value string, maxLength int) (string, error) {
	if maxLength <= 0 {
		maxLength = DSMUsernameMaxLength
	}
	base := sanitizeDSMName(value, maxLength, dsmUsernameForbidden)
	if base == "" {
		return "", fmt.Errorf("DSM 名称不可用：原始名称 %q 清洗后为空", value)
	}
	return base, nil
}

func SanitizeGroupName(value string) (string, error) {
	original := value
	value = strings.NewReplacer("/", "_", "\\", "_", ">", "_").Replace(value)
	groupName := sanitizeDSMName(value, DSMGroupnameMaxLength, dsmGroupnameForbidden)
	if groupName == "" {
		return "", fmt.Errorf("DSM 群组名不可用：部门名称 %q 清洗后为空，请修改部门名称或开启正确字段权限后重试", original)
	}
	return groupName, nil
}

func sanitizeDSMName(value string, maxLength int, forbidden map[rune]bool) string {
	var builder strings.Builder
	for _, r := range strings.TrimSpace(value) {
		if unicode.IsControl(r) || !unicode.IsGraphic(r) || forbidden[r] {
			continue
		}
		builder.WriteRune(r)
	}
	name := strings.TrimLeftFunc(builder.String(), func(r rune) bool {
		return r == '-' || unicode.IsSpace(r)
	})
	name = strings.TrimRightFunc(name, unicode.IsSpace)
	runes := []rune(name)
	if len(runes) > maxLength {
		name = string(runes[:maxLength])
		name = strings.TrimRightFunc(name, unicode.IsSpace)
	}
	return name
}

func forbiddenRunes(value string) map[rune]bool {
	result := make(map[rune]bool, len([]rune(value)))
	for _, r := range value {
		result[r] = true
	}
	return result
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
