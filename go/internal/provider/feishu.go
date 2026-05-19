package provider

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

type feishuErrorBody struct {
	Code  int64  `json:"code"`
	Msg   string `json:"msg"`
	Error struct {
		LogID                string `json:"log_id"`
		Troubleshooter       string `json:"troubleshooter"`
		Message              string `json:"message"`
		PermissionViolations []struct {
			Subject string `json:"subject"`
			Type    string `json:"type"`
		} `json:"permission_violations"`
	} `json:"error"`
}

type Feishu struct {
	cfg    config.BackendConfig
	slug   string
	client http.Client
}

type MissingFeishuFieldError struct {
	Resource       string
	ResourceID     string
	Field          string
	RequiredScopes []string
	Advice         string
}

func (e MissingFeishuFieldError) Error() string {
	return fmt.Sprintf("飞书接口未返回%s字段：%s=%s。需要在飞书开放平台开通并发布权限：%s；同时确认应用通讯录权限范围包含该%s。%s", e.Field, e.Resource, e.ResourceID, strings.Join(e.RequiredScopes, "、"), e.Resource, e.Advice)
}

func NewFeishu(cfg config.BackendConfig) Feishu {
	return NewFeishuWithSlug(cfg, "feishu")
}

func NewFeishuWithSlug(cfg config.BackendConfig, slug string) Feishu {
	return Feishu{cfg: cfg, slug: slug, client: http.Client{Timeout: 15 * time.Second}}
}

func (f Feishu) Slug() string {
	return f.slug
}

func (f Feishu) BuildAuthorizeURL(state, redirectURI string) string {
	values := url.Values{}
	values.Set("client_id", f.cfg.FeishuClientID)
	values.Set("redirect_uri", redirectURI)
	values.Set("response_type", "code")
	values.Set("state", state)
	return f.cfg.FeishuAuthorizeURL + "?" + values.Encode()
}

func (f Feishu) ExchangeCode(code, redirectURI string) (map[string]any, error) {
	payload := map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     f.cfg.FeishuClientID,
		"client_secret": f.cfg.FeishuClientSecret,
		"code":          code,
		"redirect_uri":  redirectURI,
	}
	var out map[string]any
	if err := f.postJSON(f.cfg.FeishuTokenURL, payload, "", &out); err != nil {
		return nil, err
	}
	if errText, _ := out["error"].(string); errText != "" {
		return nil, errors.New(errText)
	}
	return out, nil
}

func (f Feishu) FetchProfile(token map[string]any) (map[string]any, error) {
	accessToken, _ := token["access_token"].(string)
	if accessToken == "" {
		if data, ok := token["data"].(map[string]any); ok {
			accessToken, _ = data["access_token"].(string)
		}
	}
	if accessToken == "" {
		return nil, errors.New("feishu access token missing")
	}
	request, err := http.NewRequest(http.MethodGet, f.cfg.FeishuUserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := f.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		return nil, err
	}
	if data, ok := out["data"].(map[string]any); ok {
		return data, nil
	}
	return out, nil
}

func (f Feishu) ListUsers() ([]User, error) {
	token, err := f.tenantToken()
	if err != nil {
		return nil, err
	}
	departments, err := f.ListGroups()
	if err != nil {
		return nil, err
	}
	usersBySubject := map[string]User{}
	for _, department := range departments {
		items, err := f.departmentUsers(token, department.Subject)
		if err != nil {
			return nil, err
		}
		for _, raw := range items {
			subject := firstString(raw, "user_id", "open_id", "union_id")
			if subject == "" {
				continue
			}
			displayName := userDisplayName(raw)
			if displayName == "" {
				return nil, MissingFeishuFieldError{
					Resource:       "用户",
					ResourceID:     subject,
					Field:          "用户姓名 name/en_name",
					RequiredScopes: []string{"contact:user.base:readonly"},
					Advice:         "如果接口本身无权限，还需要开通 contact:contact.base:readonly 或以应用身份读取通讯录权限，并发布版本/管理员审批。",
				}
			}
			departmentSubjects := uniqueStrings(firstStringSlice(raw, "department_ids", "departments"))
			if len(departmentSubjects) == 0 {
				departmentSubjects = []string{department.Subject}
			}
			existing := usersBySubject[subject]
			user := User{
				ProviderSlug: f.slug,
				Subject:      subject,
				DisplayName:  displayName,
				Email:        firstString(raw, "email"),
				Mobile:       firstString(raw, "mobile"),
				Active:       true,
			}
			if existing.Subject != "" {
				user.DepartmentSubjects = uniqueStrings(append(existing.DepartmentSubjects, departmentSubjects...))
			} else {
				user.DepartmentSubjects = departmentSubjects
			}
			usersBySubject[subject] = user
		}
	}
	users := make([]User, 0, len(usersBySubject))
	for _, user := range usersBySubject {
		users = append(users, user)
	}
	return users, nil
}

func (f Feishu) ListGroups() ([]Group, error) {
	token, err := f.tenantToken()
	if err != nil {
		return nil, err
	}
	roots, err := f.departmentChildren(token, "0")
	if err != nil {
		return nil, err
	}
	var result []Group
	queue := make([]departmentQueueItem, 0, len(roots))
	for _, department := range roots {
		queue = append(queue, departmentQueueItem{raw: department})
	}
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		department := item.raw
		subject := firstString(department, "open_department_id", "department_id")
		name := departmentName(department, "")
		parent := firstString(department, "open_parent_department_id", "parent_department_id")
		if subject != "" {
			if name == "" {
				info, err := f.departmentInfo(token, subject)
				if err != nil {
					return nil, err
				}
				name = departmentName(info, "")
				if parent == "" {
					parent = firstString(info, "open_parent_department_id", "parent_department_id")
				}
			}
			if parent == "" {
				parent = item.parentSubject
			}
			if parent == "0" {
				parent = ""
			}
			if name == "" {
				return nil, MissingFeishuFieldError{
					Resource:       "部门",
					ResourceID:     subject,
					Field:          "部门名称 name/i18n_name",
					RequiredScopes: []string{"contact:department.base:readonly"},
					Advice:         "同步部门树还需要 contact:department.organize:readonly；如果接口本身无权限，还需要 contact:contact.base:readonly 或以应用身份读取通讯录权限，并发布版本/管理员审批。",
				}
			}
			path := departmentPath(item.parentPath, name)
			result = append(result, Group{
				ProviderSlug:  f.slug,
				Subject:       subject,
				ParentSubject: parent,
				Name:          name,
				Path:          path,
			})
			children, err := f.departmentChildren(token, subject)
			if err != nil {
				return nil, err
			}
			for _, child := range children {
				queue = append(queue, departmentQueueItem{raw: child, parentSubject: subject, parentPath: path})
			}
		}
	}
	return result, nil
}

type departmentQueueItem struct {
	raw           map[string]any
	parentSubject string
	parentPath    string
}

func (f Feishu) ListGroupMembers(groupSubject string) ([]string, error) {
	token, err := f.tenantToken()
	if err != nil {
		return nil, err
	}
	items, err := f.departmentUsers(token, groupSubject)
	if err != nil {
		return nil, err
	}
	var members []string
	for _, raw := range items {
		subject := firstString(raw, "user_id", "open_id", "union_id")
		if subject != "" {
			members = append(members, subject)
		}
	}
	return members, nil
}

func (f Feishu) departmentUsers(token, departmentID string) ([]map[string]any, error) {
	var result []map[string]any
	pageToken := ""
	for {
		endpoint := fmt.Sprintf("%s/users/find_by_department?department_id=%s&page_size=%d&department_id_type=open_department_id&user_id_type=open_id", strings.TrimRight(f.cfg.FeishuContactBaseURL, "/"), url.QueryEscape(departmentID), f.cfg.FeishuDirectoryPageSize)
		if pageToken != "" {
			endpoint += "&page_token=" + url.QueryEscape(pageToken)
		}
		var out map[string]any
		if err := f.getJSON(endpoint, token, &out); err != nil {
			return nil, err
		}
		data, _ := out["data"].(map[string]any)
		items, _ := data["items"].([]any)
		for _, item := range items {
			if raw, ok := item.(map[string]any); ok {
				result = append(result, raw)
			}
		}
		hasMore, _ := data["has_more"].(bool)
		pageToken, _ = data["page_token"].(string)
		if !hasMore || pageToken == "" {
			break
		}
	}
	return result, nil
}

func (f Feishu) departmentChildren(token, departmentID string) ([]map[string]any, error) {
	endpoint := fmt.Sprintf("%s/departments/%s/children?page_size=%d&department_id_type=open_department_id", strings.TrimRight(f.cfg.FeishuContactBaseURL, "/"), url.PathEscape(departmentID), f.cfg.FeishuDirectoryPageSize)
	var out map[string]any
	if err := f.getJSON(endpoint, token, &out); err != nil {
		return nil, err
	}
	data, _ := out["data"].(map[string]any)
	items, _ := data["items"].([]any)
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if raw, ok := item.(map[string]any); ok {
			result = append(result, raw)
		}
	}
	return result, nil
}

func (f Feishu) departmentInfo(token, departmentID string) (map[string]any, error) {
	endpoint := fmt.Sprintf("%s/departments/%s?department_id_type=open_department_id", strings.TrimRight(f.cfg.FeishuContactBaseURL, "/"), url.PathEscape(departmentID))
	var out map[string]any
	if err := f.getJSON(endpoint, token, &out); err != nil {
		return nil, err
	}
	data, _ := out["data"].(map[string]any)
	if item, ok := data["department"].(map[string]any); ok {
		return item, nil
	}
	if item, ok := data["item"].(map[string]any); ok {
		return item, nil
	}
	if len(data) > 0 {
		return data, nil
	}
	return out, nil
}

func (f Feishu) tenantToken() (string, error) {
	payload := map[string]string{
		"app_id":     f.cfg.FeishuClientID,
		"app_secret": f.cfg.FeishuClientSecret,
	}
	var out map[string]any
	if err := f.postJSON(f.cfg.FeishuTenantTokenURL, payload, "", &out); err != nil {
		return "", err
	}
	if token, _ := out["tenant_access_token"].(string); token != "" {
		return token, nil
	}
	if data, ok := out["data"].(map[string]any); ok {
		if token, _ := data["tenant_access_token"].(string); token != "" {
			return token, nil
		}
	}
	return "", errors.New("feishu tenant token missing")
}

func (f Feishu) postJSON(endpoint string, payload any, bearer string, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := f.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return decodeResponse(response, out)
}

func (f Feishu) getJSON(endpoint, bearer string, out any) error {
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	response, err := f.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return decodeResponse(response, out)
}

func decodeResponse(response *http.Response, out any) error {
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode >= 400 {
		return formatFeishuHTTPError(response.StatusCode, body)
	}
	return json.Unmarshal(body, out)
}

func formatFeishuHTTPError(statusCode int, body []byte) error {
	var parsed feishuErrorBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("飞书接口请求失败：HTTP %d，响应内容：%s", statusCode, strings.TrimSpace(string(body)))
	}
	if parsed.Code == 99991672 {
		scopes := missingFeishuScopes(parsed)
		if len(scopes) == 0 {
			return fmt.Errorf("飞书接口权限不足：应用尚未开通通讯录读取权限。请在飞书开放平台为当前应用申请并发布权限。飞书错误码：%d，log_id：%s", parsed.Code, parsed.Error.LogID)
		}
		return fmt.Errorf("飞书接口权限不足：应用尚未开通通讯录读取权限。请在飞书开放平台为当前应用申请并发布以下任一权限：%s。飞书错误码：%d，log_id：%s，排查链接：%s", strings.Join(scopes, "、"), parsed.Code, parsed.Error.LogID, firstNonEmpty(parsed.Error.Troubleshooter, parsed.Error.Message))
	}
	message := firstNonEmpty(parsed.Msg, parsed.Error.Message, strings.TrimSpace(string(body)))
	if parsed.Error.LogID != "" {
		return fmt.Errorf("飞书接口请求失败：HTTP %d，错误码：%d，%s，log_id：%s", statusCode, parsed.Code, message, parsed.Error.LogID)
	}
	if parsed.Code != 0 {
		return fmt.Errorf("飞书接口请求失败：HTTP %d，错误码：%d，%s", statusCode, parsed.Code, message)
	}
	return fmt.Errorf("飞书接口请求失败：HTTP %d，%s", statusCode, message)
}

func missingFeishuScopes(parsed feishuErrorBody) []string {
	seen := map[string]struct{}{}
	var scopes []string
	for _, violation := range parsed.Error.PermissionViolations {
		if violation.Subject == "" {
			continue
		}
		if _, ok := seen[violation.Subject]; ok {
			continue
		}
		seen[violation.Subject] = struct{}{}
		scopes = append(scopes, violation.Subject)
	}
	return scopes
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func firstString(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := raw[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

func firstStringSlice(raw map[string]any, keys ...string) []string {
	for _, key := range keys {
		value, ok := raw[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case []string:
			return typed
		case []any:
			result := make([]string, 0, len(typed))
			for _, item := range typed {
				if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
					result = append(result, strings.TrimSpace(text))
				}
			}
			return result
		}
	}
	return nil
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	var result []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func departmentName(raw map[string]any, fallback string) string {
	if value := firstString(raw, "name"); value != "" {
		return value
	}
	if value, ok := raw["i18n_name"]; ok {
		if text := localizedString(value); text != "" {
			return text
		}
	}
	if fallback != "" {
		return "dep_" + shortHash(fallback, 10)
	}
	return ""
}

func departmentPath(parentPath, name string) string {
	parentPath = strings.Trim(strings.TrimSpace(parentPath), "/")
	name = strings.Trim(strings.TrimSpace(name), "/")
	if parentPath == "" {
		return name
	}
	if name == "" {
		return parentPath
	}
	return parentPath + "/" + name
}

func userDisplayName(raw map[string]any) string {
	if value := firstString(raw, "name", "en_name", "nickname"); value != "" {
		return value
	}
	for _, key := range []string{"i18n_name", "localized_name"} {
		if value, ok := raw[key]; ok {
			if text := localizedString(value); text != "" {
				return text
			}
		}
	}
	return ""
}

func localizedString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case map[string]any:
		for _, key := range []string{"zh_cn", "zh-CN", "zh", "en_us", "en-US", "en"} {
			if text, ok := typed[key].(string); ok && strings.TrimSpace(text) != "" {
				return strings.TrimSpace(text)
			}
		}
		for _, raw := range typed {
			if text, ok := raw.(string); ok && strings.TrimSpace(text) != "" {
				return strings.TrimSpace(text)
			}
		}
	}
	return ""
}

func shortHash(value string, length int) string {
	sum := sha256.Sum256([]byte(value))
	encoded := hex.EncodeToString(sum[:])
	if length <= 0 || length > len(encoded) {
		return encoded
	}
	return encoded[:length]
}
