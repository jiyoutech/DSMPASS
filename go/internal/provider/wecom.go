package provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	legacyWeComAuthorizeURL    = "https://open.weixin.qq.com/connect/oauth2/authorize"
	defaultWeComAuthorizeURL   = "https://open.work.weixin.qq.com/wwopen/sso/qrConnect"
	defaultWeComTokenURL       = "https://qyapi.weixin.qq.com/cgi-bin/gettoken"
	defaultWeComUserInfoURL    = "https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo"
	defaultWeComContactBaseURL = "https://qyapi.weixin.qq.com/cgi-bin"
)

type WeComConfig struct {
	CorpID            string
	CorpSecret        string
	AgentID           string
	AuthorizeURL      string
	TokenURL          string
	UserInfoURL       string
	ContactBaseURL    string
	DirectoryPageSize int
}

type weComErrorBody struct {
	ErrCode int64  `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

type weComResponseError struct {
	errCode int64
	detail  string
}

func (e *weComResponseError) Error() string {
	return e.detail
}

type WeCom struct {
	cfg    WeComConfig
	slug   string
	client http.Client
}

func NewWeCom(cfg WeComConfig) WeCom {
	return NewWeComWithSlug(cfg, "wecom")
}

func NewWeComWithSlug(cfg WeComConfig, slug string) WeCom {
	cfg = withWeComDefaults(cfg)
	return WeCom{cfg: cfg, slug: slug, client: http.Client{Timeout: 15 * time.Second}}
}

func withWeComDefaults(cfg WeComConfig) WeComConfig {
	if cfg.AuthorizeURL == "" || cfg.AuthorizeURL == legacyWeComAuthorizeURL {
		cfg.AuthorizeURL = defaultWeComAuthorizeURL
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = defaultWeComTokenURL
	}
	if cfg.UserInfoURL == "" {
		cfg.UserInfoURL = defaultWeComUserInfoURL
	}
	if cfg.ContactBaseURL == "" {
		cfg.ContactBaseURL = defaultWeComContactBaseURL
	}
	if cfg.DirectoryPageSize <= 0 {
		cfg.DirectoryPageSize = 50
	}
	return cfg
}

func (w WeCom) Slug() string {
	return w.slug
}

func (w WeCom) ProviderDisplayName() string {
	return "企业微信"
}

func (w WeCom) BuildAuthorizeURL(state, redirectURI string) string {
	values := url.Values{}
	values.Set("appid", w.cfg.CorpID)
	values.Set("redirect_uri", redirectURI)
	values.Set("state", state)
	if strings.TrimSpace(w.cfg.AgentID) != "" {
		values.Set("agentid", w.cfg.AgentID)
	}
	return withEncodedQuery(w.cfg.AuthorizeURL, values)
}

func (w WeCom) ExchangeCode(code, redirectURI string) (map[string]any, error) {
	accessToken, err := w.accessToken()
	if err != nil {
		return nil, err
	}
	endpoint := withQuery(w.cfg.UserInfoURL, map[string]string{
		"access_token": accessToken,
		"code":         code,
	})
	var out map[string]any
	if err := w.getJSON(endpoint, &out); err != nil {
		return nil, err
	}
	out["access_token"] = accessToken
	return out, nil
}

func (w WeCom) FetchProfile(token map[string]any) (map[string]any, error) {
	profile := map[string]any{}
	for key, value := range token {
		if key == "access_token" {
			continue
		}
		profile[key] = value
	}
	if userid := firstStringish(profile, "userid", "UserId", "user_id"); userid != "" {
		profile["userid"] = userid
		return profile, nil
	}
	if openid := firstStringish(profile, "openid", "OpenId"); openid != "" {
		profile["openid"] = openid
		return profile, nil
	}
	return nil, errors.New("企业微信授权结果未返回用户身份，请确认应用可见范围和 OAuth 配置")
}

func (w WeCom) ProfileSubject(profile map[string]any) (string, string) {
	return weComUserSubject(profile)
}

func (w WeCom) ListUsers() ([]User, error) {
	token, err := w.accessToken()
	if err != nil {
		return nil, err
	}
	groups, err := w.listGroups(token)
	if err != nil {
		return nil, weComDirectorySyncError("读取通讯录部门", err)
	}
	if len(groups) == 0 {
		users, err := w.visibleUsers(token)
		if err != nil {
			return nil, weComDirectorySyncError("读取通讯录用户", err)
		}
		return users, nil
	}
	users, err := w.usersFromGroups(token, groups)
	if err != nil {
		return nil, weComDirectorySyncError("读取通讯录部门成员", err)
	}
	return users, nil
}

func (w WeCom) ListUsersAndGroups() ([]User, []Group, error) {
	token, err := w.accessToken()
	if err != nil {
		return nil, nil, err
	}
	groups, err := w.listGroups(token)
	if err != nil {
		return nil, nil, weComDirectorySyncError("读取通讯录部门", err)
	}
	if len(groups) == 0 {
		users, err := w.visibleUsers(token)
		if err != nil {
			return nil, nil, weComDirectorySyncError("读取通讯录用户", err)
		}
		return users, groups, nil
	}
	users, err := w.usersFromGroups(token, groups)
	if err != nil {
		return nil, nil, weComDirectorySyncError("读取通讯录部门成员", err)
	}
	return users, groups, nil
}

func (w WeCom) usersFromGroups(token string, groups []Group) ([]User, error) {
	usersBySubject := map[string]User{}
	for _, group := range groups {
		items, err := w.departmentUsers(token, group.Subject)
		if err != nil {
			return nil, err
		}
		for _, raw := range items {
			w.upsertUserFromRaw(usersBySubject, raw, []string{group.Subject})
		}
	}
	return usersFromMap(usersBySubject), nil
}

func (w WeCom) visibleUsers(token string) ([]User, error) {
	if strings.TrimSpace(w.cfg.AgentID) != "" {
		userIDs, err := w.agentVisibleUserIDs(token)
		if err != nil {
			return nil, fmt.Errorf("企业微信读取自建应用可见范围失败：%w", err)
		}
		if len(userIDs) > 0 {
			return w.usersByIDs(token, userIDs, nil)
		}
	}
	items, err := w.visibleUserIDs(token)
	if err != nil {
		return nil, err
	}
	departmentsByUser := map[string][]string{}
	userIDs := make([]string, 0, len(items))
	for _, raw := range items {
		userID := firstStringish(raw, "userid", "UserId", "user_id")
		if userID == "" {
			continue
		}
		if _, ok := departmentsByUser[userID]; !ok {
			userIDs = append(userIDs, userID)
		}
		departments := uniqueStrings(firstStringishSlice(raw, "department", "department_id", "department_ids", "departments"))
		if len(departments) == 0 {
			if department := firstStringish(raw, "department", "department_id"); department != "" {
				departments = []string{department}
			}
		}
		departmentsByUser[userID] = uniqueStrings(append(departmentsByUser[userID], departments...))
	}
	return w.usersByIDs(token, userIDs, departmentsByUser)
}

func (w WeCom) usersByIDs(token string, userIDs []string, departmentsByUser map[string][]string) ([]User, error) {
	usersBySubject := map[string]User{}
	for _, userID := range uniqueStrings(userIDs) {
		raw, err := w.user(token, userID)
		if err != nil {
			return nil, err
		}
		if firstStringish(raw, "userid", "UserId", "user_id") == "" {
			raw["userid"] = userID
		}
		w.upsertUserFromRaw(usersBySubject, raw, departmentsByUser[userID])
	}
	return usersFromMap(usersBySubject), nil
}

func (w WeCom) upsertUserFromRaw(usersBySubject map[string]User, raw map[string]any, fallbackDepartments []string) {
	subject, subjectType := weComUserSubject(raw)
	if subject == "" {
		return
	}
	displayName := userDisplayName(raw)
	if displayName == "" {
		displayName = subject
	}
	departmentSubjects := uniqueStrings(firstStringishSlice(raw, "department", "department_ids", "departments"))
	if len(departmentSubjects) == 0 {
		departmentSubjects = uniqueStrings(fallbackDepartments)
	}
	existing := usersBySubject[subject]
	user := User{
		ProviderSlug: w.slug,
		Subject:      subject,
		SubjectType:  subjectType,
		DisplayName:  displayName,
		Email:        firstString(raw, "email", "biz_mail"),
		Mobile:       firstString(raw, "mobile"),
		Active:       weComUserActive(raw),
	}
	if existing.Subject != "" {
		user.DepartmentSubjects = uniqueStrings(append(existing.DepartmentSubjects, departmentSubjects...))
		user.Active = existing.Active || user.Active
	} else {
		user.DepartmentSubjects = departmentSubjects
	}
	usersBySubject[subject] = user
}

func usersFromMap(usersBySubject map[string]User) []User {
	users := make([]User, 0, len(usersBySubject))
	for _, user := range usersBySubject {
		users = append(users, user)
	}
	return users
}

func (w WeCom) ListGroups() ([]Group, error) {
	token, err := w.accessToken()
	if err != nil {
		return nil, err
	}
	return w.listGroups(token)
}

func (w WeCom) listGroups(token string) ([]Group, error) {
	items, err := w.departments(token)
	if err != nil {
		return nil, err
	}
	rawBySubject := map[string]map[string]any{}
	for _, raw := range items {
		subject := weComDepartmentID(raw)
		if subject != "" {
			rawBySubject[subject] = raw
		}
	}
	pathBySubject := map[string]string{}
	visiting := map[string]bool{}
	var buildPath func(string) string
	buildPath = func(subject string) string {
		if path, ok := pathBySubject[subject]; ok {
			return path
		}
		if visiting[subject] {
			return ""
		}
		visiting[subject] = true
		raw := rawBySubject[subject]
		name := departmentName(raw, subject)
		parent := weComParentDepartmentID(raw)
		parentPath := ""
		if parent != "" && parent != "0" && parent != subject {
			parentPath = buildPath(parent)
		}
		path := departmentPath(parentPath, name)
		pathBySubject[subject] = path
		delete(visiting, subject)
		return path
	}
	groups := make([]Group, 0, len(rawBySubject))
	for _, raw := range items {
		subject := weComDepartmentID(raw)
		if subject == "" {
			continue
		}
		parent := weComParentDepartmentID(raw)
		if parent == "0" {
			parent = ""
		}
		groups = append(groups, Group{
			ProviderSlug:  w.slug,
			Subject:       subject,
			ParentSubject: parent,
			Name:          departmentName(raw, subject),
			Path:          buildPath(subject),
		})
	}
	return groups, nil
}

func (w WeCom) ListGroupMembers(groupSubject string) ([]string, error) {
	token, err := w.accessToken()
	if err != nil {
		return nil, err
	}
	items, err := w.departmentUsers(token, groupSubject)
	if err != nil {
		return nil, err
	}
	var members []string
	for _, raw := range items {
		subject, _ := weComUserSubject(raw)
		if subject != "" {
			members = append(members, subject)
		}
	}
	return members, nil
}

func (w WeCom) departments(token string) ([]map[string]any, error) {
	endpoint := withQuery(strings.TrimRight(w.cfg.ContactBaseURL, "/")+"/department/list", map[string]string{
		"access_token": token,
	})
	var out map[string]any
	if err := w.getJSON(endpoint, &out); err != nil {
		return nil, err
	}
	return mapItems(out, "department"), nil
}

func (w WeCom) departmentUsers(token, departmentID string) ([]map[string]any, error) {
	endpoint := withQuery(strings.TrimRight(w.cfg.ContactBaseURL, "/")+"/user/list", map[string]string{
		"access_token":  token,
		"department_id": departmentID,
		"fetch_child":   "0",
	})
	var out map[string]any
	if err := w.getJSON(endpoint, &out); err != nil {
		return nil, err
	}
	return mapItems(out, "userlist"), nil
}

func (w WeCom) agentVisibleUserIDs(token string) ([]string, error) {
	endpoint := withQuery(strings.TrimRight(w.cfg.ContactBaseURL, "/")+"/agent/get", map[string]string{
		"access_token": token,
		"agentid":      strings.TrimSpace(w.cfg.AgentID),
	})
	var out map[string]any
	if err := w.getJSON(endpoint, &out); err != nil {
		return nil, err
	}
	items := nestedMapItems(out, "allow_userinfos", "user")
	userIDs := make([]string, 0, len(items))
	for _, raw := range items {
		if userID := firstStringish(raw, "userid", "UserId", "user_id"); userID != "" {
			userIDs = append(userIDs, userID)
		}
	}
	return uniqueStrings(userIDs), nil
}

func (w WeCom) visibleUserIDs(token string) ([]map[string]any, error) {
	endpoint := withQuery(strings.TrimRight(w.cfg.ContactBaseURL, "/")+"/user/list_id", map[string]string{
		"access_token": token,
	})
	var all []map[string]any
	seenCursors := map[string]bool{}
	cursor := ""
	for {
		body := map[string]any{"limit": w.pageLimit()}
		if cursor != "" {
			body["cursor"] = cursor
		}
		var out map[string]any
		if err := w.postJSON(endpoint, body, &out); err != nil {
			return nil, err
		}
		all = append(all, mapItems(out, "dept_user")...)
		nextCursor := strings.TrimSpace(firstStringish(out, "next_cursor"))
		if nextCursor == "" {
			return all, nil
		}
		if seenCursors[nextCursor] {
			return nil, errors.New("企业微信成员 ID 列表分页游标重复，请稍后重试")
		}
		seenCursors[nextCursor] = true
		cursor = nextCursor
	}
}

func (w WeCom) user(token, userID string) (map[string]any, error) {
	endpoint := withQuery(strings.TrimRight(w.cfg.ContactBaseURL, "/")+"/user/get", map[string]string{
		"access_token": token,
		"userid":       userID,
	})
	var out map[string]any
	if err := w.getJSON(endpoint, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (w WeCom) pageLimit() int {
	if w.cfg.DirectoryPageSize <= 0 {
		return 50
	}
	if w.cfg.DirectoryPageSize > 10000 {
		return 10000
	}
	return w.cfg.DirectoryPageSize
}

func (w WeCom) accessToken() (string, error) {
	endpoint := withQuery(w.cfg.TokenURL, map[string]string{
		"corpid":     w.cfg.CorpID,
		"corpsecret": w.cfg.CorpSecret,
	})
	var out map[string]any
	if err := w.getJSON(endpoint, &out); err != nil {
		return "", err
	}
	if token := firstString(out, "access_token"); token != "" {
		return token, nil
	}
	return "", errors.New("企业微信 access_token 缺失，请检查 CorpID、Secret 和可信 IP 配置")
}

func (w WeCom) getJSON(endpoint string, out any) error {
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	response, err := w.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return decodeWeComResponse(response, out)
}

func (w WeCom) postJSON(endpoint string, body any, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := w.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return decodeWeComResponse(response, out)
}

func decodeWeComResponse(response *http.Response, out any) error {
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode >= 400 {
		return formatWeComHTTPError(response.StatusCode, body)
	}
	if err := weComAPIError(response.StatusCode, body); err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func weComAPIError(statusCode int, body []byte) error {
	var parsed weComErrorBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	if parsed.ErrCode == 0 {
		return nil
	}
	return formatWeComHTTPError(statusCode, body)
}

func formatWeComHTTPError(statusCode int, body []byte) error {
	var parsed weComErrorBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("企业微信接口请求失败：HTTP %d，响应内容：%s", statusCode, strings.TrimSpace(string(body)))
	}
	message := firstNonEmpty(parsed.ErrMsg, strings.TrimSpace(string(body)))
	detail := ""
	if parsed.ErrCode == 48002 {
		detail = fmt.Sprintf("企业微信接口请求失败：HTTP %d，错误码：%d，%s。当前 Secret 无权调用本次同步所需的通讯录接口。请在企业微信管理后台确认 DSMPASS 使用的 Secret 具备读取通讯录/读取成员接口权限，并确认自建应用可见范围包含要同步的成员或部门。", statusCode, parsed.ErrCode, message)
	} else if parsed.ErrCode == 60020 {
		detail = fmt.Sprintf("企业微信接口请求失败：HTTP %d，错误码：%d，%s。请确认 DSMPASS 后端公网出口 IP 已加入企业微信应用的可信 IP，并检查 CorpID/Secret。", statusCode, parsed.ErrCode, message)
	} else if parsed.ErrCode != 0 {
		detail = fmt.Sprintf("企业微信接口请求失败：HTTP %d，错误码：%d，%s。请检查 CorpID、AgentID、Secret、可信 IP、可信域名和应用可见范围。", statusCode, parsed.ErrCode, message)
	} else {
		detail = fmt.Sprintf("企业微信接口请求失败：HTTP %d，%s", statusCode, message)
	}
	return &weComResponseError{errCode: parsed.ErrCode, detail: detail}
}

func weComDirectorySyncError(operation string, err error) error {
	prefix := fmt.Sprintf("企业微信%s失败，已中止同步", operation)
	var responseErr *weComResponseError
	if errors.As(err, &responseErr) && (responseErr.errCode == 60011 || responseErr.errCode == 48002) {
		return fmt.Errorf("%s。请到企业微信管理后台重新设置自建应用可见范围，确保包含需要同步的用户及其所属部门，并确认当前 Secret 具备读取通讯录部门和成员的权限：%w", prefix, err)
	}
	return fmt.Errorf("%s：%w", prefix, err)
}

func weComUserSubject(raw map[string]any) (string, string) {
	for _, item := range []struct {
		fields      []string
		subjectType string
	}{
		{[]string{"userid", "UserId", "user_id"}, "wecom_userid"},
		{[]string{"openid", "OpenId"}, "wecom_openid"},
	} {
		if value := firstStringish(raw, item.fields...); value != "" {
			return value, item.subjectType
		}
	}
	return "", ""
}

func weComUserActive(raw map[string]any) bool {
	status, ok := firstInt64(raw, "status")
	if !ok {
		return true
	}
	return status == 1
}

func weComDepartmentID(raw map[string]any) string {
	return firstStringish(raw, "id", "department_id", "open_department_id")
}

func weComParentDepartmentID(raw map[string]any) string {
	return firstStringish(raw, "parentid", "parent_id", "open_parent_department_id")
}

func withQuery(endpoint string, values map[string]string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		query := url.Values{}
		for key, value := range values {
			query.Set(key, value)
		}
		if strings.Contains(endpoint, "?") {
			return endpoint + "&" + query.Encode()
		}
		return endpoint + "?" + query.Encode()
	}
	query := parsed.Query()
	for key, value := range values {
		query.Set(key, value)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func withEncodedQuery(endpoint string, values url.Values) string {
	return withEncodedQueryAndFragment(endpoint, values, "")
}

func withEncodedQueryAndFragment(endpoint string, values url.Values, fragment string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		result := endpoint + "?" + values.Encode()
		if fragment != "" {
			result += "#" + fragment
		}
		return result
	}
	query := parsed.Query()
	for key, rawValues := range values {
		for _, value := range rawValues {
			query.Set(key, value)
		}
	}
	parsed.RawQuery = query.Encode()
	if fragment != "" {
		parsed.Fragment = fragment
	}
	return parsed.String()
}

func mapItems(raw map[string]any, key string) []map[string]any {
	items, _ := raw[key].([]any)
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if row, ok := item.(map[string]any); ok {
			result = append(result, row)
		}
	}
	return result
}

func nestedMapItems(raw map[string]any, parentKey, childKey string) []map[string]any {
	parent, _ := raw[parentKey].(map[string]any)
	if parent == nil {
		return nil
	}
	return mapItems(parent, childKey)
}

func firstStringish(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := raw[key]; ok {
			if text := stringish(value); text != "" {
				return text
			}
		}
	}
	return ""
}

func firstStringishSlice(raw map[string]any, keys ...string) []string {
	for _, key := range keys {
		value, ok := raw[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case []string:
			return typed
		case []int:
			result := make([]string, 0, len(typed))
			for _, item := range typed {
				result = append(result, strconv.Itoa(item))
			}
			return result
		case []int64:
			result := make([]string, 0, len(typed))
			for _, item := range typed {
				result = append(result, strconv.FormatInt(item, 10))
			}
			return result
		case []float64:
			result := make([]string, 0, len(typed))
			for _, item := range typed {
				result = append(result, strconv.FormatInt(int64(item), 10))
			}
			return result
		case []any:
			result := make([]string, 0, len(typed))
			for _, item := range typed {
				if text := stringish(item); text != "" {
					result = append(result, text)
				}
			}
			return result
		}
	}
	return nil
}

func firstInt64(raw map[string]any, keys ...string) (int64, bool) {
	for _, key := range keys {
		if value, ok := raw[key]; ok {
			switch typed := value.(type) {
			case int:
				return int64(typed), true
			case int64:
				return typed, true
			case float64:
				return int64(typed), true
			case json.Number:
				parsed, err := typed.Int64()
				return parsed, err == nil
			case string:
				parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
				return parsed, err == nil
			}
		}
	}
	return 0, false
}

func stringish(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case json.Number:
		return typed.String()
	default:
		return ""
	}
}
