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
	defaultDingTalkAuthorizeURL   = "https://login.dingtalk.com/oauth2/auth"
	defaultDingTalkUserTokenURL   = "https://api.dingtalk.com/v1.0/oauth2/userAccessToken"
	defaultDingTalkUserInfoURL    = "https://api.dingtalk.com/v1.0/contact/users/me"
	defaultDingTalkAppTokenURL    = "https://oapi.dingtalk.com/gettoken"
	defaultDingTalkContactBaseURL = "https://oapi.dingtalk.com/topapi"
)

type DingTalkConfig struct {
	AppKey            string
	AppSecret         string
	AuthorizeURL      string
	UserTokenURL      string
	UserInfoURL       string
	AppTokenURL       string
	ContactBaseURL    string
	DirectoryPageSize int
}

type dingTalkErrorBody struct {
	ErrCode   int64  `json:"errcode"`
	ErrMsg    string `json:"errmsg"`
	Code      any    `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"requestid"`
}

type DingTalk struct {
	cfg    DingTalkConfig
	slug   string
	client http.Client
}

func NewDingTalk(cfg DingTalkConfig) DingTalk {
	return NewDingTalkWithSlug(cfg, "dingtalk")
}

func NewDingTalkWithSlug(cfg DingTalkConfig, slug string) DingTalk {
	cfg = withDingTalkDefaults(cfg)
	return DingTalk{cfg: cfg, slug: slug, client: http.Client{Timeout: 15 * time.Second}}
}

func withDingTalkDefaults(cfg DingTalkConfig) DingTalkConfig {
	if cfg.AuthorizeURL == "" {
		cfg.AuthorizeURL = defaultDingTalkAuthorizeURL
	}
	if cfg.UserTokenURL == "" {
		cfg.UserTokenURL = defaultDingTalkUserTokenURL
	}
	if cfg.UserInfoURL == "" {
		cfg.UserInfoURL = defaultDingTalkUserInfoURL
	}
	if cfg.AppTokenURL == "" {
		cfg.AppTokenURL = defaultDingTalkAppTokenURL
	}
	if cfg.ContactBaseURL == "" {
		cfg.ContactBaseURL = defaultDingTalkContactBaseURL
	}
	if cfg.DirectoryPageSize <= 0 {
		cfg.DirectoryPageSize = 50
	}
	return cfg
}

func (d DingTalk) Slug() string {
	return d.slug
}

func (d DingTalk) ProviderDisplayName() string {
	return "钉钉"
}

func (d DingTalk) BuildAuthorizeURL(state, redirectURI string) string {
	values := url.Values{}
	values.Set("redirect_uri", redirectURI)
	values.Set("response_type", "code")
	values.Set("client_id", d.cfg.AppKey)
	values.Set("scope", "openid")
	values.Set("state", state)
	values.Set("prompt", "consent")
	return withEncodedQuery(d.cfg.AuthorizeURL, values)
}

func (d DingTalk) ExchangeCode(code, redirectURI string) (map[string]any, error) {
	payload := map[string]string{
		"clientId":     d.cfg.AppKey,
		"clientSecret": d.cfg.AppSecret,
		"code":         code,
		"grantType":    "authorization_code",
	}
	var out map[string]any
	if err := d.postJSON(d.cfg.UserTokenURL, payload, "", &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (d DingTalk) FetchProfile(token map[string]any) (map[string]any, error) {
	accessToken := firstStringish(token, "accessToken", "access_token")
	if accessToken == "" {
		return nil, errors.New("钉钉用户 accessToken 缺失，请检查扫码登录回调 code 是否有效")
	}
	request, err := http.NewRequest(http.MethodGet, d.cfg.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("x-acs-dingtalk-access-token", accessToken)
	response, err := d.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var out map[string]any
	if err := decodeDingTalkResponse(response, &out); err != nil {
		return nil, err
	}
	if data, ok := out["data"].(map[string]any); ok {
		return data, nil
	}
	if result, ok := out["result"].(map[string]any); ok {
		return result, nil
	}
	return out, nil
}

func (d DingTalk) ProfileSubject(profile map[string]any) (string, string) {
	return dingTalkUserSubject(profile)
}

func (d DingTalk) ListUsers() ([]User, error) {
	token, err := d.appAccessToken()
	if err != nil {
		return nil, err
	}
	groups, err := d.listGroups(token)
	if err != nil {
		return nil, err
	}
	return d.listUsers(token, groups)
}

func (d DingTalk) ListUsersAndGroups() ([]User, []Group, error) {
	token, err := d.appAccessToken()
	if err != nil {
		return nil, nil, err
	}
	groups, err := d.listGroups(token)
	if err != nil {
		return nil, nil, err
	}
	users, err := d.listUsers(token, groups)
	if err != nil {
		return nil, nil, err
	}
	return users, groups, nil
}

func (d DingTalk) listUsers(token string, groups []Group) ([]User, error) {
	usersBySubject := map[string]User{}
	loadUser := d.cachedUserGetter(token)
	for _, group := range groups {
		items, err := d.departmentUsers(token, group.Subject)
		if err != nil {
			return nil, err
		}
		for _, raw := range items {
			userID := firstStringish(raw, "userid", "userId", "user_id")
			if userID == "" {
				continue
			}
			detail, err := loadUser(userID)
			if err != nil {
				return nil, err
			}
			if err := d.upsertUserFromRaw(usersBySubject, detail, []string{group.Subject}); err != nil {
				return nil, err
			}
		}
	}
	return usersFromMap(usersBySubject), nil
}

func (d DingTalk) ListGroups() ([]Group, error) {
	token, err := d.appAccessToken()
	if err != nil {
		return nil, err
	}
	return d.listGroups(token)
}

func (d DingTalk) listGroups(token string) ([]Group, error) {
	root := Group{
		ProviderSlug: d.slug,
		Subject:      "1",
		Name:         "钉钉组织",
		Path:         "钉钉组织",
	}
	if info, err := d.departmentInfo(token, "1"); err == nil {
		if name := departmentName(info, "1"); name != "" {
			root.Name = name
			root.Path = name
		}
	}
	groups := []Group{root}
	queue := []Group{root}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		children, err := d.departmentChildren(token, parent.Subject)
		if err != nil {
			return nil, err
		}
		for _, raw := range children {
			subject := dingTalkDepartmentID(raw)
			if subject == "" {
				continue
			}
			name := departmentName(raw, subject)
			parentSubject := dingTalkParentDepartmentID(raw)
			if parentSubject == "" || parentSubject == "0" {
				parentSubject = parent.Subject
			}
			group := Group{
				ProviderSlug:  d.slug,
				Subject:       subject,
				ParentSubject: parentSubject,
				Name:          name,
				Path:          departmentPath(parent.Path, name),
			}
			groups = append(groups, group)
			queue = append(queue, group)
		}
	}
	return groups, nil
}

func (d DingTalk) ListGroupMembers(groupSubject string) ([]string, error) {
	token, err := d.appAccessToken()
	if err != nil {
		return nil, err
	}
	items, err := d.departmentUsers(token, groupSubject)
	if err != nil {
		return nil, err
	}
	var members []string
	loadUser := d.cachedUserGetter(token)
	for _, raw := range items {
		detail := raw
		if userID := firstStringish(raw, "userid", "userId", "user_id"); userID != "" {
			detail, err = loadUser(userID)
			if err != nil {
				return nil, err
			}
		}
		subject, _, err := dingTalkDirectoryUserSubject(detail)
		if err != nil {
			return nil, err
		}
		if subject != "" {
			members = append(members, subject)
		}
	}
	return uniqueStrings(members), nil
}

func (d DingTalk) departmentInfo(token, departmentID string) (map[string]any, error) {
	endpoint := withQuery(strings.TrimRight(d.cfg.ContactBaseURL, "/")+"/v2/department/get", map[string]string{
		"access_token": token,
	})
	var out map[string]any
	if err := d.postJSON(endpoint, map[string]any{"dept_id": dingTalkIDValue(departmentID)}, "", &out); err != nil {
		return nil, err
	}
	if result, ok := out["result"].(map[string]any); ok {
		return result, nil
	}
	return out, nil
}

func (d DingTalk) departmentChildren(token, departmentID string) ([]map[string]any, error) {
	endpoint := withQuery(strings.TrimRight(d.cfg.ContactBaseURL, "/")+"/v2/department/listsub", map[string]string{
		"access_token": token,
	})
	var out map[string]any
	if err := d.postJSON(endpoint, map[string]any{"dept_id": dingTalkIDValue(departmentID)}, "", &out); err != nil {
		return nil, err
	}
	return mapItems(out, "result"), nil
}

func (d DingTalk) departmentUsers(token, departmentID string) ([]map[string]any, error) {
	endpoint := withQuery(strings.TrimRight(d.cfg.ContactBaseURL, "/")+"/user/listsimple", map[string]string{
		"access_token": token,
	})
	var all []map[string]any
	cursor := int64(0)
	seenCursors := map[int64]bool{}
	for {
		body := map[string]any{
			"dept_id": dingTalkIDValue(departmentID),
			"cursor":  cursor,
			"size":    d.pageSize(),
		}
		var out map[string]any
		if err := d.postJSON(endpoint, body, "", &out); err != nil {
			return nil, err
		}
		result, _ := out["result"].(map[string]any)
		all = append(all, mapItems(result, "list")...)
		hasMore, _ := result["has_more"].(bool)
		if !hasMore {
			return all, nil
		}
		nextCursor, ok := firstInt64(result, "next_cursor")
		if !ok {
			return nil, errors.New("钉钉部门用户分页缺少 next_cursor")
		}
		if seenCursors[nextCursor] {
			return nil, errors.New("钉钉部门用户分页游标重复，请稍后重试")
		}
		seenCursors[nextCursor] = true
		cursor = nextCursor
	}
}

func (d DingTalk) user(token, userID string) (map[string]any, error) {
	endpoint := withQuery(strings.TrimRight(d.cfg.ContactBaseURL, "/")+"/v2/user/get", map[string]string{
		"access_token": token,
	})
	var out map[string]any
	if err := d.postJSON(endpoint, map[string]any{"userid": userID, "language": "zh_CN"}, "", &out); err != nil {
		return nil, err
	}
	if result, ok := out["result"].(map[string]any); ok {
		return result, nil
	}
	return out, nil
}

func (d DingTalk) cachedUserGetter(token string) func(string) (map[string]any, error) {
	cache := map[string]map[string]any{}
	return func(userID string) (map[string]any, error) {
		if detail, ok := cache[userID]; ok {
			return detail, nil
		}
		detail, err := d.user(token, userID)
		if err != nil {
			return nil, err
		}
		if firstStringish(detail, "userid", "userId", "user_id") == "" {
			detail["userid"] = userID
		}
		cache[userID] = detail
		return detail, nil
	}
}

func (d DingTalk) upsertUserFromRaw(usersBySubject map[string]User, raw map[string]any, fallbackDepartments []string) error {
	subject, subjectType, err := dingTalkDirectoryUserSubject(raw)
	if err != nil {
		return err
	}
	if subject == "" {
		return nil
	}
	displayName := userDisplayName(raw)
	if displayName == "" {
		displayName = subject
	}
	departmentSubjects := uniqueStrings(firstStringishSlice(raw, "dept_id_list", "department", "department_ids", "departments"))
	if len(departmentSubjects) == 0 {
		departmentSubjects = uniqueStrings(fallbackDepartments)
	}
	existing := usersBySubject[subject]
	user := User{
		ProviderSlug: d.slug,
		Subject:      subject,
		SubjectType:  subjectType,
		DisplayName:  displayName,
		Email:        firstString(raw, "email", "org_email"),
		Mobile:       firstString(raw, "mobile"),
		Active:       dingTalkUserActive(raw),
	}
	if existing.Subject != "" {
		user.DepartmentSubjects = uniqueStrings(append(existing.DepartmentSubjects, departmentSubjects...))
		user.Active = existing.Active || user.Active
	} else {
		user.DepartmentSubjects = departmentSubjects
	}
	usersBySubject[subject] = user
	return nil
}

func (d DingTalk) appAccessToken() (string, error) {
	endpoint := strings.TrimSpace(d.cfg.AppTokenURL)
	if strings.Contains(endpoint, "/v1.0/") {
		var out map[string]any
		if err := d.postJSON(endpoint, map[string]string{"appKey": d.cfg.AppKey, "appSecret": d.cfg.AppSecret}, "", &out); err != nil {
			return "", err
		}
		if token := firstStringish(out, "accessToken", "access_token"); token != "" {
			return token, nil
		}
		return "", errors.New("钉钉应用 accessToken 缺失，请检查 AppKey/AppSecret")
	}
	endpoint = withQuery(endpoint, map[string]string{
		"appkey":    d.cfg.AppKey,
		"appsecret": d.cfg.AppSecret,
	})
	var out map[string]any
	if err := d.getJSON(endpoint, "", &out); err != nil {
		return "", err
	}
	if token := firstStringish(out, "access_token", "accessToken"); token != "" {
		return token, nil
	}
	return "", errors.New("钉钉应用 access_token 缺失，请检查 AppKey/AppSecret")
}

func (d DingTalk) pageSize() int {
	if d.cfg.DirectoryPageSize <= 0 {
		return 50
	}
	if d.cfg.DirectoryPageSize > 100 {
		return 100
	}
	return d.cfg.DirectoryPageSize
}

func (d DingTalk) getJSON(endpoint, bearer string, out any) error {
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	if bearer != "" {
		request.Header.Set("x-acs-dingtalk-access-token", bearer)
	}
	response, err := d.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return decodeDingTalkResponse(response, out)
}

func (d DingTalk) postJSON(endpoint string, body any, bearer string, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		request.Header.Set("x-acs-dingtalk-access-token", bearer)
	}
	response, err := d.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return decodeDingTalkResponse(response, out)
}

func decodeDingTalkResponse(response *http.Response, out any) error {
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode >= 400 {
		return formatDingTalkHTTPError(response.StatusCode, body)
	}
	if err := dingTalkAPIError(response.StatusCode, body); err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func dingTalkAPIError(statusCode int, body []byte) error {
	var parsed dingTalkErrorBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	if parsed.ErrCode != 0 {
		return formatDingTalkHTTPError(statusCode, body)
	}
	code := strings.TrimSpace(stringish(parsed.Code))
	if code != "" && code != "0" && !strings.EqualFold(code, "ok") {
		return formatDingTalkHTTPError(statusCode, body)
	}
	return nil
}

func formatDingTalkHTTPError(statusCode int, body []byte) error {
	var parsed dingTalkErrorBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("钉钉接口请求失败：HTTP %d，响应内容：%s", statusCode, strings.TrimSpace(string(body)))
	}
	message := firstNonEmpty(parsed.ErrMsg, parsed.Message, strings.TrimSpace(string(body)))
	code := firstNonEmpty(stringish(parsed.Code), stringish(parsed.ErrCode))
	if parsed.RequestID != "" {
		return fmt.Errorf("钉钉接口请求失败：HTTP %d，错误码：%s，%s，requestid：%s。请检查 AppKey/AppSecret、扫码登录回调域名、应用权限和通讯录权限范围。", statusCode, code, message, parsed.RequestID)
	}
	return fmt.Errorf("钉钉接口请求失败：HTTP %d，错误码：%s，%s。请检查 AppKey/AppSecret、扫码登录回调域名、应用权限和通讯录权限范围。", statusCode, code, message)
}

func dingTalkUserSubject(raw map[string]any) (string, string) {
	for _, item := range []struct {
		fields      []string
		subjectType string
	}{
		{[]string{"unionid", "unionId", "union_id"}, "dingtalk_unionid"},
		{[]string{"openid", "openId", "open_id"}, "dingtalk_openid"},
		{[]string{"userid", "userId", "user_id"}, "dingtalk_userid"},
	} {
		if value := firstStringish(raw, item.fields...); value != "" {
			return value, item.subjectType
		}
	}
	return "", ""
}

func dingTalkDirectoryUserSubject(raw map[string]any) (string, string, error) {
	for _, item := range []struct {
		fields      []string
		subjectType string
	}{
		{[]string{"unionid", "unionId", "union_id"}, "dingtalk_unionid"},
		{[]string{"openid", "openId", "open_id"}, "dingtalk_openid"},
	} {
		if value := firstStringish(raw, item.fields...); value != "" {
			return value, item.subjectType, nil
		}
	}
	if userID := firstStringish(raw, "userid", "userId", "user_id"); userID != "" {
		return "", "", fmt.Errorf("钉钉通讯录用户 %s 缺少 unionid/openid，无法和扫码登录身份保持一致；请检查钉钉应用通讯录权限和可见范围", userID)
	}
	return "", "", nil
}

func dingTalkUserActive(raw map[string]any) bool {
	if value, ok := raw["active"].(bool); ok {
		return value
	}
	if value, ok := firstInt64(raw, "active"); ok {
		return value != 0
	}
	return true
}

func dingTalkDepartmentID(raw map[string]any) string {
	return firstStringish(raw, "dept_id", "deptId", "department_id", "id")
}

func dingTalkParentDepartmentID(raw map[string]any) string {
	return firstStringish(raw, "parent_id", "parentId", "parentid")
}

func dingTalkIDValue(value string) any {
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err == nil {
		return parsed
	}
	return value
}
