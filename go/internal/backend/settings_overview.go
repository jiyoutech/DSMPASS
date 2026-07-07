package backend

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type settingsOverviewResponse struct {
	Title            string                   `json:"title"`
	Summary          []string                 `json:"summary"`
	Runtime          []settingsOverviewFact   `json:"runtime"`
	DeploymentModes  []settingsOverviewFact   `json:"deployment_modes"`
	Configuration    []settingsOverviewConfig `json:"configuration"`
	Certificates     []settingsOverviewConfig `json:"certificates"`
	OperationalNotes []string                 `json:"operational_notes"`
}

type settingsOverviewFact struct {
	Title        string   `json:"title"`
	Value        string   `json:"value"`
	Configurable bool     `json:"configurable"`
	ChangeMethod string   `json:"change_method"`
	Applies      string   `json:"applies"`
	Description  string   `json:"description"`
	Notes        []string `json:"notes"`
}

type settingsOverviewConfig struct {
	Key          string   `json:"key"`
	Label        string   `json:"label"`
	Value        string   `json:"value"`
	Configurable bool     `json:"configurable"`
	ChangeMethod string   `json:"change_method"`
	Applies      string   `json:"applies"`
	Effect       string   `json:"effect"`
	Notes        []string `json:"notes"`
}

func (s *Server) settingsOverview(c *gin.Context) {
	settings, err := s.effectiveSettings(c.Request.Context())
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, s.buildSettingsOverview(settings))
}

func (s *Server) buildSettingsOverview(settings map[string]any) settingsOverviewResponse {
	adminListen := s.AdminListenAddress()
	idpListen := s.IDPListenAddress()
	if idpListen == "" {
		idpListen = adminListen
	}
	adminPort := firstPositiveInt(parsePortInt(listenAddressPort(adminListen)), 25000)
	idpPort := firstPositiveInt(parsePortInt(listenAddressPort(idpListen)), parsePortInt(publicBaseURLPort(s.cfg.PublicBaseURL)), adminPort, 25000)
	routeTopology := "管理后台和 /idp 认证入口共用同一个本机监听"
	if idpListen != "" && !listenAddressesEqual(idpListen, adminListen) {
		routeTopology = "/idp 认证入口使用独立本机监听"
	} else {
		routeTopology = "管理后台和 /idp 认证入口当前共用同一个本机监听；建议将 IDP 监听端口改为 " + strconv.Itoa(defaultIDPPortForAdmin(adminPort))
	}
	adminProtocol := "HTTP"
	if s.cfg.TLSEnabled {
		adminProtocol = "HTTPS"
	}
	idpProtocol := "HTTP"
	if s.IDPTLSEnabled() {
		idpProtocol = "HTTPS"
	}
	deploymentMode := normalizeDeploymentMode(overviewString(settings, "deployment_mode", s.cfg.DeploymentMode))
	accessHost := overviewString(settings, "access_host", s.cfg.AccessHost)
	accessScheme := overviewString(settings, "access_scheme", s.configuredAccessScheme())
	publicBaseURL := overviewString(settings, "public_base_url", s.cfg.PublicBaseURL)
	dsmRedirectURL := overviewString(settings, "dsm_redirect_url", s.cfg.DSMRedirectURL)
	helperDSMLoginAPI := overviewString(settings, "helper_dsm_login_api", s.cfg.HelperDSMLoginAPI)
	dsmLoginMode := overviewString(settings, "helper_dsm_login_mode", s.cfg.DSMLoginMode)
	adminAllowedCIDRs := overviewString(settings, "admin_allowed_cidrs", s.cfg.AdminAllowedCIDRs)
	browserLoginTTL := overviewInt(settings, "helper_dsm_browser_login_ttl_seconds", s.cfg.DSMBrowserLoginTTLSeconds)
	dsmTLSSkipVerify := overviewBool(settings, "helper_dsm_tls_skip_verify", true)

	return settingsOverviewResponse{
		Title: "系统说明",
		Summary: []string{
			"DSMPASS 有两个入口：管理后台用于配置、同步、审计和证书管理；认证入口用于 /idp 登录、OAuth 回调和跳转 DSM。两个入口默认使用不同端口，避免管理面和登录面混用。",
			"反向代理只改变用户浏览器和外部身份平台访问 DSMPASS 的公网地址，不会取消 DSMPASS 在 NAS 本机上的监听端口。反代必须转发到对应的本机监听。",
			"系统设置页只允许修改运行期可安全调整的配置。套件启动参数、管理后台监听、证书文件路径等运行环境信息只读展示；如需修改，需要改套件环境并重启 DSMPASS 套件。",
			"每个配置项都标明了修改入口、何时生效和影响范围。保存后立即生效表示后端内存配置和数据库会同步更新；刷新认证路由表示只重启 /idp listener，不重启管理后台。",
		},
		Runtime: []settingsOverviewFact{
			{
				Title:        "管理后台本机监听",
				Value:        listenValue(adminListen, adminPort),
				Configurable: false,
				ChangeMethod: "修改套件环境变量 DSMPASS_GO_LISTEN 或安装向导管理端口",
				Applies:      "重启 DSMPASS 套件后生效",
				Description:  "管理后台页面、静态前端和 /api/admin 接口使用此监听。系统设置页不会修改它。",
				Notes: []string{
					"套件中心打开按钮使用管理后台端口。",
					"不建议把管理后台端口映射给公网用户登录使用。",
				},
			},
			{
				Title:        "认证入口本机监听",
				Value:        listenValue(idpListen, idpPort),
				Configurable: true,
				ChangeMethod: "系统设置 > 基础配置 > IDP 监听端口",
				Applies:      "保存后刷新认证路由；无需重启套件",
				Description:  "/idp 登录入口实际监听在此地址。反向代理场景下，公网域名应转发到这个监听。",
				Notes: []string{
					"端口必须大于 1024，不能与管理后台端口一致，且不能被其他进程占用。",
					"如果保存时重启认证路由失败，页面会返回错误信息；旧路由不会被静默当作成功。",
				},
			},
			{
				Title:        "路由拓扑",
				Value:        routeTopology,
				Configurable: true,
				ChangeMethod: "调整 IDP 监听端口",
				Applies:      "保存后刷新认证路由",
				Description:  "管理后台和认证入口应保持独立监听。端口不同则启动独立的 IDP 路由。",
				Notes: []string{
					"如果这里显示共用监听，说明仍存在旧配置或异常配置，应将 IDP 监听端口改为独立端口。",
				},
			},
			{
				Title:        "管理后台协议",
				Value:        adminProtocol,
				Configurable: false,
				ChangeMethod: "修改套件环境变量 DSMPASS_TLS_ENABLED",
				Applies:      "重启 DSMPASS 套件后生效",
				Description:  "影响管理后台 HTTPS 连接和管理端证书，不决定 OAuth 回调地址。",
				Notes: []string{
					"上传管理端证书只替换证书，不改变管理后台协议。",
				},
			},
			{
				Title:        "认证入口协议",
				Value:        idpProtocol,
				Configurable: true,
				ChangeMethod: "系统设置 > 基础配置 > IDP 协议",
				Applies:      "保存后刷新认证路由；无需重启套件",
				Description:  "影响本机 /idp 监听使用 HTTP 还是 HTTPS。公网协议以认证入口公网地址为准。",
				Notes: []string{
					"反代终止 TLS 时，公网地址可以是 HTTPS，本机 IDP 协议可以按反代目标选择 HTTP 或 HTTPS。",
				},
			},
			{
				Title:        "认证入口公网地址",
				Value:        publicBaseURL,
				Configurable: true,
				ChangeMethod: "系统设置 > 基础配置 > IDP 对外地址",
				Applies:      "保存后立即影响新生成的登录地址和回调地址",
				Description:  "外部身份平台和用户浏览器看到的 DSMPASS 基址，登录地址和回调地址都从这里生成。",
				Notes: []string{
					"它不会改变本机监听端口。",
					"企业微信、飞书、钉钉后台的回调域名需要与这里保持一致。",
				},
			},
			{
				Title:        "OAuth 回调地址格式",
				Value:        strings.TrimRight(publicBaseURL, "/") + "/idp/{provider}/callback",
				Configurable: false,
				ChangeMethod: "由认证入口公网地址和身份源标识自动生成",
				Applies:      "认证入口公网地址变更后立即更新",
				Description:  "在企业微信、飞书、钉钉等平台配置回调域名时，应与此地址所属域名保持一致。",
				Notes: []string{
					"{provider} 是身份源标识，不需要在平台里照字面填写。",
				},
			},
			{
				Title:        "DSM 登录目标",
				Value:        dsmRedirectURL,
				Configurable: true,
				ChangeMethod: "系统设置 > DSM 登录 > DSM 地址",
				Applies:      "保存后立即影响后续登录跳转",
				Description:  "用户完成身份源登录后，最终跳转到这个 DSM 地址。",
				Notes: []string{
					"浏览器直登模式下，用户浏览器必须能访问这个地址。",
				},
			},
		},
		DeploymentModes: []settingsOverviewFact{
			{
				Title:       "直接访问",
				Value:       modeActiveValue(deploymentMode, "direct"),
				Description: "根据默认 NAS 主机名、本机 IDP 端口和协议生成认证入口公网地址，同时生成 DSM 地址和 DSM Auth API。",
			},
			{
				Title:       "反向代理",
				Value:       modeActiveValue(deploymentMode, "reverse_proxy"),
				Description: "认证入口公网地址填写反代后的域名；本机 IDP 端口仍然存在，反代需要转发到该端口。",
			},
			{
				Title:       "高级",
				Value:       modeActiveValue(deploymentMode, "advanced"),
				Description: "允许分别指定认证入口公网地址、DSM 地址和 DSM Auth API，适合 DSM 与 IDP 暴露路径不一致的环境。",
			},
		},
		Configuration: []settingsOverviewConfig{
			{
				Key:          "deployment_mode",
				Label:        "部署方式",
				Value:        deploymentModeLabel(deploymentMode),
				Configurable: true,
				ChangeMethod: "系统设置 > 基础配置 > 部署方式",
				Applies:      "保存后立即影响前端地址推导；涉及 IDP 协议或端口时会刷新认证路由",
				Effect:       "影响系统设置页的地址推导方式和哪些地址允许手动编辑。",
				Notes: []string{
					"不会关闭本机 /idp 监听端口。",
					"选择反向代理后，仍需要确保反代目标指向认证入口本机监听。",
				},
			},
			{
				Key:          "access_host",
				Label:        "默认 NAS 主机名",
				Value:        accessHost,
				Configurable: true,
				ChangeMethod: "系统设置 > 基础配置 > NAS IP / 域名，或上传认证端证书自动识别非通配符 DNS SAN",
				Applies:      "保存后立即更新默认地址推导；直接访问模式会同步派生地址",
				Effect:       "用于生成默认认证入口地址、DSM 地址和 DSM Auth API，也是认证端证书自动识别域名时会更新的主机名。",
				Notes: []string{
					"填写主机名或 IP，不包含协议、端口和路径。",
					"高级模式下，公网认证地址和 DSM 地址可以与该值不同。",
				},
			},
			{
				Key:          "access_scheme",
				Label:        "本机 IDP 协议",
				Value:        accessScheme,
				Configurable: true,
				ChangeMethod: "系统设置 > 基础配置 > IDP 协议",
				Applies:      "保存后刷新认证路由；无需重启 DSMPASS 套件",
				Effect:       "决定 DSMPASS 本机 /idp 监听使用 HTTP 还是 HTTPS，并影响默认 DSM 地址端口推导。",
				Notes: []string{
					"变更后会刷新认证路由。",
					"反向代理的公网协议由认证入口公网地址决定，不由该字段单独决定。",
				},
			},
			{
				Key:          "idp_port",
				Label:        "本机 IDP 监听端口",
				Value:        strconv.Itoa(idpPort),
				Configurable: true,
				ChangeMethod: "系统设置 > 基础配置 > IDP 监听端口",
				Applies:      "保存后刷新认证路由；端口可用时无需重启 DSMPASS 套件",
				Effect:       "决定 DSMPASS 在本机提供 /idp 登录入口的端口。",
				Notes: []string{
					"反向代理场景下，该端口仍然存在，反代需要转发到它。",
					"不会自动改变认证入口公网地址中的端口；公网地址由认证入口公网地址字段决定。",
					"不能与管理后台端口一致。",
				},
			},
			{
				Key:          "public_base_url",
				Label:        "认证入口公网地址",
				Value:        publicBaseURL,
				Configurable: true,
				ChangeMethod: "系统设置 > 基础配置 > IDP 对外地址",
				Applies:      "保存后立即影响新生成的登录地址、回调地址和身份源展示",
				Effect:       "决定登录链接和 OAuth redirect_uri/callback_url，是企业微信、飞书、钉钉等平台需要配置的外部地址。",
				Notes: []string{
					"它描述外部访问地址，不改变 DSMPASS 本机监听端口。",
					"更换域名后，需要同步更新各身份平台的回调域名和可信域名配置。",
				},
			},
			{
				Key:          "dsm_redirect_url",
				Label:        "DSM 访问地址",
				Value:        dsmRedirectURL,
				Configurable: true,
				ChangeMethod: "系统设置 > DSM 登录 > DSM 地址",
				Applies:      "保存后立即影响后续认证成功后的跳转目标",
				Effect:       "决定认证成功后浏览器跳回哪个 DSM 地址。",
				Notes: []string{
					"浏览器直登模式下，浏览器必须能访问该地址。",
					"如果外网用户无法访问 DSM，该流程会在跳转 DSM 时失败。",
				},
			},
			{
				Key:          "helper_dsm_login_api",
				Label:        "DSM Auth API",
				Value:        helperDSMLoginAPI,
				Configurable: true,
				ChangeMethod: "系统设置 > DSM 登录 > DSM Auth API",
				Applies:      "保存后立即影响后续 DSM 登录调用",
				Effect:       "决定浏览器直登或 Helper 调用哪个 DSM SYNO.API.Auth 登录接口。",
				Notes: []string{
					"浏览器直登模式下，用户浏览器会直接访问该地址。",
					"Helper 连接模式下，由 NAS 上的 helper 访问该地址。",
				},
			},
			{
				Key:          "helper_dsm_login_mode",
				Label:        "DSM 登录模式",
				Value:        dsmLoginModeLabel(dsmLoginMode),
				Configurable: true,
				ChangeMethod: "系统设置 > DSM 登录 > DSM 登录模式",
				Applies:      "保存后立即影响后续登录流程",
				Effect:       "决定认证成功后由浏览器直接登录 DSM，还是由本机 Helper 代为调用 DSM Auth API。",
				Notes: []string{
					"浏览器直登要求 DSM 地址和 DSM Auth API 对用户浏览器可达。",
					"Helper 连接适合 DSM 不直接暴露给外网的场景。",
				},
			},
			{
				Key:          "admin_allowed_cidrs",
				Label:        "管理端访问范围",
				Value:        cidrLabel(adminAllowedCIDRs),
				Configurable: true,
				ChangeMethod: "系统设置 > 基础配置 > 管理端仅允许内网访问",
				Applies:      "保存后立即影响管理后台和 /api/admin 的新请求",
				Effect:       "限制管理后台页面和 /api/admin 接口允许哪些来源 IP 访问。",
				Notes: []string{
					"不影响 /idp 登录入口。",
					"保存时会校验当前访问 IP，避免把当前管理员锁在外面。",
				},
			},
			{
				Key:          "helper_dsm_browser_login_ttl_seconds",
				Label:        "直登 TTL",
				Value:        strconv.Itoa(browserLoginTTL) + " 秒",
				Configurable: true,
				ChangeMethod: "系统设置 > DSM 登录 > 直登 TTL 秒数",
				Applies:      "保存后立即影响后续浏览器直登临时密码",
				Effect:       "控制浏览器直登模式下临时 DSM 密码的有效时间。",
				Notes: []string{
					"时间越短暴露窗口越小，但弱网环境下用户可能来不及完成 DSM 登录。",
				},
			},
			{
				Key:          "helper_dsm_tls_skip_verify",
				Label:        "跳过 DSM TLS 校验",
				Value:        enabledLabel(dsmTLSSkipVerify),
				Configurable: true,
				ChangeMethod: "系统设置 > DSM 登录 > 跳过 DSM TLS 校验",
				Applies:      "保存后立即影响后续 DSMPASS/Helper 访问 DSM Auth API",
				Effect:       "控制 DSMPASS/Helper 访问 DSM Auth API 时是否跳过 DSM 证书校验。",
				Notes: []string{
					"适合 DSM 使用自签名证书的环境。",
					"如果 DSM 使用受信任证书，建议关闭。",
				},
			},
		},
		Certificates: []settingsOverviewConfig{
			{
				Key:          "admin_certificate",
				Label:        "管理端证书",
				Value:        "独立证书槽位",
				Configurable: true,
				ChangeMethod: "系统设置 > 证书与路由 > 上传管理端证书",
				Applies:      "上传后无需重启；新建 HTTPS 连接自动使用新证书",
				Effect:       "用于管理后台 HTTPS 连接。",
				Notes: []string{
					"上传后不会修改认证入口公网地址。",
					"无需重启套件；新建 HTTPS 连接会自动使用新证书。",
				},
			},
			{
				Key:          "idp_certificate",
				Label:        "认证端口证书",
				Value:        "独立证书槽位",
				Configurable: true,
				ChangeMethod: "系统设置 > 证书与路由 > 上传认证端证书",
				Applies:      "上传后无需重启；新建 /idp HTTPS 连接自动使用新证书",
				Effect:       "用于 /idp 登录入口 HTTPS 连接。",
				Notes: []string{
					"如果证书包含非通配符 DNS SAN，会自动同步为认证入口域名。",
					"通配符证书可以使用，但不会自动改写认证入口公网域名。",
				},
			},
		},
		OperationalNotes: []string{
			"企业微信、飞书、钉钉的回调域名应以认证入口公网地址为准，不以管理后台地址为准。",
			"如果外网只暴露 IDP 而不暴露 DSM，浏览器直登模式无法完成最终 DSM 登录；应改用 Helper 连接，或让用户浏览器可以访问 DSM 地址。",
			"修改本机 IDP 监听端口会刷新认证路由；修改认证入口公网地址会影响新生成的登录链接和身份平台回调地址。",
			"管理后台监听端口和管理后台 HTTP/HTTPS 协议不是运行期设置项；修改套件环境变量后必须重启 DSMPASS 套件。",
			"证书上传只替换对应入口的 TLS 证书，不会自动改变另一个入口，也不会自动开放 DSM 或 NAS 防火墙端口。",
			"身份平台的可信域名、回调域名、企业微信可信 IP 等平台侧配置，需要在平台后台单独维护；DSMPASS 只能展示和生成本系统侧地址。",
		},
	}
}

func listenValue(listen string, fallbackPort int) string {
	if listen != "" {
		return listen
	}
	if fallbackPort > 0 {
		return "0.0.0.0:" + strconv.Itoa(fallbackPort)
	}
	return "未配置"
}

func modeActiveValue(current, mode string) string {
	if current == mode {
		return "当前使用"
	}
	return "可选"
}

func deploymentModeLabel(value string) string {
	switch normalizeDeploymentMode(value) {
	case "reverse_proxy":
		return "反向代理"
	case "advanced":
		return "高级"
	default:
		return "直接访问"
	}
}

func dsmLoginModeLabel(value string) string {
	if value == "helper" {
		return "Helper 连接"
	}
	return "直接连接"
}

func enabledLabel(value bool) string {
	if value {
		return "已开启"
	}
	return "已关闭"
}

func cidrLabel(value string) string {
	if value == "" || strings.EqualFold(value, "all") || strings.EqualFold(value, "any") {
		return "不限来源"
	}
	if _, ok := cidrAlias(value); ok {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "private", "lan", "local", "intranet", "内网":
			return "仅本机和内网"
		case "loopback", "localhost", "本机":
			return "仅本机"
		}
	}
	return value
}

func overviewString(settings map[string]any, key, fallback string) string {
	if settings == nil {
		return fallback
	}
	switch value := settings[key].(type) {
	case string:
		if strings.TrimSpace(value) != "" {
			return value
		}
	case int:
		return strconv.Itoa(value)
	case int64:
		return strconv.FormatInt(value, 10)
	case float64:
		return strconv.Itoa(int(value))
	case bool:
		return enabledLabel(value)
	}
	return fallback
}

func overviewInt(settings map[string]any, key string, fallback int) int {
	if settings == nil {
		return fallback
	}
	switch value := settings[key].(type) {
	case int:
		if value > 0 {
			return value
		}
	case int64:
		if value > 0 {
			return int(value)
		}
	case float64:
		if value > 0 {
			return int(value)
		}
	}
	return fallback
}

func overviewBool(settings map[string]any, key string, fallback bool) bool {
	if settings == nil {
		return fallback
	}
	if value, ok := settings[key].(bool); ok {
		return value
	}
	return fallback
}

func listenAddressesEqual(left, right string) bool {
	leftHost, leftPort, leftErr := net.SplitHostPort(strings.TrimSpace(left))
	rightHost, rightPort, rightErr := net.SplitHostPort(strings.TrimSpace(right))
	if leftErr != nil || rightErr != nil {
		return strings.TrimSpace(left) == strings.TrimSpace(right)
	}
	return leftPort == rightPort && normalizeOverviewListenHost(leftHost) == normalizeOverviewListenHost(rightHost)
}

func normalizeOverviewListenHost(host string) string {
	host = strings.Trim(host, "[] ")
	if host == "" || host == "0.0.0.0" || host == "::" {
		return ""
	}
	return host
}
