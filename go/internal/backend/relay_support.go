package backend

import (
	"html"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/diaglog"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
)

func (s *Server) writeDSMCookies(c *gin.Context, relayResult helperclient.RelayLoginResult) []helperclient.RelayCookie {
	written := make([]helperclient.RelayCookie, 0, len(relayResult.Cookies)+1)
	hasSessionCookie := false
	for _, cookie := range relayResult.Cookies {
		if cookie.Name == "" || cookie.Value == "" {
			continue
		}
		path := cookie.Path
		if path == "" {
			path = "/"
		}
		value := cookie.Value
		if cookie.Name == s.cfg.DSMCookieName {
			hasSessionCookie = true
			value = relayResult.SID
		}
		s.setDSMCookie(c, cookie.Name, value, cookie.MaxAge, path)
		written = append(written, helperclient.RelayCookie{
			Name:     cookie.Name,
			Value:    value,
			Path:     path,
			MaxAge:   cookie.MaxAge,
			HTTPOnly: s.cfg.DSMCookieHTTPOnly,
		})
	}
	if !hasSessionCookie {
		s.setDSMCookie(c, s.cfg.DSMCookieName, relayResult.SID, 0, "/")
		written = append(written, helperclient.RelayCookie{
			Name:     s.cfg.DSMCookieName,
			Value:    relayResult.SID,
			Path:     "/",
			HTTPOnly: s.cfg.DSMCookieHTTPOnly,
		})
	}
	return written
}

func renderBrowserDSMLoginPage(login helperclient.BrowserLoginResult, loginAPI, redirectURL, relaunchURL, completeURL, requestID string) string {
	redirectDelayMS := 1800
	if login.TTLSeconds > 1 {
		redirectDelayMS = (login.TTLSeconds * 1000) - 250
	}
	if redirectDelayMS < 1500 {
		redirectDelayMS = 1500
	}
	if redirectDelayMS > 3000 {
		redirectDelayMS = 3000
	}
	trustRetrySeconds := 30
	trustURL := browserTrustURL(loginAPI, redirectURL)
	return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>正在进入 DSM</title>
  <style>
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f6f8fb;color:#172033}
    main{width:min(520px,calc(100vw - 40px));background:#fff;border:1px solid #dce3ee;border-radius:8px;padding:24px;box-shadow:0 16px 40px rgba(26,43,73,.08)}
    h1{font-size:20px;margin:0 0 10px}
    p{font-size:14px;line-height:1.6;margin:8px 0;color:#526070}
    .actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}
    button,a.button{appearance:none;border:1px solid #1d6fdc;background:#1d6fdc;color:#fff;border-radius:6px;padding:9px 14px;font-size:14px;text-decoration:none;cursor:pointer}
    button.secondary,a.secondary{background:#fff;color:#1d6fdc}
    #trust{display:none}
  </style>
</head>
<body>
  <main id="loading">
    <h1>正在进入 DSM</h1>
    <p>正在检查 DSM 登录通道并完成登录。</p>
  </main>
  <main id="trust">
    <h1>需要先信任 DSM 证书</h1>
    <p>这台电脑还没有信任 DSM 的 HTTPS 证书。请先打开 DSM 证书页面，在浏览器里接受或信任证书，然后回到这里继续登录。</p>
    <p>如果已经信任过证书，可以直接继续。<span id="trust-countdown">` + strconv.Itoa(trustRetrySeconds) + `</span> 秒后会自动回到授权入口重新开始。</p>
    <div class="actions">
      <a class="button" href="` + html.EscapeString(trustURL) + `" target="_blank" rel="noopener">打开 DSM 证书页面</a>
      <button class="secondary" type="button" id="continue-login">已信任，继续登录</button>
      <a class="secondary button" href="` + html.EscapeString(relaunchURL) + `">重新授权</a>
    </div>
  </main>
  <iframe name="dsm_login_frame" style="display:none" title="DSM login"></iframe>
  <form id="dsm-login" method="post" target="dsm_login_frame" action="` + html.EscapeString(loginAPI) + `">
    <input type="hidden" name="api" value="SYNO.API.Auth">
    <input type="hidden" name="method" value="login">
    <input type="hidden" name="version" value="7">
    <input type="hidden" name="account" value="` + html.EscapeString(login.Username) + `">
    <input type="hidden" name="passwd" value="` + html.EscapeString(login.TempPassword) + `">
    <input type="hidden" name="session" value="webui">
  </form>
  <script>
    (function () {
      var form = document.getElementById("dsm-login");
      var frame = document.getElementsByName("dsm_login_frame")[0];
      var loading = document.getElementById("loading");
      var trust = document.getElementById("trust");
      var continueLogin = document.getElementById("continue-login");
      var countdown = document.getElementById("trust-countdown");
      var redirected = false;
      var submitted = false;
      var redirectURL = "` + html.EscapeString(redirectURL) + `";
      var loginAPI = "` + html.EscapeString(loginAPI) + `";
      var relaunchURL = "` + html.EscapeString(relaunchURL) + `";
      var completeURL = "` + html.EscapeString(completeURL) + `";
      var requestID = "` + html.EscapeString(requestID) + `";
      var trustRetrySeconds = ` + strconv.Itoa(trustRetrySeconds) + `;
      var trustTimer = null;
      var completed = false;

      function completeBrowserLogin() {
        if (completed || !completeURL || !requestID) return;
        completed = true;
        var body = JSON.stringify({ request_id: requestID });
        if (navigator.sendBeacon) {
          try {
            var blob = new Blob([body], { type: "application/json" });
            if (navigator.sendBeacon(completeURL, blob)) return;
          } catch (err) {}
        }
        if (window.fetch) {
          fetch(completeURL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: body,
            credentials: "same-origin",
            keepalive: true
          }).catch(function () {});
        }
      }

      function go(delay) {
        if (redirected) return;
        redirected = true;
        setTimeout(function () {
          window.location.replace(redirectURL);
        }, delay);
      }

      frame.addEventListener("load", function () {
        if (submitted) {
          completeBrowserLogin();
          go(250);
        }
      });

      function submitLogin() {
        if (trustTimer) {
          clearInterval(trustTimer);
          trustTimer = null;
        }
        loading.style.display = "block";
        trust.style.display = "none";
        submitted = true;
        form.submit();
        setTimeout(function () {
          if (!redirected) {
            form.submit();
          }
        }, 650);
        setTimeout(function () {
          go(0);
        }, ` + strconv.Itoa(redirectDelayMS) + `);
      }

      function showTrust() {
        loading.style.display = "none";
        trust.style.display = "block";
        if (trustTimer) return;
        if (countdown) countdown.textContent = String(trustRetrySeconds);
        trustTimer = setInterval(function () {
          trustRetrySeconds -= 1;
          if (countdown) countdown.textContent = String(Math.max(trustRetrySeconds, 0));
          if (trustRetrySeconds <= 0) {
            clearInterval(trustTimer);
            window.location.replace(relaunchURL);
          }
        }, 1000);
      }

      continueLogin.addEventListener("click", submitLogin);

      if (window.fetch && loginAPI.indexOf("https://") === 0) {
        fetch(loginAPI + "?api=SYNO.API.Info&version=1&method=query&query=SYNO.API.Auth&_=" + Date.now(), {
          method: "GET",
          mode: "no-cors",
          cache: "no-store",
          credentials: "include"
        }).then(submitLogin).catch(showTrust);
      } else {
        submitLogin();
      }
    })();
  </script>
</body>
</html>`
}

func renderLaunchLogoutPage(authorizeURL, logoutURL string) string {
	return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>正在授权</title>
  <style>
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f6f8fb;color:#172033}
    main{width:min(480px,calc(100vw - 40px));background:#fff;border:1px solid #dce3ee;border-radius:8px;padding:24px;box-shadow:0 16px 40px rgba(26,43,73,.08)}
    h1{font-size:20px;margin:0 0 10px}
    p{font-size:14px;line-height:1.6;margin:8px 0;color:#526070}
  </style>
</head>
<body>
  <main>
    <h1>正在授权</h1>
    <p>正在进入身份源授权。</p>
  </main>
  <script>
    (function () {
      var authorizeURL = ` + strconv.Quote(authorizeURL) + `;
      var logoutURL = ` + strconv.Quote(logoutURL) + `;
      var logoutDelayMS = 2000;
      var redirected = false;
      function go() {
        if (redirected) return;
        redirected = true;
        window.location.replace(authorizeURL);
      }
      function finishLogout() {
        if (redirected) return;
        setTimeout(go, logoutDelayMS);
      }
      if (!logoutURL || !window.fetch) {
        finishLogout();
        return;
      }
      fetch(logoutURL, {
        method: "GET",
        mode: "no-cors",
        cache: "no-store",
        credentials: "include"
      }).then(finishLogout).catch(finishLogout);
      setTimeout(finishLogout, logoutDelayMS);
    })();
  </script>
</body>
</html>`
}

func dsmLogoutURL(loginAPI string) string {
	parsed, err := url.Parse(loginAPI)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	values := url.Values{}
	values.Set("api", "SYNO.API.Auth")
	values.Set("method", "logout")
	values.Set("version", "7")
	values.Set("session", "webui")
	parsed.RawQuery = values.Encode()
	parsed.Fragment = ""
	return parsed.String()
}

func browserTrustURL(loginAPI, redirectURL string) string {
	for _, raw := range []string{loginAPI, redirectURL} {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		parsed.Path = "/"
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return parsed.String()
	}
	return redirectURL
}

func (s *Server) setDSMCookie(c *gin.Context, name, value string, maxAge int, path string) {
	if path == "" {
		path = "/"
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   maxAge,
		Secure:   s.cfg.DSMCookieSecure,
		HttpOnly: s.cfg.DSMCookieHTTPOnly,
		SameSite: sameSiteMode(s.cfg.DSMCookieSameSite),
	})
}

func (s *Server) clearDSMCookie(c *gin.Context) {
	s.setDSMCookie(c, s.cfg.DSMCookieName, "", -1, "/")
}

func sameSiteMode(value string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	case "lax", "":
		return http.SameSiteLaxMode
	default:
		return http.SameSiteLaxMode
	}
}

type relayFailure struct {
	Status            int
	Detail            string
	ErrorCode         string
	ExternalAccountID string
	AppIdentityID     string
	DSMUsername       string
	EventName         string
	Event             diaglog.Event
}

func (s *Server) validateCallbackState(c *gin.Context, source db.IdentitySource, requestID string, start time.Time) bool {
	state := c.Query("state")
	if state == "" {
		s.failRelayCallback(c, source, requestID, start, relayFailure{
			Status:    http.StatusBadRequest,
			Detail:    "缺少状态参数：请从身份源 Launch 地址重新发起登录。",
			ErrorCode: "missing_state",
			EventName: "backend.callback.state.missing",
			Event: diaglog.Event{
				"source_slug": source.Slug,
			},
		})
		return false
	}
	entry, ok := s.consumeOAuthState(state, source.Slug, c.Request)
	if !ok {
		s.failRelayCallback(c, source, requestID, start, relayFailure{
			Status:    http.StatusBadRequest,
			Detail:    "登录状态无效或浏览器不匹配：请在发起登录的同一浏览器完成授权，或重新从身份源登录入口发起登录。",
			ErrorCode: "invalid_state",
			EventName: "backend.callback.state.invalid",
			Event: diaglog.Event{
				"state":          state,
				"state_found":    entry.CookieName != "",
				"state_provider": entry.ProviderSlug,
				"state_expired":  entry.CookieName != "" && time.Now().After(entry.ExpiresAt),
				"source_slug":    source.Slug,
			},
		})
		return false
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: entry.CookieName, Value: "", Path: "/", HttpOnly: true, Secure: strings.HasPrefix(entry.CookieName, "__Host-"), SameSite: http.SameSiteLaxMode, MaxAge: -1})
	diaglog.Append(s.cfg.DataDir, requestID, "backend.callback.state.valid", s.cfg.LoginDiagnosticsEnabled, diaglog.Event{
		"state":          state,
		"state_provider": entry.ProviderSlug,
		"source_slug":    source.Slug,
	})
	return true
}

func (s *Server) failRelayCallback(c *gin.Context, source db.IdentitySource, requestID string, start time.Time, failure relayFailure) {
	if failure.EventName != "" {
		diaglog.Append(s.cfg.DataDir, requestID, failure.EventName, s.cfg.LoginDiagnosticsEnabled, failure.Event)
	}
	s.logLoginAudit(c.Request.Context(), loginAuditEvent{
		RequestID:         requestID,
		Provider:          source.Slug,
		ExternalAccountID: failure.ExternalAccountID,
		AppIdentityID:     failure.AppIdentityID,
		DSMUsername:       failure.DSMUsername,
		Result:            "failed",
		ErrorCode:         failure.ErrorCode,
		IPAddress:         requestClientIP(c),
		DurationMs:        time.Since(start).Milliseconds(),
	})
	if failure.ErrorCode == "invalid_state" || failure.ErrorCode == "missing_state" {
		// Restart with a fresh browser-bound flow. Never forward the old code,
		// state, callback URL or identity into the new browser's authorization.
		restartURL := "/idp/" + url.PathEscape(source.Slug) + "/launch"
		if strings.Contains(c.GetHeader("Accept"), "text/html") {
			c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
			c.Data(failure.Status, "text/html; charset=utf-8", []byte(renderOAuthRestartPage(restartURL)))
		} else {
			c.JSON(failure.Status, gin.H{"detail": failure.Detail, "restart_url": restartURL})
		}
		return
	}
	c.JSON(failure.Status, gin.H{"detail": failure.Detail})
}

func renderOAuthRestartPage(restartURL string) string {
	return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>重新开始登录</title>
<style>body{font-family:system-ui,sans-serif;background:#f6f8fb;color:#172033;margin:0;min-height:100vh;display:grid;place-items:center}main{max-width:480px;margin:20px;padding:28px;background:white;border:1px solid #dce3ee;border-radius:10px}h1{font-size:22px}p{line-height:1.7;color:#526070}a{display:inline-block;padding:12px 18px;border-radius:6px;background:#1d6fdc;color:white;text-decoration:none}</style></head>
<body><main><h1>请在当前浏览器重新登录</h1><p>登录已过期，或授权过程中切换了浏览器。点击下方按钮，重新验证你自己的账号。</p><p>如果需要从飞书、企业微信或钉钉内置浏览器切换到系统浏览器，请先在系统浏览器打开登录入口，再完成授权。请勿复制授权完成后的回调地址。</p><a href="` + html.EscapeString(restartURL) + `">在当前浏览器重新登录</a></main></body></html>`
}

func firstProfileString(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := raw[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}
