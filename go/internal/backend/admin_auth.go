package backend

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/pbkdf2"
)

const adminSessionCookieBaseName = "dsmpass_admin"
const adminSessionTTL = 12 * time.Hour
const adminPasswordPBKDF2Iterations = 210000

type adminJWTClaims struct {
	Username string `json:"sub"`
	Expires  int64  `json:"exp"`
	IssuedAt int64  `json:"iat"`
}

func (s *Server) adminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.authorizeAdminRequest(c) {
			c.Next()
			return
		}
	}
}

func (s *Server) adminAuthStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"authenticated":  !s.cfg.AdminAuthEnabled || s.validAdminSession(c),
		"username":       s.cfg.AdminUsername,
		"enabled":        s.cfg.AdminAuthEnabled,
		"setup_required": s.cfg.AdminAuthEnabled && s.cfg.AdminSetupRequired,
	})
}

func (s *Server) adminSetup(c *gin.Context) {
	if !s.cfg.AdminAuthEnabled {
		c.JSON(http.StatusOK, gin.H{"authenticated": true, "username": s.cfg.AdminUsername, "setup_required": false})
		return
	}
	s.adminMu.Lock()
	setupRequired := s.cfg.AdminSetupRequired || s.cfg.AdminPassword == ""
	s.adminMu.Unlock()
	if !setupRequired {
		c.JSON(http.StatusConflict, gin.H{"detail": "already initialized"})
		return
	}
	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "invalid json"})
		return
	}
	username := strings.TrimSpace(payload.Username)
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "invalid username"})
		return
	}
	if strings.TrimSpace(payload.Password) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "invalid password"})
		return
	}
	passwordHash, err := hashAdminPassword(payload.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	if err := s.saveSetting(c.Request.Context(), "admin_username", username); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	if err := s.saveSetting(c.Request.Context(), "admin_password_hash", passwordHash); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	s.adminMu.Lock()
	s.cfg.AdminUsername = username
	s.cfg.AdminPassword = passwordHash
	s.cfg.AdminSetupRequired = false
	s.adminMu.Unlock()
	token, expires, err := s.issueAdminJWT()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	s.setAdminSessionCookie(c, token, int(time.Until(expires).Seconds()))
	c.JSON(http.StatusOK, gin.H{"authenticated": true, "username": username, "setup_required": false})
}

func (s *Server) adminLogin(c *gin.Context) {
	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "invalid json"})
		return
	}
	if !s.cfg.AdminAuthEnabled {
		c.JSON(http.StatusOK, gin.H{"authenticated": true, "username": s.cfg.AdminUsername})
		return
	}
	if s.cfg.AdminSetupRequired || s.cfg.AdminPassword == "" {
		c.JSON(http.StatusPreconditionRequired, gin.H{"detail": "setup required"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(payload.Username), []byte(s.cfg.AdminUsername)) != 1 ||
		!s.verifyAdminPassword(payload.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "unauthorized"})
		return
	}
	token, expires, err := s.issueAdminJWT()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	s.setAdminSessionCookie(c, token, int(time.Until(expires).Seconds()))
	c.JSON(http.StatusOK, gin.H{"authenticated": true, "username": s.cfg.AdminUsername})
}

func (s *Server) adminLogout(c *gin.Context) {
	s.setAdminSessionCookie(c, "", -1)
	c.JSON(http.StatusOK, gin.H{"authenticated": false})
}

func (s *Server) adminChangePassword(c *gin.Context) {
	var payload struct {
		Username        string `json:"username"`
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := c.BindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "invalid json"})
		return
	}
	if !s.verifyAdminPassword(payload.CurrentPassword) {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "unauthorized"})
		return
	}
	username := strings.TrimSpace(payload.Username)
	if username == "" {
		username = s.cfg.AdminUsername
	}
	if strings.TrimSpace(payload.NewPassword) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "invalid new_password"})
		return
	}
	passwordHash, err := hashAdminPassword(payload.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	if err := s.saveSetting(c.Request.Context(), "admin_username", username); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	if err := s.saveSetting(c.Request.Context(), "admin_password_hash", passwordHash); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	s.adminMu.Lock()
	s.cfg.AdminUsername = username
	s.cfg.AdminPassword = passwordHash
	s.adminMu.Unlock()
	s.setAdminSessionCookie(c, "", -1)
	c.JSON(http.StatusOK, gin.H{"success": true, "username": username})
}

func (s *Server) authorizeAdminRequest(c *gin.Context) bool {
	if !s.cfg.AdminAuthEnabled {
		return true
	}
	if s.cfg.AdminSetupRequired || s.cfg.AdminPassword == "" {
		c.AbortWithStatusJSON(http.StatusPreconditionRequired, gin.H{"detail": "setup required"})
		return false
	}
	if s.validAdminSession(c) {
		return true
	}
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "unauthorized"})
	return false
}

func (s *Server) validAdminSession(c *gin.Context) bool {
	token, err := c.Cookie(s.adminSessionCookieName())
	if err != nil || token == "" {
		return false
	}
	claims, ok := s.verifyAdminJWT(token)
	if !ok {
		return false
	}
	return claims.Username == s.cfg.AdminUsername
}

func (s *Server) issueAdminJWT() (string, time.Time, error) {
	now := time.Now()
	expires := now.Add(adminSessionTTL)
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	claims := adminJWTClaims{Username: s.cfg.AdminUsername, IssuedAt: now.Unix(), Expires: expires.Unix()}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", time.Time{}, err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	signature := signAdminJWT(unsigned, s.adminJWTSecret())
	return unsigned + "." + signature, expires, nil
}

func (s *Server) adminSessionCookieName() string {
	port := listenAddressPort(s.AdminListenAddress())
	if port == "" {
		return adminSessionCookieBaseName
	}
	return adminSessionCookieBaseName + "_" + port
}

func (s *Server) setAdminSessionCookie(c *gin.Context, value string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     s.adminSessionCookieName(),
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   s.cfg.TLSEnabled,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) verifyAdminJWT(token string) (adminJWTClaims, bool) {
	var claims adminJWTClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims, false
	}
	unsigned := parts[0] + "." + parts[1]
	expected := signAdminJWT(unsigned, s.adminJWTSecret())
	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(expected)) != 1 {
		return claims, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, false
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, false
	}
	if claims.Expires <= time.Now().Unix() {
		return claims, false
	}
	return claims, true
}

func (s *Server) adminJWTSecret() []byte {
	if s.cfg.AdminJWTSecret != "" {
		return []byte(s.cfg.AdminJWTSecret)
	}
	hash := sha256.Sum256([]byte(s.cfg.AdminUsername + "\x00" + s.cfg.AdminPassword + "\x00" + s.cfg.DataDir))
	return hash[:]
}

func signAdminJWT(unsigned string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(unsigned))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Server) verifyAdminPassword(password string) bool {
	stored := s.cfg.AdminPassword
	if strings.HasPrefix(stored, "pbkdf2-sha256:") {
		return verifyAdminPasswordPBKDF2(password, stored)
	}
	if strings.HasPrefix(stored, "sha256:") {
		return verifyAdminPasswordSHA256(password, stored)
	}
	return subtle.ConstantTimeCompare([]byte(password), []byte(stored)) == 1
}

func hashAdminPassword(password string) (string, error) {
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return "", err
	}
	salt := hex.EncodeToString(saltBytes)
	key := pbkdf2.Key([]byte(password), []byte(salt), adminPasswordPBKDF2Iterations, 32, sha256.New)
	return "pbkdf2-sha256:" + strconv.Itoa(adminPasswordPBKDF2Iterations) + ":" + salt + ":" + hex.EncodeToString(key), nil
}

func verifyAdminPasswordPBKDF2(password, stored string) bool {
	parts := strings.Split(stored, ":")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" || parts[1] == "" || parts[2] == "" || parts[3] == "" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations <= 0 {
		return false
	}
	expected, err := hex.DecodeString(parts[3])
	if err != nil || len(expected) == 0 {
		return false
	}
	key := pbkdf2.Key([]byte(password), []byte(parts[2]), iterations, len(expected), sha256.New)
	return subtle.ConstantTimeCompare(key, expected) == 1
}

func verifyAdminPasswordSHA256(password, stored string) bool {
	parts := strings.Split(stored, ":")
	if len(parts) != 3 || parts[0] != "sha256" || parts[1] == "" || parts[2] == "" {
		return false
	}
	hash := sha256.Sum256([]byte(parts[1] + "\x00" + password))
	expected := hex.EncodeToString(hash[:])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(parts[2])) == 1
}

func (s *Server) refreshAdminSetupState() {
	if !s.cfg.AdminAuthEnabled {
		s.cfg.AdminSetupRequired = false
		return
	}
	s.cfg.AdminSetupRequired = s.cfg.AdminPassword == ""
}
