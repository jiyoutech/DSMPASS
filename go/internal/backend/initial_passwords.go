package backend

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const generatedInitialPasswordBytes = 16

func generatedInitialPassword() string {
	return randomHex(generatedInitialPasswordBytes)
}

func (s *Server) provisionUserInitialPassword(ctx context.Context, sourceSlug string) (string, error) {
	sourceSlug = strings.TrimSpace(sourceSlug)
	if sourceSlug == "" {
		return "", errors.New("identity source is required for initial password")
	}
	if password, ok, err := s.lookupSourceInitialPassword(ctx, sourceSlug); err != nil || ok {
		return password, err
	}
	password := generatedInitialPassword()
	if err := s.createSourceInitialPassword(ctx, sourceSlug, password); err != nil {
		return "", err
	}
	password, ok, err := s.lookupSourceInitialPassword(ctx, sourceSlug)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New("initial password was not stored")
	}
	return password, nil
}

func (s *Server) lookupSourceInitialPassword(ctx context.Context, sourceSlug string) (string, bool, error) {
	var encrypted string
	err := s.store.DBTX().QueryRowContext(ctx, `
SELECT encrypted_password
FROM source_initial_password_secrets
WHERE source_slug = ?`, sourceSlug).Scan(&encrypted)
	if err == nil {
		password, err := s.decryptInitialPassword(sourceSlug, encrypted)
		return password, true, err
	}
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return "", false, err
}

func (s *Server) createSourceInitialPassword(ctx context.Context, sourceSlug, password string) error {
	sourceSlug = strings.TrimSpace(sourceSlug)
	password = strings.TrimSpace(password)
	if sourceSlug == "" || password == "" {
		return errors.New("initial password metadata is incomplete")
	}
	encrypted, err := s.encryptInitialPassword(sourceSlug, password)
	if err != nil {
		return err
	}
	_, err = s.store.DBTX().ExecContext(ctx, `
INSERT OR IGNORE INTO source_initial_password_secrets (id, source_slug, encrypted_password, reveal_count, last_revealed_at, created_at, updated_at)
VALUES (?, ?, ?, 0, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
`, "pwd_"+randomHex(12), sourceSlug, encrypted)
	return err
}

func (s *Server) encryptInitialPassword(scope, password string) (string, error) {
	aead, err := s.initialPasswordAEAD()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aead.Seal(nil, nonce, []byte(password), []byte(scope))
	payload := append(nonce, ciphertext...)
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func (s *Server) decryptInitialPassword(scope, encrypted string) (string, error) {
	aead, err := s.initialPasswordAEAD()
	if err != nil {
		return "", err
	}
	payload, err := base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	nonceSize := aead.NonceSize()
	if len(payload) <= nonceSize {
		return "", errors.New("invalid encrypted initial password")
	}
	plaintext, err := aead.Open(nil, payload[:nonceSize], payload[nonceSize:], []byte(scope))
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (s *Server) initialPasswordAEAD() (cipher.AEAD, error) {
	material := append([]byte("dsmpass-initial-password-v1:"), s.adminJWTSecret()...)
	key := sha256.Sum256(material)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Server) initialPasswords(c *gin.Context) {
	provider := strings.TrimSpace(c.Query("provider"))
	paging := parsePagination(c)
	args := []any{}
	where := ""
	if provider != "" && provider != "all" {
		where = "WHERE p.source_slug = ?"
		args = append(args, provider)
	}
	countArgs := append([]any{}, args...)
	total, err := queryCount(c.Request.Context(), s.store, `SELECT COUNT(*) FROM source_initial_password_secrets p `+where, countArgs...)
	if err != nil {
		writeItems(c, nil, err)
		return
	}
	args = append(args, paging.Limit, paging.Offset)
	rows, err := queryJSON(c.Request.Context(), s.store, `
SELECT p.id,
       p.source_slug,
       COALESCE(s.display_name, p.source_slug) AS source_display_name,
       COALESCE(s.provider_type, '') AS provider_type,
       p.reveal_count,
       p.last_revealed_at,
       p.created_at,
       p.updated_at
FROM source_initial_password_secrets p
LEFT JOIN identity_sources s ON s.slug = p.source_slug
`+where+`
ORDER BY p.updated_at DESC
LIMIT ? OFFSET ?`, args...)
	writePagedItems(c, rows, total, paging, err)
}

func (s *Server) revealInitialPassword(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	var sourceSlug, sourceDisplayName, encrypted string
	err := s.store.DBTX().QueryRowContext(c.Request.Context(), `
SELECT p.source_slug, COALESCE(s.display_name, p.source_slug), p.encrypted_password
FROM source_initial_password_secrets p
LEFT JOIN identity_sources s ON s.slug = p.source_slug
WHERE p.id = ?`, id).Scan(&sourceSlug, &sourceDisplayName, &encrypted)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"detail": "initial password not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	password, err := s.decryptInitialPassword(sourceSlug, encrypted)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "initial password cannot be decrypted"})
		return
	}
	_, _ = s.store.DBTX().ExecContext(c.Request.Context(), `
UPDATE source_initial_password_secrets
SET reveal_count = reveal_count + 1, last_revealed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
WHERE id = ?`, id)
	c.JSON(http.StatusOK, gin.H{
		"id":                  id,
		"source_slug":         sourceSlug,
		"source_display_name": sourceDisplayName,
		"initial_password":    password,
	})
}
