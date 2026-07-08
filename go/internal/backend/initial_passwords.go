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

	"github.com/dsmpass/dsmpass/go/internal/db"
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
	if err := s.ensureSourceInitialPassword(ctx, s.store.DBTX(), sourceSlug); err != nil {
		return "", err
	}
	password, ok, err := s.lookupSourceInitialPassword(ctx, sourceSlug)
	if err != nil {
		return password, err
	}
	if !ok {
		return "", errors.New("initial password was not stored")
	}
	return password, nil
}

func (s *Server) ensureSourceInitialPassword(ctx context.Context, q db.DBTX, sourceSlug string) error {
	sourceSlug = strings.TrimSpace(sourceSlug)
	if sourceSlug == "" {
		return errors.New("identity source is required for initial password")
	}
	var id string
	err := q.QueryRowContext(ctx, `SELECT id FROM source_initial_password_secrets WHERE source_slug = ?`, sourceSlug).Scan(&id)
	if err == nil {
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	return s.createSourceInitialPasswordWithDB(ctx, q, sourceSlug, generatedInitialPassword())
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

func (s *Server) createSourceInitialPasswordWithDB(ctx context.Context, q db.DBTX, sourceSlug, password string) error {
	sourceSlug = strings.TrimSpace(sourceSlug)
	password = strings.TrimSpace(password)
	if sourceSlug == "" || password == "" {
		return errors.New("initial password metadata is incomplete")
	}
	encrypted, err := s.encryptInitialPassword(sourceSlug, password)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `
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

func (s *Server) sourceInitialPasswordStatus(ctx context.Context, sourceSlug string) (gin.H, error) {
	var revealCount int64
	var lastRevealedAt, createdAt, updatedAt sql.NullString
	err := s.store.DBTX().QueryRowContext(ctx, `
SELECT reveal_count, last_revealed_at, created_at, updated_at
FROM source_initial_password_secrets
WHERE source_slug = ?`, sourceSlug).Scan(&revealCount, &lastRevealedAt, &createdAt, &updatedAt)
	if err == sql.ErrNoRows || isMissingSourceInitialPasswordTable(err) {
		return gin.H{"configured": false}, nil
	}
	if err != nil {
		return nil, err
	}
	return gin.H{
		"configured":       true,
		"reveal_count":     revealCount,
		"last_revealed_at": nullableString(lastRevealedAt),
		"created_at":       nullableString(createdAt),
		"updated_at":       nullableString(updatedAt),
	}, nil
}

func isMissingSourceInitialPasswordTable(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no such table: source_initial_password_secrets")
}

func (s *Server) revealProviderInitialPassword(c *gin.Context) {
	source, err := s.loadIdentitySource(c.Request.Context(), c.Param("slug"))
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"detail": "identity source not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	if err := s.ensureSourceInitialPassword(c.Request.Context(), s.store.DBTX(), source.Slug); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	var encrypted string
	err = s.store.DBTX().QueryRowContext(c.Request.Context(), `
SELECT encrypted_password
FROM source_initial_password_secrets
WHERE source_slug = ?`, source.Slug).Scan(&encrypted)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"detail": "initial password not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	password, err := s.decryptInitialPassword(source.Slug, encrypted)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "initial password cannot be decrypted"})
		return
	}
	_, _ = s.store.DBTX().ExecContext(c.Request.Context(), `
UPDATE source_initial_password_secrets
SET reveal_count = reveal_count + 1, last_revealed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
WHERE source_slug = ?`, source.Slug)
	status, err := s.sourceInitialPasswordStatus(c.Request.Context(), source.Slug)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"source_slug":         source.Slug,
		"source_display_name": source.DisplayName,
		"status":              status,
		"initial_password":    password,
	})
}
