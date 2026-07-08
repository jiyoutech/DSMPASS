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

func (s *Server) provisionUserInitialPassword(ctx context.Context, sourceSlug, accountID, username string) (string, bool, error) {
	var encrypted string
	err := s.store.DBTX().QueryRowContext(ctx, `
SELECT encrypted_password
FROM initial_password_secrets
WHERE dsm_account_id = ?`, accountID).Scan(&encrypted)
	if err == nil {
		password, err := s.decryptInitialPassword(accountID, encrypted)
		return password, false, err
	}
	if err != sql.ErrNoRows {
		return "", false, err
	}
	password := generatedInitialPassword()
	if err := s.storeInitialPassword(ctx, sourceSlug, accountID, username, password); err != nil {
		return "", false, err
	}
	return password, true, nil
}

func (s *Server) storeInitialPassword(ctx context.Context, sourceSlug, accountID, username, password string) error {
	sourceSlug = strings.TrimSpace(sourceSlug)
	accountID = strings.TrimSpace(accountID)
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	if sourceSlug == "" || accountID == "" || username == "" || password == "" {
		return errors.New("initial password metadata is incomplete")
	}
	encrypted, err := s.encryptInitialPassword(accountID, password)
	if err != nil {
		return err
	}
	_, err = s.store.DBTX().ExecContext(ctx, `
INSERT INTO initial_password_secrets (id, source_slug, dsm_account_id, dsm_username, encrypted_password, reveal_count, last_revealed_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, 0, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT(dsm_account_id) DO UPDATE SET
    source_slug = excluded.source_slug,
    dsm_username = excluded.dsm_username,
    encrypted_password = excluded.encrypted_password,
    reveal_count = 0,
    last_revealed_at = NULL,
    updated_at = CURRENT_TIMESTAMP
`, "pwd_"+randomHex(12), sourceSlug, accountID, username, encrypted)
	return err
}

func (s *Server) deleteInitialPassword(ctx context.Context, accountID string) {
	if strings.TrimSpace(accountID) == "" || s.store == nil {
		return
	}
	_, _ = s.store.DBTX().ExecContext(ctx, `DELETE FROM initial_password_secrets WHERE dsm_account_id = ?`, accountID)
}

func (s *Server) encryptInitialPassword(accountID, password string) (string, error) {
	aead, err := s.initialPasswordAEAD()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aead.Seal(nil, nonce, []byte(password), []byte(accountID))
	payload := append(nonce, ciphertext...)
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func (s *Server) decryptInitialPassword(accountID, encrypted string) (string, error) {
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
	plaintext, err := aead.Open(nil, payload[:nonceSize], payload[nonceSize:], []byte(accountID))
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
		where = "WHERE source_slug = ?"
		args = append(args, provider)
	}
	countArgs := append([]any{}, args...)
	total, err := queryCount(c.Request.Context(), s.store, `SELECT COUNT(*) FROM initial_password_secrets `+where, countArgs...)
	if err != nil {
		writeItems(c, nil, err)
		return
	}
	args = append(args, paging.Limit, paging.Offset)
	rows, err := queryJSON(c.Request.Context(), s.store, `
SELECT id, source_slug, dsm_account_id, dsm_username, reveal_count, last_revealed_at, created_at, updated_at
FROM initial_password_secrets
`+where+`
ORDER BY updated_at DESC
LIMIT ? OFFSET ?`, args...)
	writePagedItems(c, rows, total, paging, err)
}

func (s *Server) revealInitialPassword(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	var accountID, username, encrypted string
	err := s.store.DBTX().QueryRowContext(c.Request.Context(), `
SELECT dsm_account_id, dsm_username, encrypted_password
FROM initial_password_secrets
WHERE id = ?`, id).Scan(&accountID, &username, &encrypted)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"detail": "initial password not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	password, err := s.decryptInitialPassword(accountID, encrypted)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "initial password cannot be decrypted"})
		return
	}
	_, _ = s.store.DBTX().ExecContext(c.Request.Context(), `
UPDATE initial_password_secrets
SET reveal_count = reveal_count + 1, last_revealed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
WHERE id = ?`, id)
	c.JSON(http.StatusOK, gin.H{
		"id":               id,
		"dsm_account_id":   accountID,
		"dsm_username":     username,
		"initial_password": password,
	})
}
