package helperserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

type groupWebApproval struct {
	GID       int    `json:"gid"`
	Code      string `json:"code"`
	ExpiresAt int64  `json:"expires_at"`
}

// The code is public. Only an actor able to edit this exact group in DSM can
// place it in the DSM-owned description. The package RPC supplies no evidence.
func (s *Server) webGroupApproval(cfg config.HelperConfig, payload map[string]any) map[string]any {
	name, err := requiredString(payload, "dsm_groupname")
	verify, ok := payload["verify"].(bool)
	if err != nil || !ok || cfg.AccountPolicyPath == "" {
		return errorResponse("BAD_REQUEST", "群组授权请求无效")
	}
	response := map[string]any{"success": true, "groupname": name}
	err = withFileLock(cfg.ShadowLockPath, func() error {
		group, err := normalGroup(cfg, name)
		if err != nil {
			return err
		}
		if !isLocalDirectoryGroup(name, group.id) {
			return errors.New("网页授权仅适用于普通 DSM 本地群组")
		}
		mapped, err := s.mappingAllowed(cfg, db.HelperAuthorizationQuery{Action: "directory_group", Groupname: name})
		if err != nil {
			return err
		}
		if !mapped {
			return errors.New("当前群组没有有效的通讯录部门映射")
		}
		p, err := readAccountPolicy(cfg)
		if err != nil {
			return err
		}
		response["gid"] = group.id
		creation := creationTarget{cfg: cfg, name: name, group: true}
		_, receiptErr := os.Lstat(creation.path())
		if receiptErr != nil && !errors.Is(receiptErr, os.ErrNotExist) {
			return receiptErr
		}
		if errors.Is(receiptErr, os.ErrNotExist) {
			if p.Groups[name] == group.id {
				response["approved"] = true
				return nil
			}
			if _, enrolled := p.Groups[name]; !enrolled && p.ReusableGroups[name] == group.id {
				if err := checkGroupEnrollment(cfg, name, func() (bool, error) { return true, nil }); err != nil {
					return err
				}
				response["approved"] = true
				return nil
			}
		}
		now := time.Now()
		ticket := p.WebApprovals[name]
		valid := ticket.GID == group.id && ticket.Code != "" && ticket.ExpiresAt > now.Unix()
		if verify {
			if err := acceptDSMGroupApproval(cfg, p, group); err != nil {
				return err
			}
			response["approved"] = true
			return nil
		}
		if !valid {
			if p.WebApprovals == nil {
				p.WebApprovals = make(map[string]groupWebApproval)
			}
			for key, pending := range p.WebApprovals {
				if pending.ExpiresAt <= now.Unix() {
					delete(p.WebApprovals, key)
				}
			}
			if _, exists := p.WebApprovals[name]; !exists && len(p.WebApprovals) >= 256 {
				return errors.New("待确认群组较多，请先完成现有授权")
			}
			var nonce [12]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return err
			}
			ticket = groupWebApproval{GID: group.id, Code: "DP-" + hex.EncodeToString(nonce[:]), ExpiresAt: now.Add(15 * time.Minute).Unix()}
			p.WebApprovals[name] = ticket
			if err := saveAccountPolicy(cfg, p); err != nil {
				return err
			}
		}
		response["code"], response["expires_at"] = ticket.Code, time.Unix(ticket.ExpiresAt, 0).UTC().Format(time.RFC3339)
		response["approved"] = false
		return nil
	})
	if err != nil {
		return errorResponse("GROUP_APPROVAL_FAILED", err.Error())
	}
	return response
}

// The caller has verified the active mapping and holds the Helper writer lock.
func acceptDSMGroupApproval(cfg config.HelperConfig, p accountPolicy, group systemAccount) error {
	name := group.name
	ticket := p.WebApprovals[name]
	if !isLocalDirectoryGroup(name, group.id) || ticket.GID != group.id || ticket.Code == "" || time.Now().Unix() >= ticket.ExpiresAt {
		return errors.New("授权码已失效或群组编号已改变，请在网页重新获取授权码")
	}
	if err := verifyDSMGroupDescription(cfg, name, ticket); err != nil {
		return err
	}
	current, err := normalGroup(cfg, name)
	if err != nil {
		return err
	}
	if current.id != ticket.GID || time.Now().Unix() >= ticket.ExpiresAt {
		return errors.New("授权码过期或验证期间群组编号已改变，请在网页重新获取授权码")
	}
	if err := (creationTarget{cfg: cfg, name: name, group: true}).clear(); err != nil {
		return err
	}
	p.Groups[name] = ticket.GID
	delete(p.ReusableGroups, name)
	delete(p.WebApprovals, name)
	if err := saveAccountPolicy(cfg, p); err != nil {
		return err
	}
	log.Printf("directory group approved via DSM: group=%q gid=%d", name, ticket.GID)
	return nil
}

func verifyDSMGroupDescription(cfg config.HelperConfig, name string, ticket groupWebApproval) error {
	if cfg.SynoWebAPIPath == "" {
		return errors.New("DSM 群组查询不可用")
	}
	arg, err := json.Marshal(name)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, cfg.SynoWebAPIPath, "--exec", "api=SYNO.Core.Group", "method=get", "version=1", "name="+string(arg))
	var out limitedAuthorizationOutput
	cmd.Stdout = struct{ io.Writer }{&out}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("DSM 群组查询失败: %w", err)
	}
	var result struct {
		Success bool `json:"success"`
		Data    struct {
			Groups []struct {
				Name        string `json:"name"`
				GID         int    `json:"gid"`
				Description string `json:"description"`
			} `json:"groups"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || !result.Success || len(result.Data.Groups) != 1 {
		return errors.New("DSM 未返回唯一的目标群组")
	}
	group := result.Data.Groups[0]
	if group.Name != name || group.GID != ticket.GID {
		return errors.New("DSM 返回的群组名称或编号不匹配")
	}
	for _, part := range strings.Fields(group.Description) {
		if part == ticket.Code {
			return nil
		}
	}
	return errors.New("尚未在该 DSM 群组描述中找到授权码，请用空格分开、保存后再验证")
}
