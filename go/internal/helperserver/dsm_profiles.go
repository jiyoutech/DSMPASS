package helperserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
)

// Only fresh directory reads can acknowledge an unchanged, fully managed local
// account. Rows needing an update or an ownership decision use provisionAccount.
func (s *Server) unchangedAccounts(ctx context.Context, cfg config.HelperConfig, rows []map[string]any) map[string]bool {
	if cfg.SynoWebAPIPath == "" || cfg.AccountPolicyPath == "" || cfg.GroupPath == "" || cfg.PasswdPath == "" || len(rows) < 2 {
		return nil
	}
	scan, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	before, err := readDirectoryStamp(cfg)
	if err != nil {
		return nil
	}
	users, err := systemAccounts(cfg.PasswdPath, false)
	if err != nil {
		return nil
	}
	candidates := make(map[string]map[string]any)
	for _, row := range rows {
		name := row["dsm_username"].(string)
		if _, exists := users[name]; exists && assertAllowed(cfg, name) == nil {
			candidates[name] = row
		}
	}
	if len(candidates) < 2 {
		return nil
	}
	eligible, err := readMatchingProfiles(scan, cfg.SynoWebAPIPath, users, candidates)
	if err != nil || len(eligible) == 0 {
		return nil
	}
	confirmed := make(map[string]bool)
	err = withFileLockContext(scan, cfg.ShadowLockPath, func() error {
		current, err := readDirectoryStamp(cfg)
		if err != nil || !before.matches(current) {
			return err
		}
		groups, err := systemAccounts(cfg.GroupPath, true)
		if err != nil {
			return err
		}
		policy, err := readAccountPolicy(cfg)
		if err != nil {
			return err
		}
		ok, err := s.mappingAllowed(cfg, db.HelperAuthorizationQuery{Action: "provision_users", Usernames: eligible})
		if err != nil || !ok {
			return err
		}
		for _, name := range eligible {
			if s.canConfirmDirectoryUser(cfg, policy, name, users, groups) {
				confirmed[name] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil
	}
	return confirmed
}

type dsmUserProfile struct {
	Name        string  `json:"name"`
	UID         *int    `json:"uid"`
	Description *string `json:"description"`
	Email       *string `json:"email"`
	Expired     string  `json:"expired"`
}

func (p dsmUserProfile) matches(local systemAccount, row map[string]any) bool {
	if p.UID == nil || *p.UID != local.id || p.Expired != "normal" || p.Email == nil || p.Description == nil || *p.Description != local.description {
		return false
	}
	name, email := row["display_name"].(string), row["email"].(string)
	return (name == "" || name == *p.Description) && (email == "" || email == *p.Email)
}

type dsmProfilePage struct {
	Offset *int             `json:"offset"`
	Total  *int             `json:"total"`
	Users  []dsmUserProfile `json:"users"`
}

func readDSMProfilePage(ctx context.Context, path string, offset int) (dsmProfilePage, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var reply struct {
		Success bool           `json:"success"`
		Data    dsmProfilePage `json:"data"`
		Error   struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	cmd := exec.CommandContext(ctx, path, "--exec", "api=SYNO.Core.User", "method=list", "version=1", `type="local"`, "offset="+strconv.Itoa(offset), "limit="+strconv.Itoa(helperclient.UserProvisionBatchSize), `additional=["uid","description","email","expired"]`)
	cmd.WaitDelay = time.Second
	data, err := cmd.Output()
	if err != nil {
		return dsmProfilePage{}, err
	}
	if err := json.Unmarshal(data, &reply); err != nil {
		return dsmProfilePage{}, err
	}
	if !reply.Success {
		return dsmProfilePage{}, fmt.Errorf("DSM user list error %d", reply.Error.Code)
	}
	return reply.Data, nil
}

func readMatchingProfiles(ctx context.Context, path string, users map[string]systemAccount, candidates map[string]map[string]any) ([]string, error) {
	var eligible []string
	seen := map[string]bool{}
	for offset := 0; offset < len(users) && len(seen) < len(candidates); {
		page, err := readDSMProfilePage(ctx, path, offset)
		if err != nil {
			return nil, err
		}
		if page.Offset == nil || *page.Offset != offset || page.Total == nil || *page.Total > len(users) || len(page.Users) == 0 || len(page.Users) > helperclient.UserProvisionBatchSize || offset+len(page.Users) > *page.Total {
			return nil, nil
		}
		for _, p := range page.Users {
			row, wanted := candidates[p.Name]
			if !wanted {
				continue
			}
			if seen[p.Name] {
				return nil, nil
			}
			seen[p.Name] = true
			if p.matches(users[p.Name], row) {
				eligible = append(eligible, p.Name)
			}
		}
		offset += len(page.Users)
		if offset == *page.Total {
			break
		}
	}
	return eligible, nil
}
