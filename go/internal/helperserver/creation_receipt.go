package helperserver

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/securefs"
)

// All methods run under the existing writer lock. A receipt is independent of
// the grants file so a failed grant write can be retried after a restart.
type creationTarget struct {
	cfg   config.HelperConfig
	name  string
	group bool
}

func (t creationTarget) path() string {
	kind := "user"
	if t.group {
		kind = "group"
	}
	return fmt.Sprintf("%s.pending-%s-%x", t.cfg.AccountPolicyPath, kind, sha256.Sum256([]byte(t.name)))
}

func (t creationTarget) account() (systemAccount, error) {
	if t.group {
		return normalGroup(t.cfg, t.name)
	}
	return normalUser(t.cfg, t.name)
}

func (t creationTarget) write(id int) error {
	data := []byte(strconv.Itoa(id))
	if t.cfg.Privileged {
		return securefs.WriteRootFile(t.path(), data, 0600)
	}
	return os.WriteFile(t.path(), data, 0600)
}
func (t creationTarget) begin() error {
	if t.cfg.AccountPolicyPath == "" && !t.cfg.Privileged {
		return nil
	}
	if !t.group {
		// A previous attempt may already have changed DSM. Only its original
		// owner may clear a confirmed failure or finish registering its UID.
		if _, found, err := t.receiptID(); err != nil {
			return err
		} else if found {
			return fmt.Errorf("DSM 用户 %q 有待核实的创建回执", t.name)
		}
	}
	return t.write(-1)
}
func (t creationTarget) clear() error {
	if t.cfg.AccountPolicyPath == "" && !t.cfg.Privileged {
		return nil
	}
	err := os.Remove(t.path())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (t creationTarget) confirm() error {
	_, err := t.confirmID()
	return err
}

func (t creationTarget) confirmID() (int, error) {
	if t.cfg.AccountPolicyPath == "" && !t.cfg.Privileged {
		return 0, nil
	}
	a, err := t.account()
	if err != nil {
		return 0, fmt.Errorf("DSM 已创建 %q，读取系统编号失败: %w", t.name, err)
	}
	if err = t.write(a.id); err != nil {
		return 0, fmt.Errorf("DSM 已创建 %q，保存系统编号失败: %w", t.name, err)
	}
	return a.id, t.resume()
}

func (t creationTarget) resume() error {
	if t.cfg.AccountPolicyPath == "" && !t.cfg.Privileged {
		return nil
	}
	id, found, err := t.receiptID()
	if err != nil || !found {
		return err
	}
	a, err := t.account()
	if err != nil {
		return err
	}
	if a.id != id {
		return fmt.Errorf("DSM 对象 %q 的系统编号已改变，请管理员核实后授权", t.name)
	}
	p, err := readAccountPolicy(t.cfg)
	if err != nil {
		return err
	}
	entries := p.Users
	if _, limited := p.DirectoryUsers[t.name]; !t.group && limited {
		return fmt.Errorf("DSM 用户 %q 已登记为通讯录同步账号，请核实创建凭据", t.name)
	}
	if previous, exists := entries[t.name]; !t.group && exists && previous != id {
		return fmt.Errorf("DSM 用户 %q 的创建凭据与当前授权记录不符", t.name)
	}
	if t.group {
		entries = p.Groups
	}
	entries[t.name] = id
	if err := saveAccountPolicy(t.cfg, p); err != nil {
		return fmt.Errorf("DSM 已创建 %q，保存授权失败，可重试同步: %w", t.name, err)
	}
	return t.clear()
}

func (t creationTarget) receiptID() (int, bool, error) {
	path := t.path()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return 0, false, errors.New("invalid creation receipt permissions")
	}
	if t.cfg.Privileged {
		if err := securefs.CheckRootPath(path); err != nil {
			return 0, false, err
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false, err
	}
	id, err := strconv.Atoi(string(raw))
	if err != nil || id < 0 {
		return 0, false, fmt.Errorf("DSM 对象 %q 创建结果待核实，请管理员确认名称与系统编号后授权", t.name)
	}
	return id, true, nil
}
