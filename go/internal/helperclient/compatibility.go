package helperclient

import "fmt"

// Packaged releases require the same revision even when versions are equal.
func CheckCompatibility(health map[string]any, version, revision string) error {
	if version == "dev" {
		return nil
	}
	helperVersion, _ := health["version"].(string)
	helperRevision, _ := health["revision"].(string)
	if helperVersion != version || helperRevision != revision {
		return fmt.Errorf("Helper 与当前套件版本不匹配（套件 %s，Helper %s）；请点击“重启并检查 Helper”更新。首次迁移或自行编译的未签名套件需管理员运行 setup-helper-sudo.sh 一次", version, helperVersion)
	}
	return nil
}
