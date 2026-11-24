package helperclient

import "fmt"

// Packaged releases require the same revision even when versions are equal.
func CheckCompatibility(health map[string]any, version, revision, epoch string) error {
	if version == "dev" {
		return nil
	}
	helperVersion, _ := health["version"].(string)
	helperRevision, _ := health["revision"].(string)
	helperEpoch, _ := health["build_epoch"].(string)
	// Old Helpers did not report a build timestamp. Their version/revision
	// still identifies the packaged code.
	if helperVersion != version || helperRevision != revision || (helperEpoch != "" && epoch != "" && epoch != "0" && helperEpoch != epoch) {
		return fmt.Errorf("运行中的 Helper 与套件构建不匹配（期望 %s %s，运行 %s %s），请点击“重启并检查 Helper”", version, revision, helperVersion, helperRevision)
	}
	return nil
}
