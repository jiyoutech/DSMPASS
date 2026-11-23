package db

import "context"

const dingTalkOffboardingScope = `
FROM identity_sources s
JOIN dsm_mapping_entries m ON m.provider_slug=s.slug AND m.mapping_type='user'
JOIN dsm_accounts a ON a.id=m.dsm_account_id
JOIN external_accounts e ON e.id=m.external_account_id AND e.provider_slug=s.slug AND e.app_identity_id=a.app_identity_id`

const dingTalkOffboardingEligible = `s.provider_type='dingtalk' AND s.enabled=1 AND s.directory_sync_enabled=1
AND COALESCE(json_extract(s.config_json,'$.disable_missing_users'),1)=1
AND a.provision_status IN ('created','linked_existing','failed','pending') AND COALESCE(a.conflict_reason,'')=''
AND e.active=0 AND e.subject<>'' AND NOT EXISTS (
 SELECT 1 FROM external_accounts live WHERE live.active=1 AND
 (live.app_identity_id=a.app_identity_id OR (live.provider_slug=s.slug AND trim(live.display_name)=a.dsm_username))
)`

type DingTalkOffboardingCandidate struct{ AccountID, Username, Subject string }

func DingTalkOffboardingCandidates(ctx context.Context, q *Queries, source string) ([]DingTalkOffboardingCandidate, error) {
	rows, err := q.DBTX().QueryContext(ctx, `SELECT DISTINCT a.id,a.dsm_username,e.subject `+dingTalkOffboardingScope+` WHERE `+dingTalkOffboardingEligible+` AND s.slug=? ORDER BY a.id,e.subject`, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []DingTalkOffboardingCandidate
	for rows.Next() {
		var candidate DingTalkOffboardingCandidate
		if err := rows.Scan(&candidate.AccountID, &candidate.Username, &candidate.Subject); err != nil {
			return nil, err
		}
		result = append(result, candidate)
	}
	return result, rows.Err()
}
