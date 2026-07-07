export type ProvisionStatus = "pending" | "created" | "linked_existing" | "disabled" | "conflict" | string;

export interface SyncPlanItem {
  action: string;
  provider_slug: string;
  subject: string;
  display_name: string | null;
  dsm_username: string | null;
  dsm_groupname: string | null;
  provision_status: ProvisionStatus;
}

export interface SyncResult {
  provider_slug: string;
  items: SyncPlanItem[];
}

export interface PagedResponse<T> {
  items: T[];
  page: number;
  limit: number;
  total: number;
  offset: number;
}

export interface DSMAccount {
  id: string;
  provider_slug: string;
  app_identity_id: string;
  dsm_username: string;
  display_name?: string;
  primary_email?: string;
  external_emails?: string;
  mobile_masked?: string;
  external_subjects?: string;
  provision_status: ProvisionStatus;
  conflict_reason: string | null;
  allow_login: boolean;
}

export interface DSMGroup {
  id: string;
  provider_slug: string;
  dsm_groupname: string;
  provision_status: ProvisionStatus;
  conflict_reason: string | null;
  provider_group_name?: string;
  provider_group_path?: string;
}

export interface GroupMember {
  id: string;
  provider_slug: string;
  dsm_group_id: string;
  dsm_account_id: string;
  dsm_groupname: string;
  dsm_username: string;
  provision_status: ProvisionStatus;
}

export interface ProviderItem {
  slug: string;
  provider_type: string;
  display_name: string;
  enabled: boolean;
  login_enabled: boolean;
  directory_sync_enabled: boolean;
  credentials_configured: boolean;
  login_url?: string;
  callback_url?: string;
  feishu_authorize_url?: string;
  wecom_authorize_url?: string;
  builtin?: boolean;
  config?: {
    public_base_url?: string;
    client_id?: string;
    agent_id?: string;
    client_secret_configured?: boolean;
    authorize_url?: string;
    token_url?: string;
    user_info_url?: string;
    tenant_token_url?: string;
    contact_base_url?: string;
    directory_page_size?: number;
    sync_interval_minutes?: number;
    disable_missing_users?: boolean;
    deactivate_missing_data?: boolean;
    initial_password?: string;
  };
}

export interface ProviderTypeItem {
  type: string;
  display_name: string;
  supports_login: boolean;
  supports_sync: boolean;
  requires_client_id?: boolean;
  requires_secret?: boolean;
  requires_agent_id?: boolean;
  supports_authorize?: boolean;
  supports_contact_api?: boolean;
}

export interface ProviderUpsert {
  slug?: string;
  provider_type?: string;
  display_name?: string;
  enabled?: boolean;
  login_enabled?: boolean;
  directory_sync_enabled?: boolean;
  config?: {
    public_base_url?: string;
    client_id?: string;
    agent_id?: string;
    client_secret?: string;
    authorize_url?: string;
    token_url?: string;
    user_info_url?: string;
    tenant_token_url?: string;
    contact_base_url?: string;
    directory_page_size?: number;
    sync_interval_minutes?: number;
    disable_missing_users?: boolean;
    deactivate_missing_data?: boolean;
    initial_password?: string;
  };
}

export interface ResetSyncDataResult {
  slug: string;
  deleted_external: number;
  deleted_identities: number;
  deleted_dsm_accounts: number;
  deleted_provider_groups: number;
  deleted_dsm_groups: number;
  deleted_group_links: number;
  deleted_group_members: number;
  deleted_dsm_mappings?: number;
  disabled_dsm_users: number;
  detail: string;
}

export interface SyncOperationLog {
  id: string;
  sync_run_id: string;
  source_slug: string;
  object_type: string;
  object_key: string;
  dsm_name: string | null;
  action: string;
  status: string;
  before_state: string | null;
  after_state: string | null;
  error: string | null;
  created_at: string;
}

export interface HelperStatus {
  mode: string;
  socket_path: string;
  reachable: boolean;
  error: string | null;
  details: HelperStatusDetails;
}

export interface HelperCommandStatus {
  path?: string;
  exists?: boolean;
  executable?: boolean;
  mode?: string;
  uid?: number;
  gid?: number;
  error?: string;
}

export interface HelperStatusDetails {
  version?: string;
  socket_path?: string;
  euid?: number;
  egid?: number;
  synouser_path?: string;
  synouser_status?: HelperCommandStatus;
  synogroup_path?: string;
  synogroup_status?: HelperCommandStatus;
  [key: string]: unknown;
}

export interface VersionInfo {
  backend_version: string;
  frontend_version: string;
  helper_version: string;
  helper_reachable: boolean;
  helper_error?: string;
}

export interface AdminAuthStatus {
  authenticated: boolean;
  username: string;
  enabled: boolean;
  setup_required: boolean;
}

export interface AdminLoginRequest {
  username: string;
  password: string;
}

export interface AdminPasswordChange {
  username?: string;
  current_password: string;
  new_password: string;
}

export interface LoginAuditLog {
  id: string;
  request_id: string;
  provider_slug: string;
  dsm_username: string | null;
  result: string;
  error_code: string | null;
  ip_address: string | null;
  ip_hash: string | null;
  user_agent_hash: string | null;
  duration_ms: number | null;
  created_at: string;
}

export interface OperationRun {
  id: string;
  kind: string;
  source_slug: string | null;
  status: "running" | "success" | "failed" | string;
  phase: string;
  message: string;
  current: number;
  total: number;
  started_at: string;
  updated_at: string;
  finished_at: string | null;
  error: string | null;
}

export interface OperationEvent {
  id: string;
  operation_run_id: string;
  source_slug: string | null;
  kind: string;
  phase: string;
  message: string;
  current: number;
  total: number;
  status: string;
  error: string | null;
  created_at: string;
}

export interface SystemSettings {
  deployment_mode: "direct" | "reverse_proxy" | "advanced";
  access_host: string;
  access_scheme: "http" | "https";
  admin_port: number;
  idp_port: number;
  admin_allowed_cidrs: string;
  idp_allowed_cidrs: string;
  public_base_url: string;
  dsm_redirect_url: string;
  dsm_cookie_name: string;
  dsm_cookie_secure: boolean;
  dsm_cookie_httponly: boolean;
  dsm_cookie_samesite: string;
  helper_dsm_login_mode: "browser" | "helper";
  helper_dsm_browser_login_ttl_seconds: number;
  helper_dsm_login_api: string;
  helper_dsm_session: string;
  helper_dsm_format: string;
  helper_dsm_tls_skip_verify: boolean;
  setup_completed: boolean;
  helper_hmac_secret_configured: boolean;
}

export interface SystemSettingsOverviewFact {
  title: string;
  value: string;
  configurable: boolean;
  change_method: string;
  applies: string;
  description: string;
  notes: string[];
}

export interface SystemSettingsOverviewConfig {
  key: string;
  label: string;
  value: string;
  configurable: boolean;
  change_method: string;
  applies: string;
  effect: string;
  notes: string[];
}

export interface SystemSettingsOverview {
  title: string;
  summary: string[];
  runtime: SystemSettingsOverviewFact[];
  deployment_modes: SystemSettingsOverviewFact[];
  configuration: SystemSettingsOverviewConfig[];
  certificates: SystemSettingsOverviewConfig[];
  operational_notes: string[];
}

export interface SystemSettingsDiscovery {
  deployment_mode?: "direct" | "reverse_proxy" | "advanced";
  access_host: string;
  access_scheme: "http" | "https";
  admin_port: number;
  idp_port: number;
  admin_allowed_cidrs?: string;
  idp_allowed_cidrs?: string;
  public_base_url: string;
  dsm_redirect_url: string;
  helper_dsm_login_api: string;
  dsm_detected: boolean;
}

export interface CertificateInfo {
  common_name: string;
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  dns_names: string[];
  label: string;
  is_self_signed: boolean;
  is_test_certificate: boolean;
}

export type SystemSettingsUpdate = Partial<
  Omit<SystemSettings, "helper_hmac_secret_configured"> & {
    relay_helper_hmac_secret: string;
  }
>;
