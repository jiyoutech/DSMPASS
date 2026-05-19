import type {
  AdminAuthStatus,
  AdminLoginRequest,
  AdminPasswordChange,
  DSMAccount,
  DSMGroup,
  GroupMember,
  HelperStatus,
  LoginAuditLog,
  ProviderUpsert,
  ProviderItem,
  ProviderTypeItem,
  ResetSyncDataResult,
  SyncOperationLog,
  SyncResult,
  SystemSettings,
  SystemSettingsDiscovery,
  SystemSettingsUpdate,
  VersionInfo
} from "./types";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {})
    },
    ...init
  });
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      message = body.detail ?? body.message ?? body.error ?? message;
    } catch {
      // Keep status text.
    }
    throw new Error(message);
  }
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string }>("/healthz"),
  ready: () => request<{ status: string }>("/readyz"),
  adminAuthStatus: () => request<AdminAuthStatus>("/api/admin/auth/status"),
  adminLogin: (payload: AdminLoginRequest) =>
    request<AdminAuthStatus>("/api/admin/auth/login", { method: "POST", body: JSON.stringify(payload) }),
  adminSetup: (payload: AdminLoginRequest) =>
    request<AdminAuthStatus>("/api/admin/auth/setup", { method: "POST", body: JSON.stringify(payload) }),
  adminLogout: () => request<{ authenticated: boolean }>("/api/admin/auth/logout", { method: "POST" }),
  adminChangePassword: (payload: AdminPasswordChange) =>
    request<{ success: boolean; username: string }>("/api/admin/auth/password", { method: "PUT", body: JSON.stringify(payload) }),
  syncApply: (provider: string) => request<SyncResult>(`/api/sync/${provider}/apply`, { method: "POST" }),
  listDSMAccounts: (provider?: string) => request<{ items: DSMAccount[] }>(`/api/admin/dsm-accounts${provider ? `?provider=${encodeURIComponent(provider)}` : ""}`),
  listDSMGroups: (provider?: string) => request<{ items: DSMGroup[] }>(`/api/admin/dsm-groups${provider ? `?provider=${encodeURIComponent(provider)}` : ""}`),
  listGroupMembers: (provider?: string) => request<{ items: GroupMember[] }>(`/api/admin/group-members${provider ? `?provider=${encodeURIComponent(provider)}` : ""}`),
  provisionAccount: (id: string) => request<DSMAccount>(`/api/admin/dsm-accounts/${id}/provision`, { method: "POST" }),
  setDSMAccountUsername: (id: string, dsm_username: string) =>
    request<DSMAccount>(`/api/admin/dsm-accounts/${id}/username`, { method: "PUT", body: JSON.stringify({ dsm_username }) }),
  setDSMAccountLogin: (id: string, allow_login: boolean) =>
    request<DSMAccount>(`/api/admin/dsm-accounts/${id}/login`, { method: "PUT", body: JSON.stringify({ allow_login }) }),
  setDSMAccountsLogin: (ids: string[], allow_login: boolean) =>
    request<{ items: DSMAccount[] }>("/api/admin/dsm-accounts/login", { method: "PUT", body: JSON.stringify({ ids, allow_login }) }),
  provisionGroup: (id: string) => request<DSMGroup>(`/api/admin/dsm-groups/${id}/provision`, { method: "POST" }),
  setDSMGroupName: (id: string, dsm_groupname: string) =>
    request<DSMGroup>(`/api/admin/dsm-groups/${id}/name`, { method: "PUT", body: JSON.stringify({ dsm_groupname }) }),
  provisionMember: (id: string) =>
    request<{ id: string; provision_status: string }>(`/api/admin/group-members/${id}/provision`, { method: "POST" }),
  listProviders: () => request<{ items: ProviderItem[] }>("/api/admin/providers"),
  listProviderTypes: () => request<{ items: ProviderTypeItem[] }>("/api/admin/provider-types"),
  createProvider: (payload: ProviderUpsert) =>
    request<ProviderItem>("/api/admin/providers", { method: "POST", body: JSON.stringify(payload) }),
  updateProvider: (slug: string, payload: ProviderUpsert) =>
    request<ProviderItem>(`/api/admin/providers/${slug}`, { method: "PUT", body: JSON.stringify(payload) }),
  deleteProvider: (slug: string) =>
    request<{ slug: string; deleted_sources: number; disabled_dsm_users: number; detail: string }>(`/api/admin/providers/${slug}`, { method: "DELETE" }),
  resetProviderSyncData: (slug: string) =>
    request<ResetSyncDataResult>(`/api/admin/providers/${slug}/reset-sync-data`, { method: "POST" }),
  sourceSyncLogs: (slug: string) => request<{ items: SyncOperationLog[] }>(`/api/admin/providers/${slug}/sync-logs`),
  helperStatus: () => request<HelperStatus>("/api/admin/helper/status"),
  restartHelper: () => request<{ success: boolean }>("/api/admin/helper/restart", { method: "POST" }),
  version: () => request<VersionInfo>("/api/admin/version"),
  systemSettings: () => request<SystemSettings>("/api/admin/settings"),
  updateSystemSettings: (payload: SystemSettingsUpdate) =>
    request<SystemSettings>("/api/admin/settings", { method: "PUT", body: JSON.stringify(payload) }),
  discoverSettings: (payload: { access_host: string; access_scheme?: "http" | "https"; admin_port?: number; idp_port?: number }) =>
    request<SystemSettingsDiscovery>("/api/admin/settings/discover", { method: "POST", body: JSON.stringify(payload) }),
  loginAuditLogs: (provider?: string) => request<{ items: LoginAuditLog[] }>(`/api/admin/audit/logins${provider ? `?provider=${encodeURIComponent(provider)}` : ""}`),
  relayJournals: () => request<{ items: unknown[] }>("/api/admin/relay/journals")
};
