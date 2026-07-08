import type {
  AdminAuthStatus,
  AdminLoginRequest,
  AdminPasswordChange,
  CertificateInfo,
  DSMAccount,
  DSMGroup,
  GroupMember,
  HelperStatus,
  LoginAuditLog,
  OperationEvent,
  OperationRun,
  PagedResponse,
  ProviderUpsert,
  ProviderItem,
  ProviderTypeItem,
  ResetSyncDataResult,
  SourceInitialPasswordReveal,
  SyncOperationLog,
  SyncResult,
  SystemSettings,
  SystemSettingsDiscovery,
  SystemSettingsOverview,
  SystemSettingsUpdate,
  VersionInfo
} from "./types";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "";

export interface ListParams {
  provider?: string;
  q?: string;
  status?: string;
  result?: string;
  active?: string;
  page?: number;
  limit?: number;
}

const MAX_PAGE_LIMIT = 200;

function queryString(params: ListParams = {}) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "" || value === "all") {
      continue;
    }
    search.set(key, String(value));
  }
  const encoded = search.toString();
  return encoded ? `?${encoded}` : "";
}

async function listAllPaged<T>(loader: (params: ListParams) => Promise<PagedResponse<T>>, params: ListParams = {}) {
  const limit = Math.max(1, params.limit ?? MAX_PAGE_LIMIT);
  let page = 1;
  const items: T[] = [];
  for (;;) {
    const response = await loader({ ...params, page, limit });
    items.push(...response.items);
    if (items.length >= response.total || response.items.length === 0) {
      return { ...response, items, page: 1, limit, total: response.total, offset: 0 };
    }
    page += 1;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (!(init?.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(`${API_BASE}${path}`, {
    credentials: "same-origin",
    ...init,
    headers
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
  startSyncRun: (provider: string) => request<{ run_id: string }>(`/api/admin/providers/${provider}/sync-runs`, { method: "POST" }),
  listDSMAccounts: (params?: ListParams) => request<PagedResponse<DSMAccount>>(`/api/admin/dsm-accounts${queryString(params)}`),
  listAllDSMAccounts: (params?: ListParams) => listAllPaged<DSMAccount>(api.listDSMAccounts, { ...params, limit: params?.limit ?? MAX_PAGE_LIMIT }),
  listDSMGroups: (params?: ListParams) => request<PagedResponse<DSMGroup>>(`/api/admin/dsm-groups${queryString(params)}`),
  listAllDSMGroups: (params?: ListParams) => listAllPaged<DSMGroup>(api.listDSMGroups, { ...params, limit: params?.limit ?? MAX_PAGE_LIMIT }),
  listGroupMembers: (provider?: string) => request<{ items: GroupMember[] }>(`/api/admin/group-members${provider ? `?provider=${encodeURIComponent(provider)}` : ""}`),
  provisionAccount: (id: string) => request<DSMAccount>(`/api/admin/dsm-accounts/${id}/provision`, { method: "POST" }),
  setDSMAccountUsername: (id: string, dsm_username: string) =>
    request<DSMAccount>(`/api/admin/dsm-accounts/${id}/username`, { method: "PUT", body: JSON.stringify({ dsm_username }) }),
  setDSMAccountLogin: (id: string, allow_login: boolean) =>
    request<DSMAccount>(`/api/admin/dsm-accounts/${id}/login`, { method: "PUT", body: JSON.stringify({ allow_login }) }),
  setDSMAccountsLogin: (ids: string[], allow_login: boolean) =>
    request<{ items: DSMAccount[] }>("/api/admin/dsm-accounts/login", { method: "PUT", body: JSON.stringify({ ids, allow_login }) }),
  startDSMAccountsLoginRun: (ids: string[], allow_login: boolean) =>
    request<{ run_id: string }>("/api/admin/dsm-accounts/login-runs", { method: "POST", body: JSON.stringify({ ids, allow_login }) }),
  provisionGroup: (id: string) => request<DSMGroup>(`/api/admin/dsm-groups/${id}/provision`, { method: "POST" }),
  setDSMGroupName: (id: string, dsm_groupname: string) =>
    request<DSMGroup>(`/api/admin/dsm-groups/${id}/name`, { method: "PUT", body: JSON.stringify({ dsm_groupname }) }),
  provisionMember: (id: string) =>
    request<{ id: string; provision_status: string }>(`/api/admin/group-members/${id}/provision`, { method: "POST" }),
  listProviders: () => request<{ items: ProviderItem[] }>("/api/admin/providers"),
  listProviderTypes: () => request<{ items: ProviderTypeItem[] }>("/api/admin/provider-types"),
  revealSourceInitialPassword: (slug: string) =>
    request<SourceInitialPasswordReveal>(`/api/admin/providers/${slug}/initial-password/reveal`, { method: "POST" }),
  createProvider: (payload: ProviderUpsert) =>
    request<ProviderItem>("/api/admin/providers", { method: "POST", body: JSON.stringify(payload) }),
  updateProvider: (slug: string, payload: ProviderUpsert) =>
    request<ProviderItem>(`/api/admin/providers/${slug}`, { method: "PUT", body: JSON.stringify(payload) }),
  deleteProvider: (slug: string) =>
    request<{ slug: string; deleted_sources: number; disabled_dsm_users: number; detail: string }>(`/api/admin/providers/${slug}`, { method: "DELETE" }),
  resetProviderSyncData: (slug: string) =>
    request<ResetSyncDataResult>(`/api/admin/providers/${slug}/reset-sync-data`, { method: "POST" }),
  startCleanupRun: (slug: string) =>
    request<{ run_id: string }>(`/api/admin/providers/${slug}/cleanup-runs`, { method: "POST" }),
  sourceSyncLogs: (slug: string, params?: ListParams) => request<PagedResponse<SyncOperationLog>>(`/api/admin/providers/${slug}/sync-logs${queryString(params)}`),
  operationRun: (runID: string) => request<OperationRun>(`/api/admin/operation-runs/${runID}`),
  operationRunEvents: (runID: string, params?: ListParams) => request<PagedResponse<OperationEvent>>(`/api/admin/operation-runs/${runID}/events${queryString(params)}`),
  helperStatus: () => request<HelperStatus>("/api/admin/helper/status"),
  restartHelper: () => request<{ success: boolean }>("/api/admin/helper/restart", { method: "POST" }),
  version: () => request<VersionInfo>("/api/admin/version"),
  systemSettings: () => request<SystemSettings>("/api/admin/settings"),
  systemSettingsOverview: () => request<SystemSettingsOverview>("/api/admin/settings/overview"),
  updateSystemSettings: (payload: SystemSettingsUpdate) =>
    request<SystemSettings>("/api/admin/settings", { method: "PUT", body: JSON.stringify(payload) }),
  uploadCertificate: (scope: "admin" | "idp", cert: File, key: File) => {
    const body = new FormData();
    body.append("cert", cert);
    body.append("key", key);
    return request<{ success: boolean; scope: string; restart_required: boolean; connections_refreshed: boolean; certificate_domains: string[]; certificate_info: CertificateInfo; applied_access_host: string }>(`/api/admin/settings/certificates/${scope}`, { method: "POST", body });
  },
  refreshTLSConnections: () => request<{ success: boolean; connections_refreshed: boolean }>("/api/admin/tls-connections/refresh", { method: "POST" }),
  restartIDPRoute: () => request<{ success: boolean }>("/api/admin/idp-route/restart", { method: "POST" }),
  discoverSettings: (payload: { access_host: string; access_scheme?: "http" | "https"; admin_port?: number; idp_port?: number }) =>
    request<SystemSettingsDiscovery>("/api/admin/settings/discover", { method: "POST", body: JSON.stringify(payload) }),
  loginAuditLogs: (params?: ListParams) => request<PagedResponse<LoginAuditLog>>(`/api/admin/audit/logins${queryString(params)}`)
};
