import {
  ArrowLeftOutlined,
  CopyOutlined,
  DeleteOutlined,
  KeyOutlined,
  LogoutOutlined,
  PlusOutlined,
  ReloadOutlined,
  SettingOutlined
} from "@ant-design/icons";
import {
  Alert,
  App as AntApp,
  Badge,
  Button,
  Card,
  ConfigProvider,
  Flex,
  Form,
  Input,
  InputNumber,
  Layout,
  Menu,
  Modal,
  Progress,
  Segmented,
  Select,
  Space,
  Steps,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
  theme
} from "antd";
import type { ColumnsType } from "antd/es/table";
import zhCN from "antd/locale/zh_CN";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "./api";
import { EntityList, HelpLabel, IdentityCell, LogBlock, MetricStrip, PageTitle, RelationCount, SourceTable } from "./components/common";
import { useAsyncData } from "./hooks/useAsyncData";
import { SystemSettings as SystemSettingsPage, SystemSettingsFields } from "./pages/SystemSettings";
import type {
  DSMAccount,
  DSMGroup,
  GroupMember,
  LoginAuditLog,
  AdminAuthStatus,
  AdminLoginRequest,
  HelperStatus,
  ProviderItem,
  ProviderTypeItem,
  ProviderUpsert,
  SystemSettings,
  SystemSettingsUpdate
} from "./types";
import { actionTag, includesQuery, labelOf, resultTag, statusTag } from "./utils/labels";
import { formatLocalTime } from "./utils/time";

const { Header, Sider, Content } = Layout;
const { Title } = Typography;
const appName = "DSM Pass";
const defaultIDPPort = 26000;
const sourceTablePageSize = 50;

function helperStatusOK(status: HelperStatus | null | undefined) {
  const details = status?.details;
  return status?.reachable === true &&
    details?.euid === 0 &&
    details.synouser_status?.executable === true &&
    details.synogroup_status?.executable === true;
}

function helperStatusProblem(status: HelperStatus) {
  if (!status.reachable) {
    return `检查未通过：${status.error || "Helper 不可连接"}`;
  }
  const details = status.details;
  const synouser = details.synouser_status?.executable ? "ok" : details.synouser_status?.error || "不可执行";
  const synogroup = details.synogroup_status?.executable ? "ok" : details.synogroup_status?.error || "不可执行";
  return `检查未通过：当前 EUID ${details.euid ?? "-"}，synouser: ${synouser}，synogroup: ${synogroup}`;
}

function preferredInitialIDPPort(settings: SystemSettings | null) {
  const idpPort = Number(settings?.idp_port || 0);
  const adminPort = Number(settings?.admin_port || 0);
  if (!idpPort || idpPort === adminPort) {
    return defaultIDPPort;
  }
  return idpPort;
}

function withPreferredPort(value: string | undefined, port: number) {
  if (!value) {
    return value;
  }
  try {
    const parsed = new URL(value);
    parsed.port = String(port);
    return parsed.toString().replace(/\/$/, "");
  } catch {
    return value;
  }
}

function accountContactText(record: DSMAccount) {
  return [record.primary_email || record.external_emails, record.mobile_masked].filter(Boolean).join(" / ");
}

type PageKey = "providers" | "source-detail" | "settings";
const pageKeys: PageKey[] = ["providers", "source-detail", "settings"];
type SourceTabKey = "addresses" | "users" | "groups" | "sync-logs" | "audit-logs";
const sourceTabKeys: SourceTabKey[] = ["addresses", "users", "groups", "sync-logs", "audit-logs"];
type EnrichedDSMAccount = DSMAccount & { groups: string[]; member_records: GroupMember[] };

function accountConflictKind(record: DSMAccount) {
  const reason = record.conflict_reason || "";
  if (reason.includes("飞书用户姓名重名") || reason.includes("飞书通讯录内用户姓名重名")) {
    return "feishu_duplicate";
  }
  if (reason.includes("DSM 用户名已存在") || reason.includes("DSM 本地已存在同名用户")) {
    return "dsm_existing";
  }
  if (reason.includes("已被其他身份占用") || reason.includes("DSM Pass 内已有身份占用")) {
    return "dsmpass_existing";
  }
  return "other";
}

function accountConflictLabel(record: DSMAccount) {
  switch (accountConflictKind(record)) {
    case "feishu_duplicate":
      return "飞书内重名";
    case "dsm_existing":
      return "DSM 已有同名旧记录";
    case "dsmpass_existing":
      return "已被其他身份占用";
    default:
      return "其他冲突";
  }
}

function BridgeLogo() {
  return <img src="/favicon.svg" alt={appName} />;
}

const sourceFieldHelp = {
  displayName: "后台里显示的身份源名称，只影响管理界面展示，不会同步到飞书或 DSM。",
  providerType: "选择这个身份源连接的上游系统。当前用于飞书登录和通讯录同步。",
  clientID: "飞书开放平台应用的 App ID，用于发起飞书 OAuth 登录和调用通讯录接口。",
  clientSecret: "飞书应用密钥，用于后端向飞书换取访问 token。留空保存会沿用旧密钥。",
  initialPassword: "同步创建新的 DSM 用户时使用的初始密码。已有 DSM 用户通常不会被改密码。",
  enabled: "身份源总开关。关闭后，这个身份源整体不可用，登录和同步都会停止。",
  loginEnabled: "控制这个身份源是否允许用户通过飞书登录 DSM。关闭后同步功能仍可单独使用。",
  syncEnabled: "控制是否允许从飞书通讯录同步用户、部门和成员关系到本地映射/DSM。",
  syncInterval: "自动同步间隔。0 表示不自动同步，只能手动点击同步。",
  disableMissingUsers: "同步时如果用户已不在飞书通讯录中，就禁用对应 DSM 用户登录。"
};

function helpLabel(label: string, help: string) {
  return <HelpLabel label={label} help={help} />;
}

function AuthGate() {
  const auth = useAsyncData(() => api.adminAuthStatus(), []);
  const [session, setSession] = useState<AdminAuthStatus | null>(null);

  useEffect(() => {
    if (auth.data) {
      setSession(auth.data);
    }
  }, [auth.data]);

  if (auth.loading && !session) {
    return <div className="login-page" />;
  }
  if (session?.setup_required) {
    return <SetupPage onSetup={setSession} />;
  }
  if (!session?.authenticated) {
    return <LoginPage onLogin={setSession} />;
  }
  return <OnboardingGate auth={session} onLogout={() => setSession({ ...session, authenticated: false })} />;
}

function SetupPage({ onSetup }: { onSetup: (status: AdminAuthStatus) => void }) {
  const [form] = Form.useForm<AdminLoginRequest>();
  const { message } = AntApp.useApp();
  const [loading, setLoading] = useState(false);

  async function setup(values: AdminLoginRequest) {
    setLoading(true);
    try {
      onSetup(await api.adminSetup(values));
    } catch (err) {
      message.error(err instanceof Error ? err.message : "保存失败");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-page">
      <Card title="初始化后台账号" className="login-card">
        <Form form={form} layout="vertical" onFinish={(values) => void setup(values)} initialValues={{ username: "admin" }}>
          <Form.Item name="username" label="账号" rules={[{ required: true }]}>
            <Input autoComplete="username" autoFocus />
          </Form.Item>
          <Form.Item name="password" label="密码" rules={[{ required: true }]}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Button type="primary" htmlType="submit" block loading={loading}>保存</Button>
        </Form>
      </Card>
    </div>
  );
}

function LoginPage({ onLogin }: { onLogin: (status: AdminAuthStatus) => void }) {
  const [form] = Form.useForm<AdminLoginRequest>();
  const { message } = AntApp.useApp();
  const [loading, setLoading] = useState(false);

  async function login(values: AdminLoginRequest) {
    setLoading(true);
    try {
      onLogin(await api.adminLogin(values));
    } catch (err) {
      message.error(err instanceof Error ? err.message : "登录失败");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-page">
      <Card title={appName} className="login-card">
        <Form form={form} layout="vertical" onFinish={(values) => void login(values)}>
          <Form.Item name="username" label="账号" rules={[{ required: true }]}>
            <Input autoComplete="username" autoFocus />
          </Form.Item>
          <Form.Item name="password" label="密码" rules={[{ required: true }]}>
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Button type="primary" htmlType="submit" block loading={loading}>登录</Button>
        </Form>
      </Card>
    </div>
  );
}

function systemReady(settings: SystemSettings | null) {
  return Boolean(
    settings?.access_host &&
    settings.public_base_url &&
    settings.dsm_redirect_url &&
    settings.helper_dsm_login_api &&
    settings.setup_completed
  );
}

function OnboardingGate({ auth, onLogout }: { auth: AdminAuthStatus; onLogout: () => void }) {
  const settings = useAsyncData(() => api.systemSettings(), []);

  const ready = systemReady(settings.data);

  if (settings.loading && !settings.data) {
    return <div className="login-page" />;
  }
  if (ready) {
    return <AppShell auth={auth} onLogout={onLogout} />;
  }
  return (
    <Onboarding
      settings={settings.data}
      settingsError={settings.error}
      reloadSettings={settings.reload}
    />
  );
}

function Onboarding({
  settings,
  settingsError,
  reloadSettings
}: {
  settings: SystemSettings | null;
  settingsError: string | null;
  reloadSettings: () => Promise<void>;
}) {
  const { message } = AntApp.useApp();
  const [saving, setSaving] = useState(false);
  const [systemForm] = Form.useForm<SystemSettingsUpdate>();

  useEffect(() => {
    if (settings) {
      const idpPort = preferredInitialIDPPort(settings);
      systemForm.setFieldsValue({
        access_host: settings.access_host,
        access_scheme: settings.access_scheme || "https",
        idp_port: idpPort,
        admin_allowed_cidrs: settings.admin_allowed_cidrs,
        public_base_url: withPreferredPort(settings.public_base_url, idpPort),
        dsm_redirect_url: settings.dsm_redirect_url,
        helper_dsm_login_api: settings.helper_dsm_login_api,
        helper_dsm_login_mode: settings.helper_dsm_login_mode || "browser",
        helper_dsm_browser_login_ttl_seconds: settings.helper_dsm_browser_login_ttl_seconds || 30,
        helper_dsm_tls_skip_verify: settings.helper_dsm_tls_skip_verify
      });
    }
  }, [settings, systemForm]);

  async function saveSystem(values: SystemSettingsUpdate) {
    setSaving(true);
    try {
      await api.updateSystemSettings({ ...values, setup_completed: true });
      await reloadSettings();
      message.success("已保存");
    } catch (err) {
      message.error(err instanceof Error ? err.message : "保存失败");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="login-page">
      <Card title="初始化配置" className="setup-card">
        <Steps
          current={0}
          className="setup-steps"
          percent={systemReady(settings) ? 100 : 50}
          items={[
            { title: "系统配置", status: systemReady(settings) ? "finish" : "process" }
          ]}
        />
        <Progress percent={systemReady(settings) ? 100 : 50} status={systemReady(settings) ? "success" : "active"} />
        {settingsError && <Alert type="error" showIcon message={settingsError} />}
        <Form
          form={systemForm}
          layout="vertical"
          onFinish={(values) => void saveSystem(values)}
          initialValues={{
            access_scheme: "https",
            idp_port: defaultIDPPort,
            admin_allowed_cidrs: "all",
            helper_dsm_login_mode: "browser",
            helper_dsm_browser_login_ttl_seconds: 30,
            helper_dsm_tls_skip_verify: true
          }}
          disabled={saving}
          className="settings-form"
        >
          <SystemSettingsFields />
          <Flex justify="end">
            <Button type="primary" htmlType="submit" loading={saving}>保存并进入</Button>
          </Flex>
        </Form>
      </Card>
    </div>
  );
}

function AppShell({ auth, onLogout }: { auth: AdminAuthStatus; onLogout: () => void }) {
  const initialParams = new URLSearchParams(window.location.search);
  const initialPage = initialParams.get("page");
  const initialSourceSlug = initialParams.get("source") ?? "";
  const initialSourceTab = initialParams.get("tab");
  const [page, setPage] = useState<PageKey>(pageKeys.includes(initialPage as PageKey) ? initialPage as PageKey : "providers");
  const [selectedSource, setSelectedSource] = useState<ProviderItem | null>(null);
  const [pendingSourceSlug, setPendingSourceSlug] = useState(initialSourceSlug);
  const [sourceTab, setSourceTab] = useState<SourceTabKey>(sourceTabKeys.includes(initialSourceTab as SourceTabKey) ? initialSourceTab as SourceTabKey : "addresses");
  const { message } = AntApp.useApp();
  const helperStatus = useAsyncData(() => api.helperStatus(), []);
  const version = useAsyncData(() => api.version(), []);
  const [helperRestarting, setHelperRestarting] = useState(false);
  const helperReachable = helperStatus.data?.reachable === true;
  const helperDetails = helperStatus.data?.details;
  const helperPermissionOK = helperStatusOK(helperStatus.data);
  const menuItems = [
    { key: "providers", icon: <KeyOutlined />, label: "身份源" },
    { key: "settings", icon: <SettingOutlined />, label: "系统设置" }
  ];

  useEffect(() => {
    if (page !== "source-detail" || selectedSource || !pendingSourceSlug) {
      return;
    }
    let cancelled = false;
    api.listProviders()
      .then((result) => {
        if (cancelled) {
          return;
        }
        const source = result.items.find((item) => item.slug === pendingSourceSlug);
        if (source) {
          setSelectedSource(source);
        } else {
          setPendingSourceSlug("");
          setPage("providers");
        }
      })
      .catch(() => {
        if (!cancelled) {
          setPage("providers");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [page, pendingSourceSlug, selectedSource]);

  useEffect(() => {
    const params = new URLSearchParams();
    if (page !== "providers") {
      params.set("page", page);
    }
    if (page === "source-detail") {
      const sourceSlug = selectedSource?.slug || pendingSourceSlug;
      if (sourceSlug) {
        params.set("source", sourceSlug);
      }
      params.set("tab", sourceTab);
    }
    const query = params.toString();
    window.history.replaceState(null, "", query ? `${window.location.pathname}?${query}` : window.location.pathname);
  }, [page, pendingSourceSlug, selectedSource, sourceTab]);

  function openSource(source: ProviderItem) {
    setSelectedSource(source);
    setPendingSourceSlug(source.slug);
    setSourceTab("addresses");
    setPage("source-detail");
  }

  function showProviders() {
    setSelectedSource(null);
    setPendingSourceSlug("");
    setSourceTab("addresses");
    setPage("providers");
  }

  function showSettings() {
    setSelectedSource(null);
    setPendingSourceSlug("");
    setSourceTab("addresses");
    setPage("settings");
  }

  async function restartAndCheckHelper() {
    setHelperRestarting(true);
    try {
      await api.restartHelper();
      const status = await helperStatus.reloadWithResult({ silent: true });
      await version.reload();
      showHelperCheckResult(status, "Helper 已重启，检查通过");
    } catch (err) {
      const detail = err instanceof Error ? err.message : "Helper 重启失败";
      message.error(`Helper 未能重启，请先通过 SSH 执行提权脚本。${detail}`);
    } finally {
      setHelperRestarting(false);
    }
  }

  function showHelperCheckResult(status: HelperStatus | null, okText: string) {
    if (!status) {
      message.error("检查失败：无法获取 Helper 状态");
      return;
    }
    if (helperStatusOK(status)) {
      message.success(okText);
      return;
    }
    message.warning(helperStatusProblem(status));
  }

  return (
    <Layout className="app-shell">
          <Sider width={248} className="app-sider">
            <div className="brand">
              <div className="brand-mark"><BridgeLogo /></div>
              <div className="brand-text">
                <strong>{appName}</strong>
                <span>DSM Identity Gateway</span>
              </div>
            </div>
            <Menu
              theme="light"
              mode="inline"
              selectedKeys={[page === "source-detail" ? "providers" : page]}
              items={menuItems}
              onClick={(event) => event.key === "settings" ? showSettings() : showProviders()}
            />
          </Sider>
          <Layout>
            <Header className="app-header">
              <div className="header-title">
                <Title level={4}>{appName}</Title>
                <span>飞书身份源到 DSM 登录与账号同步</span>
              </div>
              <div className="header-meta">
                <div className="version-stack" aria-label="版本">
                  <span>FE {version.data?.frontend_version ?? "-"}</span>
                  <span>BE {version.data?.backend_version ?? "-"}</span>
                  <span>Helper {version.data?.helper_version || "-"}</span>
                </div>
                <Space className="runtime-status">
                  <Badge status="success" text="Backend" />
                  <Badge
                    status={helperStatus.loading ? "processing" : helperPermissionOK ? "success" : "error"}
                    text={helperStatus.loading ? "Helper" : helperPermissionOK ? "Helper" : "Helper 权限异常"}
                  />
                </Space>
                <Button icon={<LogoutOutlined />} onClick={async () => { await api.adminLogout(); onLogout(); }}>
                  {auth.username}
                </Button>
              </div>
            </Header>
            <Content className="app-content">
              {!helperStatus.loading && !helperPermissionOK && (
                <Alert
                  type="error"
                  showIcon
                  className="runtime-alert"
                  message="Helper 无法执行 DSM 用户和群组命令"
                  description={
                    <div className="runtime-alert-detail">
                      <div>
                        {helperReachable
                          ? `当前 EUID: ${helperDetails?.euid ?? "-"}，synouser: ${helperDetails?.synouser_status?.error ?? "ok"}，synogroup: ${helperDetails?.synogroup_status?.error ?? "ok"}`
                          : helperStatus.data?.error ?? helperStatus.error ?? "Helper 不可连接"}
                      </div>
                      <div>
                        Helper 需要 root 权限调用 DSM 的用户和群组命令。请用管理员账号 SSH 登录 NAS，切换到 root 后安装 Helper sudo 规则；完成后点击下方按钮重启并自动检查。
                      </div>
                      <pre><code>ssh 管理员账号@NAS_IP{"\n"}sudo -i{"\n"}/var/packages/DSMPASS/target/setup-helper-sudo.sh{"\n"}# 回到本页面点击「重启并检查 Helper」后，再检查 socket 是否生成{"\n"}ls -l /var/packages/DSMPASS/var/run/helper.sock</code></pre>
                      <div>
                        正常结果应显示 `helper.sock`，并且权限列以 `s` 开头，例如 `srw-rw----`；如果显示 `No such file or directory`，说明 Helper 还没有成功启动。
                      </div>
                      <Space>
                        <Button
                          htmlType="button"
                          icon={<ReloadOutlined />}
                          loading={helperRestarting}
                          onClick={() => void restartAndCheckHelper()}
                        >
                          重启并检查 Helper
                        </Button>
                      </Space>
                    </div>
                  }
                />
              )}
              {page === "providers" && <Providers onOpen={openSource} helperReady={helperPermissionOK} helperLoading={helperStatus.loading} />}
              {page === "source-detail" && selectedSource && (
                <SourceDetail
                  source={selectedSource}
                  activeTab={sourceTab}
                  onTabChange={setSourceTab}
                  onBack={showProviders}
                  onUpdated={setSelectedSource}
                  onDeleted={showProviders}
                />
              )}
              {page === "settings" && <SystemSettingsPage />}
            </Content>
          </Layout>
    </Layout>
  );
}

function Providers({
  onOpen,
  helperReady,
  helperLoading
}: {
  onOpen: (source: ProviderItem) => void;
  helperReady: boolean;
  helperLoading: boolean;
}) {
  const { data, loading, error, reload } = useAsyncData(() => api.listProviders(), []);
  const providerTypes = useAsyncData(() => api.listProviderTypes(), []);
  const [form] = Form.useForm<ProviderUpsert>();
  const { modal, message } = AntApp.useApp();
  const [open, setOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [deletingSlug, setDeletingSlug] = useState<string | null>(null);
  const providerTypeItems = providerTypes.data?.items ?? [];
  const providerTypeLabels = useMemo(() => {
    const labels = new Map<string, string>();
    for (const item of providerTypeItems) {
      labels.set(item.type, item.display_name);
    }
    return labels;
  }, [providerTypeItems]);
  const providerTypeOptions = useMemo(() => providerTypeItems.map((item) => ({ label: item.display_name, value: item.type })), [providerTypeItems]);
  const selectedProviderType = Form.useWatch("provider_type", form) as string | undefined;
  const selectedProvider = providerTypeItems.find((item) => item.type === selectedProviderType);
  const canCreateSource = helperReady && !helperLoading;

  useEffect(() => {
    if (open && providerTypeOptions.length > 0 && !form.getFieldValue("provider_type")) {
      form.setFieldValue("provider_type", providerTypeOptions[0].value);
    }
  }, [form, open, providerTypeOptions]);

  async function create(values: ProviderUpsert) {
    if (!canCreateSource) {
      message.error("请先完成 Helper 提权，并点击「重启并检查 Helper」，再新建身份源");
      return;
    }
    setCreating(true);
    try {
      const source = await api.createProvider(values);
      message.success("已创建");
      setOpen(false);
      form.resetFields();
      await reload();
      onOpen(source);
    } catch (err) {
      message.error(err instanceof Error ? err.message : "创建失败");
    } finally {
      setCreating(false);
    }
  }

  function deleteSource(source: ProviderItem) {
    modal.confirm({
      title: `删除 ${source.display_name}`,
      content: "会先禁用该身份源对应的 DSM 用户，然后删除身份源配置、本地同步映射和日志。此操作不可撤销。",
      okText: "删除",
      cancelText: "取消",
      okButtonProps: { danger: true },
      onOk: async () => {
        setDeletingSlug(source.slug);
        try {
          await api.deleteProvider(source.slug);
          await reload();
          message.success("已删除身份源");
        } catch (err) {
          message.error(err instanceof Error ? err.message : "删除失败");
        } finally {
          setDeletingSlug(null);
        }
      }
    });
  }

  function openCreateSource() {
    if (!canCreateSource) {
      modal.warning({
        title: "修复 Helper 权限后才能新建身份源",
        content: "身份源创建后会触发同步和 DSM 账号开通流程。请先按页面顶部提示通过 SSH 执行 Helper 提权脚本，然后在页面顶部重启并检查 Helper。",
        okText: "知道了"
      });
      return;
    }
    setOpen(true);
  }

  return (
    <Space direction="vertical" size={16} className="page">
      <PageTitle
        title="身份源"
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={() => void reload()}>刷新</Button>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              title={canCreateSource ? "新建身份源" : "请先修复 Helper 权限"}
              onClick={openCreateSource}
            >
              新建
            </Button>
          </Space>
        }
      />
      {error && <Alert type="error" showIcon message={error} />}
      <Card className="data-card">
        <Table
          rowKey="slug"
          pagination={false}
          loading={loading}
          dataSource={data?.items ?? []}
          rowClassName="clickable-table-row"
          onRow={(source) => ({
            onClick: () => onOpen(source)
          })}
          columns={[
            { title: "名称", dataIndex: "display_name" },
            { title: "Provider", dataIndex: "provider_type", render: (value) => providerTypeLabels.get(String(value)) ?? labelOf(value) },
            { title: "状态", dataIndex: "enabled", render: (value) => value ? <Tag color="success">运行中</Tag> : <Tag color="default">已暂停</Tag> },
            { title: "登录", dataIndex: "login_enabled", render: (value) => value ? <Tag color="success">启用</Tag> : <Tag>停用</Tag> },
            { title: "同步", dataIndex: "directory_sync_enabled", render: (value) => value ? <Tag color="success">启用</Tag> : <Tag>停用</Tag> },
            { title: "凭据", dataIndex: "credentials_configured", render: (value) => value ? <Tag color="success">已配置</Tag> : <Tag color="warning">未配置</Tag> },
            {
              title: "操作",
              width: 90,
              render: (_, source: ProviderItem) => (
                <Space>
                  <Button
                    danger
                    size="small"
                    icon={<DeleteOutlined />}
                    loading={deletingSlug === source.slug}
                    onClick={(event) => {
                      event.stopPropagation();
                      deleteSource(source);
                    }}
                  />
                </Space>
              )
            }
          ]}
        />
      </Card>
      <Modal title="新建身份源" open={open} width={640} onCancel={() => setOpen(false)} footer={null} destroyOnHidden>
        <Form form={form} layout="vertical" onFinish={(values) => void create(values)}>
          <div className="form-grid">
            <Form.Item name="provider_type" label={helpLabel("身份源类型", sourceFieldHelp.providerType)} initialValue={providerTypeOptions[0]?.value} rules={[{ required: true }]}>
              <Select loading={providerTypes.loading} options={providerTypeOptions} />
            </Form.Item>
            <Form.Item name="display_name" label={helpLabel("名称", sourceFieldHelp.displayName)} rules={[{ required: true }]}>
              <Input />
            </Form.Item>
            <Form.Item name={["config", "client_id"]} label={helpLabel("App ID", sourceFieldHelp.clientID)} rules={[{ required: selectedProvider?.requires_client_id }]}>
              <Input />
            </Form.Item>
            <Form.Item name={["config", "client_secret"]} label={helpLabel("App Secret", sourceFieldHelp.clientSecret)} rules={[{ required: selectedProvider?.requires_secret }]}>
              <Input.Password />
            </Form.Item>
            <Form.Item name={["config", "initial_password"]} label={helpLabel("DSM 初始密码", sourceFieldHelp.initialPassword)} initialValue="123456" rules={[{ required: true }]}>
              <Input.Password />
            </Form.Item>
            <Form.Item name="login_enabled" label={helpLabel("登录", sourceFieldHelp.loginEnabled)} valuePropName="checked" initialValue>
              <Switch />
            </Form.Item>
            <Form.Item name="directory_sync_enabled" label={helpLabel("同步", sourceFieldHelp.syncEnabled)} valuePropName="checked" initialValue>
              <Switch />
            </Form.Item>
            <Form.Item name={["config", "sync_interval_minutes"]} label={helpLabel("定期同步(分钟)", sourceFieldHelp.syncInterval)} initialValue={0}>
              <InputNumber min={0} step={5} />
            </Form.Item>
          </div>
          <Flex justify="end">
            <Button type="primary" htmlType="submit" loading={creating}>保存</Button>
          </Flex>
        </Form>
      </Modal>
    </Space>
  );
}

function SourceDetail({
  source,
  onBack,
  activeTab,
  onTabChange,
  onUpdated,
  onDeleted
}: {
  source: ProviderItem;
  onBack: () => void;
  activeTab: SourceTabKey;
  onTabChange: (tab: SourceTabKey) => void;
  onUpdated: (source: ProviderItem) => void;
  onDeleted: () => void;
}) {
  const { modal, message } = AntApp.useApp();
  const [form] = Form.useForm<ProviderUpsert>();
  const [syncError, setSyncError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [sourceLoginLoading, setSourceLoginLoading] = useState(false);
  const [sourceSyncLoading, setSourceSyncLoading] = useState(false);
  const [resettingSyncData, setResettingSyncData] = useState(false);
  const [deletingSource, setDeletingSource] = useState(false);
  const [syncApplying, setSyncApplying] = useState(false);
  const [accountLoginAction, setAccountLoginAction] = useState<string | null>(null);
  const [userQuery, setUserQuery] = useState("");
  const [groupQuery, setGroupQuery] = useState("");
  const [syncLogQuery, setSyncLogQuery] = useState("");
  const [auditQuery, setAuditQuery] = useState("");
  const [userStatusFilter, setUserStatusFilter] = useState("all");
  const [groupStatusFilter, setGroupStatusFilter] = useState("all");
  const [syncStatusFilter, setSyncStatusFilter] = useState("all");
  const [auditResultFilter, setAuditResultFilter] = useState("all");
  const [accountPage, setAccountPage] = useState(1);
  const [groupPage, setGroupPage] = useState(1);
  const [syncLogPage, setSyncLogPage] = useState(1);
  const [auditPage, setAuditPage] = useState(1);
  const [selectedAccountIDs, setSelectedAccountIDs] = useState<string[]>([]);
  const [accountConflictDrafts, setAccountConflictDrafts] = useState<Record<string, string>>({});
  const [groupConflictDrafts, setGroupConflictDrafts] = useState<Record<string, string>>({});
  const [savingConflictKey, setSavingConflictKey] = useState<string | null>(null);
  const [conflictModalOpen, setConflictModalOpen] = useState(false);
  const [conflictPromptSource, setConflictPromptSource] = useState<string | null>(null);
  const accounts = useAsyncData(() => api.listDSMAccounts({ provider: source.slug, q: userQuery, status: userStatusFilter, page: accountPage, limit: sourceTablePageSize }), [source.slug, userQuery, userStatusFilter, accountPage]);
  const groups = useAsyncData(() => api.listDSMGroups({ provider: source.slug, q: groupQuery, status: groupStatusFilter, page: groupPage, limit: sourceTablePageSize }), [source.slug, groupQuery, groupStatusFilter, groupPage]);
  const conflictAccountData = useAsyncData(() => api.listAllDSMAccounts({ provider: source.slug, status: "conflict" }), [source.slug]);
  const conflictGroupData = useAsyncData(() => api.listAllDSMGroups({ provider: source.slug, status: "conflict" }), [source.slug]);
  const members = useAsyncData(() => api.listGroupMembers(source.slug), [source.slug]);
  const syncLogs = useAsyncData(() => api.sourceSyncLogs(source.slug, { q: syncLogQuery, status: syncStatusFilter, page: syncLogPage, limit: sourceTablePageSize }), [source.slug, syncLogQuery, syncStatusFilter, syncLogPage]);
  const auditLogs = useAsyncData(() => api.loginAuditLogs({ provider: source.slug, q: auditQuery, result: auditResultFilter, page: auditPage, limit: sourceTablePageSize }), [source.slug, auditQuery, auditResultFilter, auditPage]);

  useEffect(() => {
    setAccountPage(1);
  }, [source.slug, userQuery, userStatusFilter]);

  useEffect(() => {
    setGroupPage(1);
  }, [source.slug, groupQuery, groupStatusFilter]);

  useEffect(() => {
    setSyncLogPage(1);
  }, [source.slug, syncLogQuery, syncStatusFilter]);

  useEffect(() => {
    setAuditPage(1);
  }, [source.slug, auditQuery, auditResultFilter]);

  useEffect(() => {
    form.setFieldsValue({
      display_name: source.display_name,
      enabled: source.enabled,
      login_enabled: source.login_enabled,
      directory_sync_enabled: source.directory_sync_enabled,
      config: {
        client_id: source.config?.client_id,
        sync_interval_minutes: source.config?.sync_interval_minutes ?? 0,
        disable_missing_users: source.config?.disable_missing_users ?? true,
        deactivate_missing_data: source.config?.deactivate_missing_data ?? true,
        initial_password: source.config?.initial_password ?? "123456"
      }
    });
  }, [form, source]);

  const launchURL = source.login_url ?? `${window.location.origin}/idp/${source.slug}/launch`;
  const callbackURL = source.callback_url ?? `${window.location.origin}/idp/${source.slug}/callback`;

  async function copyAddress(label: "Launch" | "Callback", url: string) {
    try {
      await navigator.clipboard.writeText(url);
      modal.success({
        title: `${label} 地址已复制`,
        content: label === "Launch"
          ? "请粘贴到飞书开放平台网页应用的入口地址/桌面端主页配置位置。"
          : "请粘贴到飞书开放平台 OAuth 重定向 URL / 回调地址配置位置。"
      });
    } catch {
      message.error("复制失败");
    }
  }

  async function save(values: ProviderUpsert) {
    setSaving(true);
    try {
      if (!values.config?.client_secret) {
        delete values.config?.client_secret;
      }
      const updated = await api.updateProvider(source.slug, values);
      onUpdated(updated);
      message.success("已保存");
    } catch (err) {
      message.error(err instanceof Error ? err.message : "保存失败");
    } finally {
      setSaving(false);
    }
  }

  async function setSourceLoginEnabled(loginEnabled: boolean) {
    setSourceLoginLoading(true);
    try {
      const updated = await api.updateProvider(source.slug, { login_enabled: loginEnabled });
      onUpdated(updated);
      form.setFieldValue("login_enabled", loginEnabled);
      message.success(loginEnabled ? "登录已恢复" : "登录已暂停");
    } catch (err) {
      message.error(err instanceof Error ? err.message : "保存失败");
    } finally {
      setSourceLoginLoading(false);
    }
  }

  async function setSourceSyncEnabled(syncEnabled: boolean) {
    setSourceSyncLoading(true);
    try {
      const updated = await api.updateProvider(source.slug, { directory_sync_enabled: syncEnabled });
      onUpdated(updated);
      form.setFieldValue("directory_sync_enabled", syncEnabled);
      message.success(syncEnabled ? "同步已恢复" : "同步已暂停");
    } catch (err) {
      message.error(err instanceof Error ? err.message : "保存失败");
    } finally {
      setSourceSyncLoading(false);
    }
  }

  async function refreshAll() {
    await Promise.all([
      accounts.reloadWithResult({ silent: true }),
      groups.reloadWithResult({ silent: true }),
      conflictAccountData.reloadWithResult({ silent: true }),
      conflictGroupData.reloadWithResult({ silent: true }),
      members.reloadWithResult({ silent: true }),
      syncLogs.reloadWithResult({ silent: true }),
      auditLogs.reloadWithResult({ silent: true })
    ]);
  }

  const memberRows = members.data?.items ?? [];
  const groupsByAccountID = useMemo(() => {
    const result = new Map<string, GroupMember[]>();
    for (const member of memberRows) {
      const rows = result.get(member.dsm_account_id) ?? [];
      rows.push(member);
      result.set(member.dsm_account_id, rows);
    }
    return result;
  }, [memberRows]);
  const membersByGroupID = useMemo(() => {
    const result = new Map<string, GroupMember[]>();
    for (const member of memberRows) {
      const rows = result.get(member.dsm_group_id) ?? [];
      rows.push(member);
      result.set(member.dsm_group_id, rows);
    }
    return result;
  }, [memberRows]);
  const enrichAccounts = useCallback((items: DSMAccount[]) => {
    return items
      .map((account) => {
        const records = (groupsByAccountID.get(account.id) ?? []).slice().sort((a, b) => a.dsm_groupname.localeCompare(b.dsm_groupname));
        return { ...account, groups: records.map((member) => member.dsm_groupname), member_records: records };
      }) as EnrichedDSMAccount[];
  }, [groupsByAccountID]);
  const enrichedAccountRows = useMemo(() => {
    return enrichAccounts(accounts.data?.items ?? []);
  }, [accounts.data?.items, enrichAccounts]);
  const accountRows = useMemo(() => {
    return enrichedAccountRows
      .filter((account) => userStatusFilter === "all" || String(account.provision_status) === userStatusFilter || (userStatusFilter === "disabled_login" && !account.allow_login))
      .filter((account) => includesQuery([account.dsm_username, account.display_name, account.primary_email, account.external_emails, account.mobile_masked, account.external_subjects, account.conflict_reason, account.app_identity_id, account.provision_status, ...account.groups], userQuery));
  }, [enrichedAccountRows, userQuery, userStatusFilter]);
  const enrichGroups = useCallback((items: DSMGroup[]) => {
    return items
      .map((group) => {
        const records = (membersByGroupID.get(group.id) ?? []).slice().sort((a, b) => a.dsm_username.localeCompare(b.dsm_username));
        return { ...group, members: records.map((member) => member.dsm_username), member_records: records };
      });
  }, [membersByGroupID]);
  const enrichedGroupRows = useMemo(() => {
    return enrichGroups(groups.data?.items ?? []);
  }, [groups.data?.items, enrichGroups]);
  const groupRows = useMemo(() => {
    return enrichedGroupRows
      .filter((group) => groupStatusFilter === "all" || String(group.provision_status) === groupStatusFilter)
      .filter((group) => includesQuery([group.dsm_groupname, group.provider_group_name, group.provider_group_path, group.provision_status, group.conflict_reason, ...group.members], groupQuery));
  }, [enrichedGroupRows, groupQuery, groupStatusFilter]);
  const conflictAccounts = useMemo(() => enrichAccounts(conflictAccountData.data?.items ?? []), [conflictAccountData.data?.items, enrichAccounts]);
  const feishuDuplicateAccountGroups = useMemo(() => {
    const groupsByName = new Map<string, EnrichedDSMAccount[]>();
    for (const account of conflictAccounts) {
      if (accountConflictKind(account) !== "feishu_duplicate") {
        continue;
      }
      const name = (account.display_name || account.dsm_username || "未命名用户").trim();
      const rows = groupsByName.get(name) ?? [];
      rows.push(account);
      groupsByName.set(name, rows);
    }
    return Array.from(groupsByName.entries())
      .map(([name, items]) => ({ name, items: items.slice().sort((a, b) => a.dsm_username.localeCompare(b.dsm_username)) }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [conflictAccounts]);
  const nonFeishuDuplicateConflictAccounts = useMemo(() => {
    return conflictAccounts.filter((account) => accountConflictKind(account) !== "feishu_duplicate");
  }, [conflictAccounts]);
  const conflictGroups = useMemo(() => enrichGroups(conflictGroupData.data?.items ?? []), [conflictGroupData.data?.items, enrichGroups]);
  const hasConflicts = conflictAccounts.length > 0 || conflictGroups.length > 0;
  const currentFeishuDuplicateGroup = feishuDuplicateAccountGroups[0];
  const conflictStepCount = (conflictGroups.length > 0 ? 1 : 0) + feishuDuplicateAccountGroups.length + (nonFeishuDuplicateConflictAccounts.length > 0 ? 1 : 0);
  const filteredSyncLogs = useMemo(() => {
    return (syncLogs.data?.items ?? [])
      .filter((record) => syncStatusFilter === "all" || record.status === syncStatusFilter)
      .filter((record) =>
        includesQuery([record.created_at, formatLocalTime(record.created_at), record.object_type, record.action, record.dsm_name, record.status, record.error, record.before_state, record.after_state], syncLogQuery)
      );
  }, [syncLogs.data?.items, syncLogQuery, syncStatusFilter]);
  const filteredAuditLogs = useMemo(() => {
    return (auditLogs.data?.items ?? [])
      .filter((record) => auditResultFilter === "all" || record.result === auditResultFilter)
      .filter((record) =>
        includesQuery([record.created_at, formatLocalTime(record.created_at), source.display_name, record.provider_slug, record.dsm_username, record.result, record.error_code, record.ip_address], auditQuery)
      );
  }, [auditLogs.data?.items, auditQuery, auditResultFilter, source.display_name]);
  const sourceStats = useMemo(() => {
    const accountItems = accounts.data?.items ?? [];
    const groupItems = groups.data?.items ?? [];
    const memberItems = members.data?.items ?? [];
    const syncItems = syncLogs.data?.items ?? [];
    const auditItems = auditLogs.data?.items ?? [];
    return {
      users: accounts.data?.total ?? accountItems.length,
      disabledLogin: accountItems.filter((item) => !item.allow_login).length,
      pendingUsers: accountItems.filter((item) => item.provision_status === "pending").length,
      accountConflicts: conflictAccountData.data?.total ?? conflictAccounts.length,
      groups: groups.data?.total ?? groupItems.length,
      pendingGroups: groupItems.filter((item) => item.provision_status === "pending").length,
      conflicts: conflictGroupData.data?.total ?? conflictGroups.length,
      members: memberItems.length,
      syncLogs: syncLogs.data?.total ?? syncItems.length,
      syncFailed: syncItems.filter((item) => item.status === "failed" || item.status === "fail").length,
      loginAudits: auditLogs.data?.total ?? auditItems.length,
      loginFailed: auditItems.filter((item) => item.result === "failed" || item.result === "fail").length
    };
  }, [accounts.data?.items, accounts.data?.total, auditLogs.data?.items, auditLogs.data?.total, conflictAccountData.data?.total, conflictAccounts.length, conflictGroupData.data?.total, conflictGroups.length, groups.data?.items, groups.data?.total, members.data?.items, syncLogs.data?.items, syncLogs.data?.total]);

  useEffect(() => {
    if (!conflictAccountData.loading && !conflictGroupData.loading && hasConflicts && conflictPromptSource !== source.slug) {
      setConflictModalOpen(true);
      setConflictPromptSource(source.slug);
    }
    if (!hasConflicts) {
      setConflictModalOpen(false);
    }
  }, [conflictAccountData.loading, conflictGroupData.loading, conflictPromptSource, hasConflicts, source.slug]);

  function apply() {
    modal.confirm({
      title: `同步 ${source.display_name}`,
      okText: "同步",
      cancelText: "取消",
      onOk: async () => {
        setSyncApplying(true);
        setSyncError(null);
        try {
          await api.syncApply(source.slug);
          await refreshAll();
          message.success("同步完成");
        } catch (err) {
          setSyncError(err instanceof Error ? err.message : "同步失败");
        } finally {
          setSyncApplying(false);
        }
      }
    });
  }

  function resetSyncData() {
    modal.confirm({
      title: `清理 ${source.display_name}`,
      okText: "清理",
      cancelText: "取消",
      okButtonProps: { danger: true },
      onOk: async () => {
        setResettingSyncData(true);
        setSyncError(null);
        try {
          await api.resetProviderSyncData(source.slug);
          await refreshAll();
          message.success("已清理");
        } catch (err) {
          message.error(err instanceof Error ? err.message : "清理失败");
        } finally {
          setResettingSyncData(false);
        }
      }
    });
  }

  function deleteSource() {
    modal.confirm({
      title: `删除 ${source.display_name}`,
      content: "会先禁用该身份源对应的 DSM 用户，然后删除身份源配置、本地同步映射和日志。此操作不可撤销。",
      okText: "删除",
      cancelText: "取消",
      okButtonProps: { danger: true },
      onOk: async () => {
        setDeletingSource(true);
        try {
          await api.deleteProvider(source.slug);
          message.success("已删除身份源");
          onDeleted();
        } catch (err) {
          message.error(err instanceof Error ? err.message : "删除失败");
        } finally {
          setDeletingSource(false);
        }
      }
    });
  }

  const provisionAccount = (record: DSMAccount) => {
    modal.confirm({
      title: `开通 ${record.dsm_username}`,
      okText: "开通",
      cancelText: "取消",
      onOk: async () => {
        await api.provisionAccount(record.id);
        await accounts.reloadWithResult({ silent: true });
      }
    });
  };

  async function provisionAccountAfterRename(id: string) {
    const result = await api.provisionAccount(id);
    await Promise.all([
      accounts.reloadWithResult({ silent: true }),
      conflictAccountData.reloadWithResult({ silent: true }),
      members.reloadWithResult({ silent: true })
    ]);
    return result;
  }

  const editAccountUsername = (record: DSMAccount) => {
    let nextUsername = record.dsm_username;
    modal.confirm({
      title: `修改 ${record.display_name || record.dsm_username} 的 DSM 用户名`,
      okText: "保存",
      cancelText: "取消",
      content: (
        <Space direction="vertical" style={{ width: "100%" }}>
          <Typography.Text type="secondary">飞书身份：{record.external_subjects || record.app_identity_id}</Typography.Text>
          {accountContactText(record) && <Typography.Text type="secondary">邮箱 / 手机号：{accountContactText(record)}</Typography.Text>}
          {record.conflict_reason && <Alert type="warning" showIcon message={record.conflict_reason} />}
          <Input defaultValue={record.dsm_username} onChange={(event) => { nextUsername = event.target.value; }} />
        </Space>
      ),
      onOk: async () => {
        await api.setDSMAccountUsername(record.id, nextUsername);
        const result = await provisionAccountAfterRename(record.id);
        message.success(result.provision_status === "linked_existing" ? "已保存并关联已有 DSM 用户" : "已保存并开通 DSM 用户");
      }
    });
  };

  const provisionGroup = (record: DSMGroup) => {
    modal.confirm({
      title: `开通 ${record.dsm_groupname}`,
      okText: "开通",
      cancelText: "取消",
      onOk: async () => {
        await api.provisionGroup(record.id);
        await groups.reloadWithResult({ silent: true });
      }
    });
  };

  async function provisionGroupAfterRename(id: string) {
    const result = await api.provisionGroup(id);
    await Promise.all([
      groups.reloadWithResult({ silent: true }),
      conflictGroupData.reloadWithResult({ silent: true }),
      members.reloadWithResult({ silent: true })
    ]);
    return result;
  }

  const editGroupName = (record: DSMGroup) => {
    let nextGroupname = record.dsm_groupname;
    modal.confirm({
      title: "修改 DSM 部门组名",
      okText: "保存",
      cancelText: "取消",
      content: (
        <Space direction="vertical" style={{ width: "100%" }}>
          <Typography.Text type="secondary">飞书部门：{record.provider_group_path || record.provider_group_name || record.dsm_groupname}</Typography.Text>
          {record.conflict_reason && <Alert type="warning" showIcon message={record.conflict_reason} />}
          <Input defaultValue={record.dsm_groupname} onChange={(event) => { nextGroupname = event.target.value; }} />
        </Space>
      ),
      onOk: async () => {
        await api.setDSMGroupName(record.id, nextGroupname);
        const result = await provisionGroupAfterRename(record.id);
        message.success(result.provision_status === "created" ? "已保存并开通 DSM 部门组" : "已保存，空部门会在成员同步时创建");
      }
    });
  };

  function validateUniqueDrafts<T extends { id: string }>(items: T[], valueOf: (item: T) => string, emptyMessage: string, duplicateMessage: string) {
    const seen = new Set<string>();
    for (const item of items) {
      const value = valueOf(item).trim();
      if (!value) {
        message.error(emptyMessage);
        return false;
      }
      const norm = value.toLowerCase();
      if (seen.has(norm)) {
        message.error(duplicateMessage);
        return false;
      }
      seen.add(norm);
    }
    return true;
  }

  async function saveAccountConflictBatch(records: EnrichedDSMAccount[], batchKey: string) {
    if (!validateUniqueDrafts(
      records,
      (record) => accountConflictDrafts[record.id] ?? record.dsm_username,
      "DSM 用户名不能为空",
      "同一批用户里不能使用相同 DSM 用户名"
    )) {
      return;
    }
    setSavingConflictKey(batchKey);
    try {
      let linkedExisting = 0;
      for (const record of records) {
        const nextUsername = (accountConflictDrafts[record.id] ?? record.dsm_username).trim();
        await api.setDSMAccountUsername(record.id, nextUsername);
        const result = await provisionAccountAfterRename(record.id);
        if (result.provision_status === "linked_existing") {
          linkedExisting += 1;
        }
      }
      setAccountConflictDrafts((drafts) => {
        const next = { ...drafts };
        for (const record of records) {
          delete next[record.id];
        }
        return next;
      });
      message.success(linkedExisting > 0 ? `已保存 ${records.length} 个用户，其中 ${linkedExisting} 个关联已有 DSM 用户` : `已保存并开通 ${records.length} 个 DSM 用户`);
    } catch (err) {
      await Promise.all([
        accounts.reloadWithResult({ silent: true }),
        conflictAccountData.reloadWithResult({ silent: true }),
        members.reloadWithResult({ silent: true })
      ]);
      message.error(err instanceof Error ? err.message : "保存或开通失败，请继续修改或检查 Helper 权限");
    } finally {
      setSavingConflictKey(null);
    }
  }

  async function saveGroupConflictBatch(records: DSMGroup[], batchKey: string) {
    if (!validateUniqueDrafts(
      records,
      (record) => groupConflictDrafts[record.id] ?? record.dsm_groupname,
      "DSM 部门组名不能为空",
      "同一批部门里不能使用相同 DSM 部门组名"
    )) {
      return;
    }
    setSavingConflictKey(batchKey);
    try {
      let pendingEmptyGroups = 0;
      for (const record of records) {
        const nextGroupname = (groupConflictDrafts[record.id] ?? record.dsm_groupname).trim();
        await api.setDSMGroupName(record.id, nextGroupname);
        const result = await provisionGroupAfterRename(record.id);
        if (result.provision_status !== "created") {
          pendingEmptyGroups += 1;
        }
      }
      setGroupConflictDrafts((drafts) => {
        const next = { ...drafts };
        for (const record of records) {
          delete next[record.id];
        }
        return next;
      });
      message.success(pendingEmptyGroups > 0 ? `已保存 ${records.length} 个部门，其中 ${pendingEmptyGroups} 个空部门会在成员同步时创建` : `已保存并开通 ${records.length} 个 DSM 部门组`);
    } catch (err) {
      await Promise.all([
        groups.reloadWithResult({ silent: true }),
        conflictGroupData.reloadWithResult({ silent: true }),
        members.reloadWithResult({ silent: true })
      ]);
      message.error(err instanceof Error ? err.message : "保存或开通失败，请继续修改或检查 Helper 权限");
    } finally {
      setSavingConflictKey(null);
    }
  }

  const accountConflictColumns: ColumnsType<EnrichedDSMAccount> = [
    { title: "冲突类型", width: 130, render: (_, record) => (
      <Tag color={accountConflictKind(record) === "dsm_existing" ? "volcano" : accountConflictKind(record) === "feishu_duplicate" ? "error" : "warning"}>
        {accountConflictLabel(record)}
      </Tag>
    ) },
    { title: "飞书用户", width: 210, render: (_, record) => <IdentityCell primary={record.display_name || "-"} secondary={record.external_subjects || record.app_identity_id} /> },
    { title: "邮箱", width: 210, ellipsis: true, render: (_, record) => record.primary_email || record.external_emails || "-" },
    { title: "手机号", width: 130, ellipsis: true, render: (_, record) => record.mobile_masked || "-" },
    { title: "部门", width: 220, render: (_, record) => <EntityList values={record.groups} limit={3} /> },
    { title: "DSM 用户名", width: 220, render: (_, record) => (
      <Input
        value={accountConflictDrafts[record.id] ?? record.dsm_username}
        onChange={(event) => setAccountConflictDrafts((drafts) => ({ ...drafts, [record.id]: event.target.value }))}
      />
    ) },
  ];

  async function setAccountLogin(ids: string[], allowLogin: boolean) {
    if (ids.length === 0) {
      return;
    }
    const actionKey = accountLoginActionKey(ids, allowLogin);
    setAccountLoginAction(actionKey);
    try {
      if (ids.length === 1) {
        await api.setDSMAccountLogin(ids[0], allowLogin);
      } else {
        await api.setDSMAccountsLogin(ids, allowLogin);
      }
      setSelectedAccountIDs([]);
      await accounts.reloadWithResult({ silent: true });
      message.success(allowLogin ? "已允许登录" : "已禁止登录");
    } catch (err) {
      message.error(err instanceof Error ? err.message : "保存失败");
    } finally {
      setAccountLoginAction(null);
    }
  }

  function accountLoginActionKey(ids: string[], allowLogin: boolean) {
    return `${allowLogin ? "allow" : "deny"}:${ids.slice().sort().join(",")}`;
  }

  return (
    <Space direction="vertical" size={16} className="page">
      <PageTitle
        title={source.display_name}
        extra={
          <Space>
            <Button icon={<ArrowLeftOutlined />} onClick={onBack}>返回</Button>
            {source.login_enabled ? (
              <Button onClick={() => void setSourceLoginEnabled(false)} loading={sourceLoginLoading}>暂停登录</Button>
            ) : (
              <Button type="primary" onClick={() => void setSourceLoginEnabled(true)} loading={sourceLoginLoading}>恢复登录</Button>
            )}
            {source.directory_sync_enabled ? (
              <Button onClick={() => void setSourceSyncEnabled(false)} loading={sourceSyncLoading}>暂停同步</Button>
            ) : (
              <Button type="primary" onClick={() => void setSourceSyncEnabled(true)} loading={sourceSyncLoading}>恢复同步</Button>
            )}
            <Button danger onClick={resetSyncData} loading={resettingSyncData}>清理</Button>
            <Button danger icon={<DeleteOutlined />} onClick={deleteSource} loading={deletingSource}>删除</Button>
            <Button type="primary" onClick={apply} loading={syncApplying} disabled={!source.enabled || !source.directory_sync_enabled}>同步</Button>
          </Space>
        }
      />
      {syncError && <Alert type="error" showIcon closable message={syncError} onClose={() => setSyncError(null)} />}
      <Modal
        title={`待处理冲突：${source.display_name}`}
        open={conflictModalOpen}
        width="min(1480px, calc(100vw - 32px))"
        style={{ top: 24 }}
        okText="关闭"
        cancelButtonProps={{ style: { display: "none" } }}
        onOk={() => setConflictModalOpen(false)}
        onCancel={() => setConflictModalOpen(false)}
      >
        <Space direction="vertical" size={16} className="conflict-modal-body">
          <Alert
            type="error"
            showIcon
            message={`还有 ${conflictGroups.length} 个部门冲突、${conflictAccounts.length} 个用户冲突未处理`}
            description="请按当前卡片处理一组冲突；保存成功会自动尝试开通，然后显示下一组。"
          />
          {conflictGroups.length > 0 && (
            <Card
              className="conflict-step-card"
              title={<Space><span>第 1 / {conflictStepCount} 组：部门冲突</span><Tag color="error">{conflictGroups.length}</Tag></Space>}
              extra={(
                <Button
                  type="primary"
                  loading={savingConflictKey === "groups:all"}
                  onClick={() => void saveGroupConflictBatch(conflictGroups, "groups:all")}
                >
                  保存并开通本组
                </Button>
              )}
            >
              <Table
                size="small"
                rowKey="id"
                dataSource={conflictGroups}
                pagination={{ pageSize: 6, hideOnSinglePage: true }}
                rowClassName="conflict-row"
                scroll={{ x: 1180 }}
                columns={[
                  { title: "飞书部门", width: 260, render: (_, record: DSMGroup) => <IdentityCell primary={record.provider_group_name || "-"} secondary={record.provider_group_path || undefined} /> },
                  { title: "当前 DSM 部门组名", width: 260, render: (_, record: DSMGroup) => (
                    <Input
                      value={groupConflictDrafts[record.id] ?? record.dsm_groupname}
                      onChange={(event) => setGroupConflictDrafts((drafts) => ({ ...drafts, [record.id]: event.target.value }))}
                    />
                  ) },
                  { title: "冲突原因", dataIndex: "conflict_reason", ellipsis: true, render: (value) => value || "-" }
                ]}
              />
            </Card>
          )}
          {conflictGroups.length === 0 && currentFeishuDuplicateGroup && (
            <Card
              className="conflict-step-card"
              title={(
                <Space>
                  <span>第 1 / {conflictStepCount} 组：飞书内重名用户</span>
                  <Tag color="error">{currentFeishuDuplicateGroup.items.length} 个同名用户</Tag>
                </Space>
              )}
              extra={(
                <Button
                  type="primary"
                  loading={savingConflictKey === `accounts:feishu:${currentFeishuDuplicateGroup.name}`}
                  onClick={() => void saveAccountConflictBatch(currentFeishuDuplicateGroup.items, `accounts:feishu:${currentFeishuDuplicateGroup.name}`)}
                >
                  保存并开通本组
                </Button>
              )}
            >
              <div className="conflict-user-group">
                <div className="conflict-user-group-head">
                  <strong>飞书姓名：{currentFeishuDuplicateGroup.name}</strong>
                </div>
                <Table
                  size="small"
                  rowKey="id"
                  dataSource={currentFeishuDuplicateGroup.items}
                  pagination={false}
                  rowClassName="conflict-row"
                  scroll={{ x: 1320 }}
                  columns={accountConflictColumns}
                />
              </div>
            </Card>
          )}
          {conflictGroups.length === 0 && !currentFeishuDuplicateGroup && nonFeishuDuplicateConflictAccounts.length > 0 && (
            <Card
              className="conflict-step-card"
              title={<Space><span>第 1 / {conflictStepCount} 组：其他用户命名冲突</span><Tag color="volcano">{nonFeishuDuplicateConflictAccounts.length}</Tag></Space>}
              extra={(
                <Button
                  type="primary"
                  loading={savingConflictKey === "accounts:other"}
                  onClick={() => void saveAccountConflictBatch(nonFeishuDuplicateConflictAccounts, "accounts:other")}
                >
                  保存并开通本组
                </Button>
              )}
            >
              <Table
                size="small"
                rowKey="id"
                dataSource={nonFeishuDuplicateConflictAccounts}
                pagination={{ pageSize: 6, hideOnSinglePage: true }}
                rowClassName="conflict-row"
                scroll={{ x: 1320 }}
                columns={accountConflictColumns}
              />
            </Card>
          )}
        </Space>
      </Modal>
      <Tabs
        activeKey={activeTab}
        onChange={(key) => {
          if (sourceTabKeys.includes(key as SourceTabKey)) {
            onTabChange(key as SourceTabKey);
          }
        }}
        items={[
          {
            key: "addresses",
            label: "飞书",
            children: (
              <Space direction="vertical" size={16} className="page">
                <Card title="地址" className="module-card">
                  <div className="address-copy-list">
                    <div className="launch-copy-row">
                      <button type="button" className="copy-row" onClick={() => void copyAddress("Launch", launchURL)}>
                        <span>Launch</span>
                        <strong>{launchURL}</strong>
                      </button>
                      <Button icon={<CopyOutlined />} onClick={() => void copyAddress("Launch", launchURL)}>
                        复制
                      </Button>
                    </div>
                    <div className="launch-copy-row">
                      <button type="button" className="copy-row" onClick={() => void copyAddress("Callback", callbackURL)}>
                        <span>Callback</span>
                        <strong>{callbackURL}</strong>
                      </button>
                      <Button icon={<CopyOutlined />} onClick={() => void copyAddress("Callback", callbackURL)}>
                        复制
                      </Button>
                    </div>
                  </div>
                </Card>
                <Card title="身份源" className="module-card">
                  <Form form={form} layout="vertical" onFinish={(values) => void save(values)} disabled={saving}>
                    <div className="form-grid">
                      <Form.Item name="display_name" label={helpLabel("名称", sourceFieldHelp.displayName)} rules={[{ required: true }]}><Input /></Form.Item>
                      <Form.Item name={["config", "client_id"]} label={helpLabel("飞书 App ID", sourceFieldHelp.clientID)} rules={[{ required: true }]}><Input /></Form.Item>
                      <Form.Item name={["config", "client_secret"]} label={helpLabel("飞书 App Secret", sourceFieldHelp.clientSecret)}><Input.Password /></Form.Item>
                      <Form.Item name={["config", "initial_password"]} label={helpLabel("DSM 初始密码", sourceFieldHelp.initialPassword)} rules={[{ required: true }]}><Input.Password /></Form.Item>
                      <Form.Item name="enabled" label={helpLabel("启用", sourceFieldHelp.enabled)} valuePropName="checked"><Switch /></Form.Item>
                      <Form.Item name="login_enabled" label={helpLabel("登录", sourceFieldHelp.loginEnabled)} valuePropName="checked"><Switch /></Form.Item>
                      <Form.Item name="directory_sync_enabled" label={helpLabel("同步", sourceFieldHelp.syncEnabled)} valuePropName="checked"><Switch /></Form.Item>
                      <Form.Item name={["config", "sync_interval_minutes"]} label={helpLabel("定期同步(分钟)", sourceFieldHelp.syncInterval)}><InputNumber min={0} step={5} /></Form.Item>
                      <Form.Item name={["config", "disable_missing_users"]} label={helpLabel("禁用缺失用户", sourceFieldHelp.disableMissingUsers)} valuePropName="checked"><Switch /></Form.Item>
                    </div>
                    <Flex justify="end"><Button type="primary" htmlType="submit" loading={saving}>保存</Button></Flex>
                  </Form>
                </Card>
              </Space>
            )
          },
          {
            key: "users",
            label: "用户",
            children: (
              <SourceTable
                error={accounts.error}
                reload={async () => {
                  await accounts.reloadWithResult({ silent: true });
                }}
                metrics={
                  <MetricStrip
                    items={[
                      { label: "用户", value: sourceStats.users },
                      { label: "待开通", value: sourceStats.pendingUsers, tone: sourceStats.pendingUsers ? "warning" : "default" },
                      { label: "冲突", value: sourceStats.accountConflicts, tone: sourceStats.accountConflicts ? "danger" : "default" },
                      { label: "禁止登录", value: sourceStats.disabledLogin, tone: sourceStats.disabledLogin ? "danger" : "default" }
                    ]}
                  />
                }
                toolbar={
                  <Space wrap className="toolbar-content">
                    <Input.Search allowClear placeholder="搜索用户、身份 ID、部门" value={userQuery} onChange={(event) => setUserQuery(event.target.value)} />
                    <Segmented
                      value={userStatusFilter}
                      onChange={(value) => setUserStatusFilter(String(value))}
                      options={[
                        { label: "全部", value: "all" },
                        { label: "待处理", value: "pending" },
                        { label: "已创建", value: "created" },
                        { label: "禁止登录", value: "disabled_login" },
                        { label: "冲突", value: "conflict" }
                      ]}
                    />
                    {selectedAccountIDs.length > 0 && (
                      <>
                        <Button loading={accountLoginAction === accountLoginActionKey(selectedAccountIDs, true)} onClick={() => void setAccountLogin(selectedAccountIDs, true)}>批量允许登录</Button>
                        <Button danger loading={accountLoginAction === accountLoginActionKey(selectedAccountIDs, false)} onClick={() => void setAccountLogin(selectedAccountIDs, false)}>批量禁止登录</Button>
                      </>
                    )}
                  </Space>
                }
                table={
                  <Table
                    rowKey="id"
                    loading={accounts.loading}
                    dataSource={accountRows}
                    pagination={{
                      current: accountPage,
                      pageSize: sourceTablePageSize,
                      total: accounts.data?.total ?? 0,
                      showSizeChanger: false,
                      onChange: setAccountPage
                    }}
                    rowClassName={(record) => record.provision_status === "conflict" ? "conflict-row" : ""}
                    rowSelection={{
                      selectedRowKeys: selectedAccountIDs,
                      onChange: (keys) => setSelectedAccountIDs(keys.map(String))
                    }}
                    expandable={{
                      expandedRowRender: (record) => (
                        <div className="entity-panel">
                          <div className="entity-panel-head">
                            <strong>{record.dsm_username}</strong>
                            <span>{record.member_records.length} 条成员关系</span>
                          </div>
                          <Table
                            rowKey="id"
                            size="small"
                            pagination={false}
                            dataSource={record.member_records}
                            columns={[
                              { title: "DSM 部门", dataIndex: "dsm_groupname", ellipsis: true },
                              { title: "关系状态", dataIndex: "provision_status", width: 120, render: statusTag }
                            ]}
                          />
                        </div>
                      ),
                      rowExpandable: (record) => record.member_records.length > 0
                    }}
                    columns={[
                      { title: "用户", dataIndex: "dsm_username", ellipsis: true, render: (_, record) => <IdentityCell primary={record.dsm_username} secondary={record.conflict_reason || record.app_identity_id} /> },
                      { title: "飞书信息", width: 260, render: (_, record: DSMAccount) => <IdentityCell primary={record.display_name || "-"} secondary={accountContactText(record) || record.external_subjects || undefined} /> },
                      { title: "部门数", dataIndex: "groups", width: 100, render: (value: string[]) => <RelationCount value={value.length} label="部门" /> },
                      { title: "所属部门", dataIndex: "groups", render: (value: string[]) => <EntityList values={value} /> },
                      { title: "登录", dataIndex: "allow_login", width: 100, render: (value) => value ? <Tag color="success">允许</Tag> : <Tag color="error">禁止</Tag> },
                      { title: "状态", dataIndex: "provision_status", width: 120, render: statusTag },
                      {
                        title: "操作",
                        width: 220,
                        render: (_, record: DSMAccount) => (
                          <Space>
                            {record.provision_status === "conflict" && <Button size="small" onClick={() => editAccountUsername(record)}>修改用户名</Button>}
                            {record.provision_status === "pending" && <Button size="small" onClick={() => provisionAccount(record)}>开通</Button>}
                            {record.allow_login ? (
                              <Button size="small" danger loading={accountLoginAction === accountLoginActionKey([record.id], false)} onClick={() => void setAccountLogin([record.id], false)}>禁止登录</Button>
                            ) : (
                              <Button size="small" loading={accountLoginAction === accountLoginActionKey([record.id], true)} onClick={() => void setAccountLogin([record.id], true)}>允许登录</Button>
                            )}
                          </Space>
                        )
                      }
                    ]}
                  />
                }
              />
            )
          },
          {
            key: "groups",
            label: "部门",
            children: (
              <SourceTable
                error={groups.error}
                reload={async () => {
                  await groups.reloadWithResult({ silent: true });
                }}
                metrics={
                  <MetricStrip
                    items={[
                      { label: "部门", value: sourceStats.groups },
                      { label: "成员关系", value: sourceStats.members },
                      { label: "待开通", value: sourceStats.pendingGroups, tone: sourceStats.pendingGroups ? "warning" : "default" },
                      { label: "冲突", value: sourceStats.conflicts, tone: sourceStats.conflicts ? "danger" : "default" }
                    ]}
                  />
                }
                toolbar={
                  <Space wrap className="toolbar-content">
                    <Input.Search allowClear placeholder="搜索部门、成员、状态" value={groupQuery} onChange={(event) => setGroupQuery(event.target.value)} />
                    <Segmented
                      value={groupStatusFilter}
                      onChange={(value) => setGroupStatusFilter(String(value))}
                      options={[
                        { label: "全部", value: "all" },
                        { label: "待处理", value: "pending" },
                        { label: "已创建", value: "created" },
                        { label: "冲突", value: "conflict" }
                      ]}
                    />
                  </Space>
                }
                table={
                  <Table
                    rowKey="id"
                    loading={groups.loading}
                    dataSource={groupRows}
                    pagination={{
                      current: groupPage,
                      pageSize: sourceTablePageSize,
                      total: groups.data?.total ?? 0,
                      showSizeChanger: false,
                      onChange: setGroupPage
                    }}
                    rowClassName={(record) => record.provision_status === "conflict" ? "conflict-row" : ""}
                    expandable={{
                      expandedRowRender: (record) => (
                        <div className="entity-panel">
                          <div className="entity-panel-head">
                            <strong>{record.dsm_groupname}</strong>
                            <span>{record.members.length} 个成员</span>
                          </div>
                          <Table
                            rowKey="id"
                            size="small"
                            pagination={false}
                            dataSource={record.member_records}
                            columns={[
                              { title: "DSM 用户", dataIndex: "dsm_username", ellipsis: true },
                              { title: "关系状态", dataIndex: "provision_status", width: 120, render: statusTag }
                            ]}
                          />
                        </div>
                      ),
                      rowExpandable: (record) => record.members.length > 0
                    }}
                    columns={[
                      { title: "部门", dataIndex: "dsm_groupname", ellipsis: true, render: (_, record) => <IdentityCell primary={record.dsm_groupname} secondary={record.conflict_reason ?? undefined} /> },
                      { title: "飞书部门", width: 240, render: (_, record: DSMGroup) => <IdentityCell primary={record.provider_group_name || "-"} secondary={record.provider_group_path || undefined} /> },
                      { title: "成员数", dataIndex: "members", width: 110, render: (value: string[]) => <RelationCount value={value.length} label="成员" /> },
                      { title: "成员预览", dataIndex: "members", render: (value: string[]) => <EntityList values={value} limit={5} /> },
                      { title: "状态", dataIndex: "provision_status", width: 120, render: statusTag },
                      { title: "操作", width: 180, render: (_, record: DSMGroup) => (
                        <Space>
                          {record.provision_status === "conflict" && <Button size="small" onClick={() => editGroupName(record)}>修改组名</Button>}
                          {record.provision_status === "pending" && <Button size="small" onClick={() => provisionGroup(record)}>开通</Button>}
                        </Space>
                      ) }
                    ]}
                  />
                }
              />
            )
          },
          {
            key: "sync-logs",
            label: "同步日志",
            children: (
              <SourceTable
                error={syncLogs.error}
                reload={async () => {
                  await syncLogs.reloadWithResult({ silent: true });
                }}
                metrics={
                  <MetricStrip
                    items={[
                      { label: "同步日志", value: sourceStats.syncLogs },
                      { label: "同步失败", value: sourceStats.syncFailed, tone: sourceStats.syncFailed ? "danger" : "default" },
                      { label: "成员关系", value: sourceStats.members }
                    ]}
                  />
                }
                toolbar={
                  <Space wrap className="toolbar-content">
                    <Input.Search allowClear placeholder="搜索时间、对象、动作、状态、错误" value={syncLogQuery} onChange={(event) => setSyncLogQuery(event.target.value)} />
                    <Segmented
                      value={syncStatusFilter}
                      onChange={(value) => setSyncStatusFilter(String(value))}
                      options={[
                        { label: "全部", value: "all" },
                        { label: "成功", value: "success" },
                        { label: "失败", value: "failed" },
                        { label: "待处理", value: "pending" }
                      ]}
                    />
                  </Space>
                }
                table={
                  <Table
                    rowKey="id"
                    loading={syncLogs.loading}
                    dataSource={filteredSyncLogs}
                    expandable={{
                      expandedRowRender: (record) => (
                        <div className="log-detail">
                          <div className="log-detail-grid">
                            <span>对象键</span><strong>{record.object_key}</strong>
                            <span>同步批次</span><strong>{record.sync_run_id}</strong>
                            <span>结果</span><strong>{record.status}</strong>
                          </div>
                          <LogBlock title="错误内容" value={record.error} empty="无错误" tone="danger" />
                        </div>
                      )
                    }}
                    columns={[
                      { title: "时间", dataIndex: "created_at", width: 190, ellipsis: true, render: formatLocalTime },
                      { title: "状态", dataIndex: "status", width: 110, render: statusTag },
                      { title: "对象", dataIndex: "object_type", width: 100, render: labelOf },
                      { title: "动作", dataIndex: "action", width: 180, render: actionTag },
                      { title: "对象名称", dataIndex: "dsm_name", ellipsis: true, render: (_, record) => <IdentityCell primary={record.dsm_name ?? record.object_key} secondary={record.object_key} /> }
                    ]}
                    pagination={{
                      current: syncLogPage,
                      pageSize: sourceTablePageSize,
                      total: syncLogs.data?.total ?? 0,
                      showSizeChanger: false,
                      onChange: setSyncLogPage
                    }}
                  />
                }
              />
            )
          },
          {
            key: "audit-logs",
            label: "登录审计",
            children: (
              <SourceTable
                error={auditLogs.error}
                reload={async () => {
                  await auditLogs.reloadWithResult({ silent: true });
                }}
                metrics={
                  <MetricStrip
                    items={[
                      { label: "登录审计", value: sourceStats.loginAudits },
                      { label: "登录失败", value: sourceStats.loginFailed, tone: sourceStats.loginFailed ? "danger" : "default" },
                      { label: "用户", value: sourceStats.users }
                    ]}
                  />
                }
                toolbar={
                  <Space wrap className="toolbar-content">
                    <Input.Search allowClear placeholder="搜索用户、结果、错误" value={auditQuery} onChange={(event) => setAuditQuery(event.target.value)} />
                    <Segmented
                      value={auditResultFilter}
                      onChange={(value) => setAuditResultFilter(String(value))}
                      options={[
                        { label: "全部", value: "all" },
                        { label: "成功", value: "success" },
                        { label: "失败", value: "failed" },
                        { label: "拒绝", value: "denied" }
                      ]}
                    />
                  </Space>
                }
                table={
                  <Table
                    rowKey="id"
                    loading={auditLogs.loading}
                    dataSource={filteredAuditLogs}
                    columns={auditColumns(source.display_name)}
                    expandable={{
                      expandedRowRender: (record) => (
                        <div className="log-detail">
                          <div className="log-detail-grid">
                            <span>身份源</span><strong>{source.display_name}</strong>
                            <span>结果</span><strong>{record.result}</strong>
                            <span>耗时</span><strong>{record.duration_ms == null ? "-" : `${record.duration_ms} ms`}</strong>
                            <span>访问 IP</span><strong>{record.ip_address ?? "-"}</strong>
                          </div>
                          <LogBlock title="错误内容" value={record.error_code} empty="无错误" tone="danger" />
                        </div>
                      )
                    }}
                    pagination={{
                      current: auditPage,
                      pageSize: sourceTablePageSize,
                      total: auditLogs.data?.total ?? 0,
                      showSizeChanger: false,
                      onChange: setAuditPage
                    }}
                  />
                }
              />
            )
          }
        ]}
      />
    </Space>
  );
}

function auditColumns(sourceName: string): ColumnsType<LoginAuditLog> {
  return [
  { title: "时间", dataIndex: "created_at", width: 190, ellipsis: true, render: formatLocalTime },
  { title: "用户", dataIndex: "dsm_username", ellipsis: true, render: (_, record) => <IdentityCell primary={record.dsm_username ?? "-"} secondary={sourceName} /> },
  { title: "访问 IP", dataIndex: "ip_address", width: 150, ellipsis: true, render: (value) => value ?? "-" },
  { title: "结果", dataIndex: "result", width: 100, render: resultTag },
  { title: "耗时", dataIndex: "duration_ms", width: 110, render: (value) => value == null ? "-" : `${value} ms` }
  ];
}

export function App() {
  return (
    <ConfigProvider
      locale={zhCN}
      theme={{
        algorithm: theme.defaultAlgorithm,
        token: {
          colorPrimary: "#1677ff",
          borderRadius: 8,
          fontSize: 14,
          colorBgLayout: "#f5f5f5",
          colorBorderSecondary: "#f0f0f0"
        },
        components: {
          Layout: { siderBg: "#fff", triggerBg: "#fff", headerBg: "#fff" },
          Menu: { itemBorderRadius: 6 },
          Card: { headerFontSize: 15 },
          Table: { headerBg: "#fafafa" }
        }
      }}
    >
      <AntApp>
        <AuthGate />
      </AntApp>
    </ConfigProvider>
  );
}
