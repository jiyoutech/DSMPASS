import { DeleteOutlined, PlusOutlined, PoweroffOutlined, ReloadOutlined, SafetyCertificateOutlined, UploadOutlined } from "@ant-design/icons";
import { Alert, App as AntApp, Button, Card, Flex, Form, Input, InputNumber, Menu, Segmented, Select, Space, Switch, Table, Tag, Upload } from "antd";
import type { ColumnsType } from "antd/es/table";
import type { UploadFile } from "antd/es/upload/interface";
import { useEffect, useState } from "react";
import { api } from "../api";
import { HelpLabel, PageTitle } from "../components/common";
import { useAsyncData } from "../hooks/useAsyncData";
import type { AdminPasswordChange, FirewallAccessLog, LoginAuditLog, SystemSettingsUpdate } from "../types";
import { resultTag } from "../utils/labels";
import { formatLocalTime } from "../utils/time";

const privateCIDRs = "default ban\nallow private";
const allCIDRs = "default allow";
const loopbackCIDRs = "default ban\nallow loopback";
type SettingsSectionKey = "base" | "firewall" | "dsm" | "certificates" | "account";

const systemFieldHelp = {
  accessHost: "需要登录的 NAS 的 IP 或域名，用于检测并生成 IDP 地址、DSM 地址和 DSM Auth API；填写主机名，不包含协议和路径。",
  accessScheme: "IDP 登录入口使用的协议。/idp/.../launch、OAuth callback 和 redirect_uri 会使用这个协议；管理后台协议由 SPK 安装配置决定。",
  idpPort: "用户登录入口对外端口，必须大于 1024 且不能被占用。登录入口 /idp/.../launch 和 OAuth callback 会使用 IDP 地址里的这个端口。",
  adminAllowedCIDRs: "管理后台入站安全组。默认禁止未匹配来源并放行本机和内网；保存时后端会确认当前访问 IP 仍可访问，避免把自己锁在外面。",
  idpAllowedCIDRs: "认证入口入站安全组。默认放行所有来源；如只给内网使用，可以一键切换为内网。",
  publicBaseURL: "IDP 对外入口地址，由 IDP 协议、访问 IP / 域名和 IDP 入口端口自动生成，不能手动修改协议。",
  dsmRedirectURL: "需要登录的 NAS 的 DSM 访问地址，由 IDP 协议和访问 IP / 域名自动生成。HTTP 使用 5000，HTTPS 使用 5001。",
  helperDSMLoginMode: "直接连接：前端浏览器用临时密码调用 DSM Auth API，DSM 看到的是用户真实访问 IP。Helper 连接：由 NAS 上的 helper 后台调用 DSM Auth API。",
  helperDSMBrowserLoginTTL: "浏览器直登时临时密码保留的秒数，到期后 helper 自动恢复 shadow。",
  helperDSMLoginAPI: "需要登录的 NAS 的 DSM 登录接口地址，由 DSM 地址自动生成。",
  helperDSMTLSSkipVerify: "控制辅助程序访问需要登录的 NAS 时是否跳过 DSM 证书校验。"
};

function normalizedHost(value: string | undefined) {
  return String(value || "").trim() || "127.0.0.1";
}

function dsmPortForScheme(scheme: "http" | "https") {
  return scheme === "https" ? 5001 : 5000;
}

function derivedSystemURLs(host: string, scheme: "http" | "https", idpPort: number) {
  const accessHost = normalizedHost(host);
  const dsmPort = dsmPortForScheme(scheme);
  return {
    public_base_url: `${scheme}://${accessHost}:${idpPort || 25000}`,
    dsm_redirect_url: `${scheme}://${accessHost}:${dsmPort}/`,
    helper_dsm_login_api: `${scheme}://${accessHost}:${dsmPort}/webapi/entry.cgi`
  };
}

export function SystemSettingsFields({ section = "all" }: { section?: "all" | "base" | "firewall" | "dsm" } = {}) {
  const form = Form.useFormInstance<SystemSettingsUpdate>();
  const { message } = AntApp.useApp();
  const [detecting, setDetecting] = useState(false);

  function syncDerivedURLs(next?: Partial<{ access_host: string; access_scheme: "http" | "https"; idp_port: number }>) {
    const scheme = next?.access_scheme || (form.getFieldValue("access_scheme") || "https") as "http" | "https";
    const host = next?.access_host ?? String(form.getFieldValue("access_host") || "");
    const idpPort = Number(next?.idp_port ?? form.getFieldValue("idp_port") ?? 25000);
    form.setFieldsValue(derivedSystemURLs(host, scheme, idpPort));
  }

  async function discover() {
    const host = String(form.getFieldValue("access_host") ?? "").trim();
    const scheme = (form.getFieldValue("access_scheme") || "https") as "http" | "https";
    const idpPort = Number(form.getFieldValue("idp_port") || 25000);
    if (!host) {
      message.error("请先填写访问 IP / 域名");
      return;
    }
    setDetecting(true);
    try {
      const result = await api.discoverSettings({ access_host: host, access_scheme: scheme, idp_port: idpPort });
      form.setFieldsValue(result);
      message.success(result.dsm_detected ? "已检测到 DSM" : "未检测到 DSM，已填入默认值");
    } catch (err) {
      message.error(err instanceof Error ? err.message : "检测失败");
    } finally {
      setDetecting(false);
    }
  }

  function setCIDR(field: "admin_allowed_cidrs" | "idp_allowed_cidrs", value: string) {
    form.setFieldValue(field, value);
  }

  return (
    <Space direction="vertical" size={18} className="settings-stack">
      {(section === "all" || section === "base") && <section className="settings-section">
        <div className="settings-section-head">
          <div>
            <h3>入口地址</h3>
            <p>配置用户访问认证入口时使用的协议、主机和端口。</p>
          </div>
          <Tag color="blue">IDP</Tag>
        </div>
        <div className="form-grid">
          <Form.Item name="access_scheme" label={<HelpLabel label="IDP 协议" help={systemFieldHelp.accessScheme} />} rules={[{ required: true }]}>
            <Segmented
              block
              options={[
                { label: "HTTP", value: "http" },
                { label: "HTTPS", value: "https" }
              ]}
              onChange={(value) => syncDerivedURLs({ access_scheme: value as "http" | "https" })}
            />
          </Form.Item>
          <Form.Item name="access_host" label={<HelpLabel label="访问 IP / 域名" help={systemFieldHelp.accessHost} />} rules={[{ required: true }]}>
            <Input
              addonAfter={<Button htmlType="button" type="link" size="small" loading={detecting} onClick={() => void discover()}>检测</Button>}
              onChange={(event) => syncDerivedURLs({ access_host: event.target.value })}
            />
          </Form.Item>
          <Form.Item name="idp_port" label={<HelpLabel label="IDP 入口端口" help={systemFieldHelp.idpPort} />} rules={[{ required: true }]}>
            <InputNumber min={1025} max={65535} precision={0} onChange={(value) => syncDerivedURLs({ idp_port: Number(value) })} />
          </Form.Item>
          <Form.Item name="public_base_url" label={<HelpLabel label="IDP 地址" help={systemFieldHelp.publicBaseURL} />} rules={[{ required: true }]}>
            <Input readOnly />
          </Form.Item>
        </div>
      </section>}

      {(section === "all" || section === "firewall") && <section className="settings-section">
        <div className="settings-section-head">
          <div>
            <h3>基础防火墙</h3>
            <p>按来源 IP 设置有序入站规则。命中规则立即生效，未命中时走该端口的默认策略。</p>
          </div>
          <Tag color="green">入站规则</Tag>
        </div>
        <Alert
          type="info"
          showIcon
          className="settings-inline-alert"
          message="这是基础访问控制：管理端口和认证端口各自使用独立允许来源，不接管 DSM 系统防火墙。"
        />
        <div className="settings-firewall-grid">
          <FirewallCIDRField
            name="admin_allowed_cidrs"
            title="管理端口"
            subtitle="后台 API、系统设置和静态管理页面"
            help={systemFieldHelp.adminAllowedCIDRs}
            tone="restricted"
            onPrivate={() => setCIDR("admin_allowed_cidrs", privateCIDRs)}
            onAll={() => setCIDR("admin_allowed_cidrs", allCIDRs)}
            onLoopback={() => setCIDR("admin_allowed_cidrs", loopbackCIDRs)}
          />
          <FirewallCIDRField
            name="idp_allowed_cidrs"
            title="认证端口"
            subtitle="飞书 OAuth 入口、Callback 和浏览器直登完成接口"
            help={systemFieldHelp.idpAllowedCIDRs}
            tone="public"
            onPrivate={() => setCIDR("idp_allowed_cidrs", privateCIDRs)}
            onAll={() => setCIDR("idp_allowed_cidrs", allCIDRs)}
          />
        </div>
      </section>}

      {(section === "all" || section === "dsm") && <section className="settings-section">
        <div className="settings-section-head">
          <div>
            <h3>DSM 登录</h3>
            <p>配置最终跳转到 DSM 的地址和 Helper 登录方式。</p>
          </div>
          <Tag color="purple">DSM</Tag>
        </div>
        <div className="form-grid">
          <Form.Item name="dsm_redirect_url" label={<HelpLabel label="DSM 地址" help={systemFieldHelp.dsmRedirectURL} />} rules={[{ required: true }]}>
            <Input readOnly />
          </Form.Item>
          <Form.Item name="helper_dsm_login_api" label={<HelpLabel label="DSM Auth API" help={systemFieldHelp.helperDSMLoginAPI} />} rules={[{ required: true }]}>
            <Input readOnly />
          </Form.Item>
          <Form.Item name="helper_dsm_login_mode" label={<HelpLabel label="DSM 登录模式" help={systemFieldHelp.helperDSMLoginMode} />} rules={[{ required: true }]}>
            <Select
              options={[
                { label: "直接连接", value: "browser" },
                { label: "Helper 连接", value: "helper" }
              ]}
            />
          </Form.Item>
          <Form.Item name="helper_dsm_browser_login_ttl_seconds" label={<HelpLabel label="直登 TTL 秒数" help={systemFieldHelp.helperDSMBrowserLoginTTL} />} rules={[{ required: true }]}>
            <InputNumber min={1} max={60} precision={0} />
          </Form.Item>
          <Form.Item name="helper_dsm_tls_skip_verify" label={<HelpLabel label="跳过 DSM TLS 校验" help={systemFieldHelp.helperDSMTLSSkipVerify} />} valuePropName="checked">
            <Switch />
          </Form.Item>
        </div>
      </section>}
    </Space>
  );
}

export function SystemSettings() {
  const [form] = Form.useForm<SystemSettingsUpdate>();
  const [passwordForm] = Form.useForm<AdminPasswordChange>();
  const { message, modal } = AntApp.useApp();
  const { data, loading, error, reload } = useAsyncData(() => api.systemSettings(), []);
  const firewallLogs = useAsyncData(() => api.firewallLogs(), []);
  const authLogs = useAsyncData(() => api.loginAuditLogs(), []);
  const [saving, setSaving] = useState(false);
  const [activeSection, setActiveSection] = useState<SettingsSectionKey>("base");
  const [uploadingCert, setUploadingCert] = useState<"admin" | "idp" | null>(null);
  const [restartingIDP, setRestartingIDP] = useState(false);
  const [restartingPackage, setRestartingPackage] = useState(false);
  const [adminCertFiles, setAdminCertFiles] = useState<UploadFile[]>([]);
  const [adminKeyFiles, setAdminKeyFiles] = useState<UploadFile[]>([]);
  const [idpCertFiles, setIDPCertFiles] = useState<UploadFile[]>([]);
  const [idpKeyFiles, setIDPKeyFiles] = useState<UploadFile[]>([]);

  useEffect(() => {
    if (data) {
      form.setFieldsValue({
        access_host: data.access_host,
        access_scheme: data.access_scheme || "https",
        idp_port: data.idp_port || 25000,
        admin_allowed_cidrs: data.admin_allowed_cidrs,
        idp_allowed_cidrs: data.idp_allowed_cidrs,
        public_base_url: data.public_base_url,
        dsm_redirect_url: data.dsm_redirect_url,
        helper_dsm_login_api: data.helper_dsm_login_api,
        helper_dsm_login_mode: data.helper_dsm_login_mode,
        helper_dsm_browser_login_ttl_seconds: data.helper_dsm_browser_login_ttl_seconds,
        helper_dsm_tls_skip_verify: data.helper_dsm_tls_skip_verify
      });
    }
  }, [data, form]);

  async function save(values: SystemSettingsUpdate) {
    setSaving(true);
    try {
      const payload = { ...values };
      if (!payload.relay_helper_hmac_secret) {
        delete payload.relay_helper_hmac_secret;
      }
      await api.updateSystemSettings(payload);
      message.success("已保存");
      form.setFieldsValue({ relay_helper_hmac_secret: "" });
      await reload();
    } catch (err) {
      message.error(err instanceof Error ? err.message : "保存失败");
    } finally {
      setSaving(false);
    }
  }

  async function changePassword(values: AdminPasswordChange) {
    setSaving(true);
    try {
      const result = await api.adminChangePassword(values);
      message.success("已保存");
      passwordForm.resetFields();
      form.setFieldsValue({});
      window.location.reload();
      return result;
    } catch (err) {
      message.error(err instanceof Error ? err.message : "保存失败");
    } finally {
      setSaving(false);
    }
  }

  async function uploadCertificate(scope: "admin" | "idp") {
    const cert = selectedFile(scope === "admin" ? adminCertFiles : idpCertFiles);
    const key = selectedFile(scope === "admin" ? adminKeyFiles : idpKeyFiles);
    if (!cert || !key) {
      message.error("请同时选择证书 PEM 和私钥 PEM");
      return;
    }
    setUploadingCert(scope);
    try {
      const result = await api.uploadCertificate(scope, cert, key);
      if (scope === "admin" || result.restart_required) {
        message.success("管理端证书已上传，点击重启管理端后生效");
      } else {
        message.success("认证端证书已上传，可重启认证路由生效");
      }
      if (scope === "admin") {
        setAdminCertFiles([]);
        setAdminKeyFiles([]);
      } else {
        setIDPCertFiles([]);
        setIDPKeyFiles([]);
      }
    } catch (err) {
      message.error(err instanceof Error ? err.message : "证书上传失败");
    } finally {
      setUploadingCert(null);
    }
  }

  async function restartIDPRoute() {
    setRestartingIDP(true);
    try {
      await api.restartIDPRoute();
      message.success("认证路由已重启");
    } catch (err) {
      message.error(err instanceof Error ? err.message : "认证路由重启失败");
    } finally {
      setRestartingIDP(false);
    }
  }

  function confirmPackageRestart() {
    modal.confirm({
      title: "重启管理端",
      content: "会重启 DSM Pass 套件进程，当前管理后台连接会短暂断开。管理端口未变化时，稍后刷新当前页面即可；如果端口已在套件侧修改，请改用新端口访问。",
      okText: "重启",
      cancelText: "取消",
      okButtonProps: { danger: true },
      onOk: () => restartPackage()
    });
  }

  async function restartPackage() {
    setRestartingPackage(true);
    try {
      await api.restartPackage();
      message.success("已发起管理端重启，页面会短暂断开");
      window.setTimeout(() => window.location.reload(), 5000);
    } catch (err) {
      message.error(err instanceof Error ? err.message : "管理端重启失败");
    } finally {
      setRestartingPackage(false);
    }
  }

  return (
    <Space direction="vertical" size={16} className="page settings-page">
      <PageTitle title="系统设置" extra={<Button icon={<ReloadOutlined />} onClick={() => void reload()}>刷新</Button>} />
      {error && <Alert type="error" showIcon message={error} />}
      <div className="settings-console">
        <Menu
          mode="inline"
          className="settings-submenu"
          selectedKeys={[activeSection]}
          onClick={({ key }) => setActiveSection(key as SettingsSectionKey)}
          items={[
            { key: "base", label: "基础配置" },
            { key: "firewall", label: "防火墙" },
            { key: "dsm", label: "DSM 登录" },
            { key: "certificates", label: "证书与路由" },
            { key: "account", label: "后台账号" }
          ]}
        />
        <div className="settings-console-body">
          {(activeSection === "base" || activeSection === "firewall" || activeSection === "dsm") && (
            <Form form={form} layout="vertical" onFinish={(values) => void save(values)} disabled={loading || saving} className="settings-form">
              <Card
                title={activeSection === "base" ? "基础配置" : activeSection === "firewall" ? "防火墙" : "DSM 登录"}
                className="module-card settings-card"
                extra={<Button type="primary" htmlType="submit" loading={saving}>保存配置</Button>}
              >
                <SystemSettingsFields section={activeSection} />
                {activeSection === "firewall" && (
                  <SettingsLogs
                    firewallLogs={firewallLogs.data?.items ?? []}
                    authLogs={authLogs.data?.items ?? []}
                    firewallLoading={firewallLogs.loading}
                    authLoading={authLogs.loading}
                    onReloadFirewall={() => void firewallLogs.reload()}
                    onReloadAuth={() => void authLogs.reload()}
                  />
                )}
              </Card>
            </Form>
          )}
          {activeSection === "certificates" && (
            <Card title="证书与路由" className="module-card settings-card">
              <Alert
                type="info"
                showIcon
                className="settings-inline-alert"
                message="管理端证书需要重启管理端生效；认证端证书可单独重启认证路由生效。"
              />
              <div className="certificate-grid">
                <CertificateUploadFields
                  title="管理端口证书"
                  description="用于管理后台 HTTPS。证书写入套件环境实际读取路径。"
                  certFiles={adminCertFiles}
                  keyFiles={adminKeyFiles}
                  onCertFiles={setAdminCertFiles}
                  onKeyFiles={setAdminKeyFiles}
                  disabled={loading || saving}
                />
                <CertificateUploadFields
                  title="认证端口证书"
                  description="用于 /idp 登录入口，可与管理端证书不同。"
                  certFiles={idpCertFiles}
                  keyFiles={idpKeyFiles}
                  onCertFiles={setIDPCertFiles}
                  onKeyFiles={setIDPKeyFiles}
                  disabled={loading || saving}
                />
              </div>
              <Flex justify="end" gap={8} wrap>
                <Button icon={<UploadOutlined />} loading={uploadingCert === "admin"} onClick={() => void uploadCertificate("admin")}>上传管理端证书</Button>
                <Button icon={<UploadOutlined />} loading={uploadingCert === "idp"} onClick={() => void uploadCertificate("idp")}>上传认证端证书</Button>
                <Button icon={<SafetyCertificateOutlined />} loading={restartingIDP} onClick={() => void restartIDPRoute()}>重启认证路由</Button>
                <Button danger icon={<PoweroffOutlined />} loading={restartingPackage} onClick={confirmPackageRestart}>重启管理端</Button>
              </Flex>
            </Card>
          )}
          {activeSection === "account" && (
            <Card title="后台账号" className="module-card settings-card">
              <Form form={passwordForm} layout="vertical" onFinish={(values) => void changePassword(values)} disabled={saving}>
                <div className="form-grid">
                  <Form.Item name="username" label="账号"><Input autoComplete="username" /></Form.Item>
                  <Form.Item name="current_password" label="当前密码" rules={[{ required: true }]}><Input.Password autoComplete="current-password" /></Form.Item>
                  <Form.Item name="new_password" label="新密码" rules={[{ required: true }]}><Input.Password autoComplete="new-password" /></Form.Item>
                </div>
                <Flex justify="end">
                  <Button type="primary" htmlType="submit" loading={saving}>保存账号</Button>
                </Flex>
              </Form>
            </Card>
          )}
        </div>
      </div>
    </Space>
  );
}

function selectedFile(files: UploadFile[]) {
  return files[0]?.originFileObj;
}

function SettingsLogs({
  firewallLogs,
  authLogs,
  firewallLoading,
  authLoading,
  onReloadFirewall,
  onReloadAuth
}: {
  firewallLogs: FirewallAccessLog[];
  authLogs: LoginAuditLog[];
  firewallLoading: boolean;
  authLoading: boolean;
  onReloadFirewall: () => void;
  onReloadAuth: () => void;
}) {
  return (
    <div className="settings-log-grid">
      <Card
        size="small"
        title="防火墙拦截日志"
        className="settings-log-card"
        extra={<Button size="small" icon={<ReloadOutlined />} onClick={onReloadFirewall}>刷新</Button>}
      >
        <Table
          size="small"
          rowKey="id"
          loading={firewallLoading}
          dataSource={firewallLogs}
          columns={firewallColumns}
          pagination={{ pageSize: 8 }}
        />
      </Card>
      <Card
        size="small"
        title="认证登录日志"
        className="settings-log-card"
        extra={<Button size="small" icon={<ReloadOutlined />} onClick={onReloadAuth}>刷新</Button>}
      >
        <Table
          size="small"
          rowKey="id"
          loading={authLoading}
          dataSource={authLogs}
          columns={authLogColumns}
          pagination={{ pageSize: 8 }}
        />
      </Card>
    </div>
  );
}

const firewallColumns: ColumnsType<FirewallAccessLog> = [
  { title: "时间", dataIndex: "created_at", width: 170, render: formatLocalTime },
  { title: "入口", dataIndex: "scope", width: 90, render: (value) => <Tag color={value === "admin" ? "green" : "blue"}>{value === "admin" ? "管理" : "认证"}</Tag> },
  { title: "动作", dataIndex: "decision", width: 90, render: (value) => <Tag color="error">{value === "deny" ? "拦截" : value}</Tag> },
  { title: "来源 IP", dataIndex: "remote_ip", width: 150, render: (value) => value || "-" },
  { title: "请求", width: 240, render: (_, record) => `${record.method} ${record.path}` },
  { title: "原因", dataIndex: "reason", ellipsis: true, render: (value) => value || "-" }
];

const authLogColumns: ColumnsType<LoginAuditLog> = [
  { title: "时间", dataIndex: "created_at", width: 170, render: formatLocalTime },
  { title: "结果", dataIndex: "result", width: 90, render: resultTag },
  { title: "身份源", dataIndex: "provider_slug", width: 120 },
  { title: "DSM 用户", dataIndex: "dsm_username", width: 140, render: (value) => value || "-" },
  { title: "来源 IP", dataIndex: "ip_address", width: 150, render: (value) => value || "-" },
  { title: "错误", dataIndex: "error_code", ellipsis: true, render: (value) => value || "-" }
];

function FirewallCIDRField({
  name,
  title,
  subtitle,
  help,
  tone,
  onPrivate,
  onAll,
  onLoopback
}: {
  name: "admin_allowed_cidrs" | "idp_allowed_cidrs";
  title: string;
  subtitle: string;
  help: string;
  tone: "restricted" | "public";
  onPrivate: () => void;
  onAll?: () => void;
  onLoopback?: () => void;
}) {
  const form = Form.useFormInstance<SystemSettingsUpdate>();
  const value = Form.useWatch(name) as string | undefined;
  const config = parseFirewallConfig(value);
  const ruleCount = config.rules.length;

  function updateConfig(next: FirewallConfig) {
    form.setFieldValue(name, formatFirewallConfig(next));
  }

  function updateRule(index: number, patch: Partial<FirewallRule>) {
    const rules = config.rules.map((rule, itemIndex) => itemIndex === index ? { ...rule, ...patch } : rule);
    updateConfig({ ...config, rules });
  }

  function addRule(action: FirewallAction) {
    updateConfig({ ...config, rules: [...config.rules, { action, source: action === "allow" ? "10.0.0.0/8" : "203.0.113.10" }] });
  }

  function removeRule(index: number) {
    updateConfig({ ...config, rules: config.rules.filter((_, itemIndex) => itemIndex !== index) });
  }

  return (
    <div className={`firewall-panel firewall-panel-${tone}`}>
      <Form.Item name={name} hidden>
        <Input />
      </Form.Item>
      <div className="firewall-panel-head">
        <div>
          <HelpLabel label={<strong>{title}</strong>} help={help} />
          <p>{subtitle}</p>
        </div>
        <Tag color={tone === "restricted" ? "green" : "blue"}>{ruleCount} 条来源规则</Tag>
      </div>
      <div className="firewall-rule-summary">
        <div className="firewall-rule-header">
          <span>优先级</span>
          <span>匹配方式</span>
          <span>结果</span>
        </div>
        {config.rules.map((rule, index) => (
          <div className="firewall-rule-row" key={`${rule.action}-${rule.source}-${index}`}>
            <span>{index + 1}</span>
            <span>{rule.source}</span>
            <Tag color={rule.action === "allow" ? "success" : "error"}>{rule.action === "allow" ? "放行" : "禁止"}</Tag>
          </div>
        ))}
        <div className="firewall-rule-row firewall-rule-row-muted">
          <span>默认</span>
          <span>未命中任何规则</span>
          <Tag color={config.defaultAction === "allow" ? "success" : "error"}>{config.defaultAction === "allow" ? "放行" : "禁止"}</Tag>
        </div>
      </div>
      <div className="firewall-actions">
        <Select
          size="small"
          className="firewall-default-select"
          value={config.defaultAction}
          options={[
            { label: "默认放行所有", value: "allow" },
            { label: "默认禁止所有", value: "ban" }
          ]}
          onChange={(defaultAction) => updateConfig({ ...config, defaultAction })}
        />
        <Button size="small" onClick={onPrivate}>仅内网访问</Button>
        {onLoopback && <Button size="small" onClick={onLoopback}>仅本机</Button>}
        {onAll && <Button size="small" onClick={onAll}>允许所有网络</Button>}
      </div>
      <div className="firewall-rule-editor">
        <div className="firewall-editor-header">
          <span>顺序</span>
          <span>动作</span>
          <span>来源 IP / CIDR / 别名</span>
          <span />
        </div>
        {config.rules.map((rule, index) => (
          <div className="firewall-editor-row" key={`editor-${index}`}>
            <span>{index + 1}</span>
            <Select
              size="small"
              value={rule.action}
              options={[
                { label: "放行", value: "allow" },
                { label: "禁止", value: "ban" }
              ]}
              onChange={(action) => updateRule(index, { action })}
            />
            <Input
              size="small"
              value={rule.source}
              placeholder="例如 private、10.0.0.0/8、203.0.113.10"
              onChange={(event) => updateRule(index, { source: event.target.value })}
            />
            <Button size="small" icon={<DeleteOutlined />} onClick={() => removeRule(index)} />
          </div>
        ))}
        <div className="firewall-editor-actions">
          <Button size="small" icon={<PlusOutlined />} onClick={() => addRule("allow")}>添加放行规则</Button>
          <Button size="small" icon={<PlusOutlined />} onClick={() => addRule("ban")}>添加禁止规则</Button>
        </div>
      </div>
    </div>
  );
}

type FirewallAction = "allow" | "ban";

interface FirewallRule {
  action: FirewallAction;
  source: string;
}

interface FirewallConfig {
  defaultAction: FirewallAction;
  rules: FirewallRule[];
}

function parseFirewallConfig(value: string | undefined): FirewallConfig {
  const lines = String(value || "default allow")
    .split(/[\r\n;]+/)
    .map((line) => line.trim())
    .filter(Boolean);
  let defaultAction: FirewallAction = "allow";
  const rules: FirewallRule[] = [];
  for (const line of lines) {
    if (line.toLowerCase().startsWith("default:") || line.toLowerCase().startsWith("default=")) {
      defaultAction = parseFirewallAction(line.slice("default:".length)) || "allow";
      continue;
    }
    const compact = parseCompactFirewallRule(line);
    if (compact) {
      rules.push(compact);
      continue;
    }
    const [first, second, ...rest] = line.split(/\s+/);
    if (first?.toLowerCase() === "default") {
      defaultAction = parseFirewallAction(second) || "allow";
      continue;
    }
    const action = parseFirewallAction(first);
    if (action) {
      rules.push({ action, source: [second, ...rest].filter(Boolean).join(" ") });
    } else {
      rules.push({ action: "allow", source: line });
    }
  }
  return { defaultAction, rules: rules.filter((rule) => rule.source.trim()) };
}

function parseCompactFirewallRule(line: string): FirewallRule | null {
  for (const separator of [":", "="]) {
    const index = line.indexOf(separator);
    if (index < 0) {
      continue;
    }
    const action = parseFirewallAction(line.slice(0, index));
    if (!action) {
      continue;
    }
    return { action, source: line.slice(index + 1).trim() };
  }
  return null;
}

function formatFirewallConfig(config: FirewallConfig) {
  return [
    `default ${config.defaultAction}`,
    ...config.rules
      .map((rule) => `${rule.action} ${rule.source.trim()}`)
      .filter((line) => !line.endsWith(" "))
  ].join("\n");
}

function parseFirewallAction(value: string | undefined): FirewallAction | null {
  const normalized = String(value || "").toLowerCase();
  if (["allow", "accept", "permit", "允许", "放行"].includes(normalized)) {
    return "allow";
  }
  if (["ban", "deny", "drop", "block", "reject", "禁止", "拒绝"].includes(normalized)) {
    return "ban";
  }
  return null;
}

function CertificateUploadFields({
  title,
  description,
  certFiles,
  keyFiles,
  onCertFiles,
  onKeyFiles,
  disabled
}: {
  title: string;
  description: string;
  certFiles: UploadFile[];
  keyFiles: UploadFile[];
  onCertFiles: (files: UploadFile[]) => void;
  onKeyFiles: (files: UploadFile[]) => void;
  disabled?: boolean;
}) {
  return (
    <div className="certificate-upload">
      <div>
        <strong>{title}</strong>
        <p>{description}</p>
      </div>
      <Upload
        accept=".pem,.crt,.cer"
        maxCount={1}
        fileList={certFiles}
        beforeUpload={() => false}
        onChange={({ fileList }) => onCertFiles(fileList.slice(-1))}
        disabled={disabled}
      >
        <Button icon={<UploadOutlined />} disabled={disabled}>选择证书 PEM</Button>
      </Upload>
      <Upload
        accept=".pem,.key"
        maxCount={1}
        fileList={keyFiles}
        beforeUpload={() => false}
        onChange={({ fileList }) => onKeyFiles(fileList.slice(-1))}
        disabled={disabled}
      >
        <Button icon={<UploadOutlined />} disabled={disabled}>选择私钥 PEM</Button>
      </Upload>
    </div>
  );
}
