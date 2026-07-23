import { ReloadOutlined, SafetyCertificateOutlined, UploadOutlined } from "@ant-design/icons";
import { Alert, App as AntApp, Button, Card, Flex, Form, Input, InputNumber, Menu, Segmented, Select, Space, Switch, Upload } from "antd";
import type { UploadFile } from "antd/es/upload/interface";
import { useEffect, useState, type ReactNode } from "react";
import { api } from "../api";
import { HelpLabel, PageTitle } from "../components/common";
import { useAsyncData } from "../hooks/useAsyncData";
import type { AdminPasswordChange, SystemSettingsOverview, SystemSettingsUpdate } from "../types";

const privateCIDRs = "private";
const allCIDRs = "all";
const defaultIDPPort = 26000;
type SettingsSectionKey = "overview" | "access" | "dsm" | "security" | "certificates" | "account";
type DeploymentMode = "direct" | "reverse_proxy" | "advanced";
type CertificateScope = "admin" | "idp";

const systemFieldHelp = {
  deploymentMode: "影响地址推导和哪些地址允许手动编辑；不会关闭本机 /idp 监听端口。",
  accessHost: "用于生成默认认证入口、DSM 地址和 DSM Auth API；填写主机名或 IP，不包含协议、端口和路径。",
  accessScheme: "影响本机 /idp 监听使用 HTTP 还是 HTTPS；反向代理公网协议由认证入口公网地址决定。",
  idpPort: "影响本机 /idp 登录入口监听端口，必须大于 1024、不能被占用，并且不能与管理后台端口一致。",
  adminPort: "管理后台页面、静态前端和 /api/admin 接口使用的本机监听端口。此值由套件启动参数决定，不能在系统设置页修改。",
  adminAllowedCIDRs: "开启后，管理后台仅允许本机和内网访问。保存时后端会确认当前访问 IP 仍可访问，避免把自己锁在外面。",
  publicBaseURL: "影响登录链接和 OAuth redirect_uri/callback_url，是企业微信、飞书、钉钉看到的认证入口公网地址。",
  dsmRedirectURL: "影响认证成功后浏览器最终跳转到哪个 DSM 地址。直接访问和反向代理模式会自动生成，高级自定义可手动填写。",
  helperDSMLoginMode: "直接连接：前端浏览器用临时密码调用 DSM Auth API，DSM 看到的是用户真实访问 IP；此模式下 DSM 地址协议必须和 IDP 协议一致。Helper 连接：由 NAS 上的 helper 后台调用 DSM Auth API。",
  helperDSMBrowserLoginTTL: "浏览器直登时临时密码保留的秒数，到期后 helper 自动恢复 shadow。",
  helperDSMLoginAPI: "影响 DSMPASS 或浏览器调用哪个 DSM SYNO.API.Auth 登录接口。直接访问和反向代理模式会自动生成，高级自定义可手动填写。",
  helperDSMTLSSkipVerify: "控制辅助程序访问需要登录的 NAS 时是否跳过 DSM 证书校验。"
};

const fieldEffectHelp = {
  adminPort: "由套件启动参数提供；修改后需重启 DSMPASS。",
  deploymentMode: "保存后立即更新地址推导规则。",
  accessHost: "保存后立即更新默认地址推导。",
  accessScheme: "保存后刷新认证路由；无需重启套件。",
  idpPort: "保存后刷新认证路由；端口可绑定时立即生效。",
  publicBaseURLLocked: "由上方字段自动生成；影响新登录链接和 OAuth 回调地址。",
  publicBaseURLEditable: "保存后立即影响新登录链接和 OAuth 回调地址。",
  dsmLocked: "当前部署方式下自动生成；高级模式可手动填写。",
  dsmRedirectURL: "保存后立即影响认证成功后的 DSM 跳转目标。",
  helperDSMLoginAPI: "保存后立即影响后续 DSM 登录调用。",
  helperDSMLoginMode: "保存后立即影响后续登录流程。",
  helperDSMBrowserLoginTTL: "保存后立即影响浏览器直登临时密码。",
  helperDSMTLSSkipVerify: "保存后立即影响 DSMPASS/Helper 访问 DSM Auth API。",
  adminAllowedCIDRs: "保存后立即影响管理后台和 /api/admin 新请求。"
};

const deploymentOptions: { label: string; value: DeploymentMode }[] = [
  { label: "直接访问", value: "direct" },
  { label: "反向代理", value: "reverse_proxy" },
  { label: "高级", value: "advanced" }
];

function normalizedDeploymentMode(value: unknown): DeploymentMode {
  if (value === "reverse_proxy" || value === "advanced") {
    return value;
  }
  return "direct";
}

function normalizedHost(value: string | undefined) {
  return String(value || "").trim() || "127.0.0.1";
}

function dsmPortForScheme(scheme: "http" | "https") {
  return scheme === "https" ? 5001 : 5000;
}

function directPublicBaseURL(host: string, scheme: "http" | "https", idpPort: number) {
  const accessHost = normalizedHost(host);
  return `${scheme}://${accessHost}:${idpPort || defaultIDPPort}`;
}

function reverseProxyPublicBaseURL(host: string, scheme: "http" | "https") {
  return `${scheme}://${normalizedHost(host)}`;
}

function derivedDSMURLs(host: string, scheme: "http" | "https") {
  const accessHost = normalizedHost(host);
  const dsmPort = dsmPortForScheme(scheme);
  return {
    dsm_redirect_url: `${scheme}://${accessHost}:${dsmPort}/`,
    helper_dsm_login_api: `${scheme}://${accessHost}:${dsmPort}/webapi/entry.cgi`
  };
}

function derivedSystemURLs(host: string, scheme: "http" | "https", idpPort: number) {
  return {
    public_base_url: directPublicBaseURL(host, scheme, idpPort),
    ...derivedDSMURLs(host, scheme)
  };
}

function urlScheme(value: unknown) {
  try {
    const parsed = new URL(String(value || ""));
    return parsed.protocol.replace(":", "");
  } catch {
    return "";
  }
}

function browserDSMProtocolMismatch(values: Partial<SystemSettingsUpdate>) {
  if (values.helper_dsm_login_mode !== "browser") {
    return "";
  }
  const idpScheme = values.access_scheme || "https";
  const dsmScheme = urlScheme(values.dsm_redirect_url);
  if (dsmScheme && dsmScheme !== idpScheme) {
    return "浏览器直登模式下，DSM 地址协议必须和 IDP 协议一致";
  }
  const apiScheme = urlScheme(values.helper_dsm_login_api);
  if (apiScheme && apiScheme !== idpScheme) {
    return "浏览器直登模式下，DSM Auth API 协议必须和 IDP 协议一致";
  }
  return "";
}

export function SystemSettingsFields({ section = "all" }: { section?: "all" | "access" | "dsm" | "security" } = {}) {
  const form = Form.useFormInstance<SystemSettingsUpdate>();
  const { message } = AntApp.useApp();
  const [detecting, setDetecting] = useState(false);
  const deploymentMode = normalizedDeploymentMode(Form.useWatch("deployment_mode", form));
  const publicBaseEditable = deploymentMode !== "direct";
  const dsmEditable = deploymentMode === "advanced";
  const adminPort = Number(Form.useWatch("admin_port", form) || 0);

  function syncDerivedURLs(next?: Partial<{ deployment_mode: DeploymentMode; access_host: string; access_scheme: "http" | "https"; idp_port: number }>) {
    const mode = normalizedDeploymentMode(next?.deployment_mode ?? form.getFieldValue("deployment_mode"));
    const scheme = next?.access_scheme || (form.getFieldValue("access_scheme") || "https") as "http" | "https";
    const host = next?.access_host ?? String(form.getFieldValue("access_host") || "");
    const idpPort = Number(next?.idp_port ?? form.getFieldValue("idp_port") ?? defaultIDPPort);
    if (mode === "direct") {
      form.setFieldsValue(derivedSystemURLs(host, scheme, idpPort));
      return;
    }
    if (mode === "reverse_proxy") {
      form.setFieldsValue({
        ...(next?.deployment_mode ? { public_base_url: reverseProxyPublicBaseURL(host, scheme) } : {}),
        ...derivedDSMURLs(host, scheme)
      });
      return;
    }
    if (next?.deployment_mode) {
      const currentPublicBaseURL = String(form.getFieldValue("public_base_url") || "");
      const currentDSMRedirectURL = String(form.getFieldValue("dsm_redirect_url") || "");
      const currentHelperAPI = String(form.getFieldValue("helper_dsm_login_api") || "");
      form.setFieldsValue({
        public_base_url: currentPublicBaseURL || directPublicBaseURL(host, scheme, idpPort),
        dsm_redirect_url: currentDSMRedirectURL || derivedDSMURLs(host, scheme).dsm_redirect_url,
        helper_dsm_login_api: currentHelperAPI || derivedDSMURLs(host, scheme).helper_dsm_login_api
      });
    }
  }

  async function discover() {
    const host = String(form.getFieldValue("access_host") ?? "").trim();
    const scheme = (form.getFieldValue("access_scheme") || "https") as "http" | "https";
    const idpPort = Number(form.getFieldValue("idp_port") || defaultIDPPort);
    const publicBaseURL = String(form.getFieldValue("public_base_url") || "").trim();
    if (!host) {
      message.error("请先填写访问 IP / 域名");
      return;
    }
    setDetecting(true);
    try {
      const result = await api.discoverSettings({
        deployment_mode: deploymentMode,
        access_host: host,
        access_scheme: scheme,
        idp_port: idpPort,
        public_base_url: publicBaseURL
      });
      if (deploymentMode === "direct") {
        form.setFieldsValue(result);
      } else {
        form.setFieldsValue({
          access_host: result.access_host,
          access_scheme: result.access_scheme,
          idp_port: result.idp_port,
          dsm_redirect_url: result.dsm_redirect_url,
          helper_dsm_login_api: result.helper_dsm_login_api
        });
      }
      const idpStatus = result.idp_detected
        ? `已检测到认证入口本机端口 ${result.idp_port}`
        : `未连接到认证入口，保留当前本机端口 ${result.idp_port}`;
      const dsmStatus = result.dsm_detected ? "已检测到 DSM" : "未检测到 DSM，已填入默认地址";
      if (deploymentMode === "direct") {
        (result.idp_detected ? message.success : message.warning)(`${idpStatus}；${dsmStatus}`);
      } else {
        const publicStatus = result.public_base_url_detected
          ? "反代公网地址可达"
          : "未从 NAS 侧验证反代公网地址，已保留原值";
        (result.idp_detected ? message.success : message.warning)(`${idpStatus}；${publicStatus}；${dsmStatus}`);
      }
    } catch (err) {
      message.error(err instanceof Error ? err.message : "检测失败");
    } finally {
      setDetecting(false);
    }
  }

  return (
    <Space direction="vertical" size={18} className="settings-stack">
      {(section === "all" || section === "access") && (
        <>
          <section className="settings-section">
            <div className="settings-section-head">
              <div>
                <h3>运行时边界</h3>
                <p>这些值来自套件启动环境，用来说明当前实例的实际监听位置。</p>
              </div>
            </div>
            <div className="form-grid">
              <Form.Item
                name="admin_port"
                label={<HelpLabel label="管理后台监听端口" help={systemFieldHelp.adminPort} />}
                extra={fieldEffectHelp.adminPort}
              >
                <InputNumber disabled controls={false} precision={0} className="settings-full-input" />
              </Form.Item>
              <Form.Item label="管理后台监听地址" extra="系统设置页不会修改管理后台监听地址；反向代理也不会取消 NAS 本机监听。">
                <Input disabled value={adminPort > 0 ? `0.0.0.0:${adminPort}` : "未配置"} />
              </Form.Item>
            </div>
          </section>

          <section className="settings-section">
            <div className="settings-section-head">
              <div>
                <h3>认证入口配置</h3>
                <p>配置 /idp 本机监听和身份平台看到的公网地址；管理后台监听不在此处修改。</p>
              </div>
            </div>
            <div className="form-grid">
              <Form.Item
                name="deployment_mode"
                label={<HelpLabel label="部署方式" help={systemFieldHelp.deploymentMode} />}
                extra={fieldEffectHelp.deploymentMode}
                rules={[{ required: true }]}
              >
                <Segmented
                  block
                  options={deploymentOptions}
                  onChange={(value) => syncDerivedURLs({ deployment_mode: value as DeploymentMode })}
                />
              </Form.Item>
              <Form.Item
                name="access_scheme"
                label={<HelpLabel label="认证入口本机协议" help={systemFieldHelp.accessScheme} />}
                extra={fieldEffectHelp.accessScheme}
                rules={[{ required: true }]}
              >
                <Segmented
                  block
                  options={[
                    { label: "HTTP", value: "http" },
                    { label: "HTTPS", value: "https" }
                  ]}
                  onChange={(value) => syncDerivedURLs({ access_scheme: value as "http" | "https" })}
                />
              </Form.Item>
              <Form.Item
                name="access_host"
                label={<HelpLabel label="NAS IP / 域名" help={systemFieldHelp.accessHost} />}
                extra={fieldEffectHelp.accessHost}
                rules={[{ required: true }]}
              >
                <Input
                  addonAfter={<Button htmlType="button" type="link" size="small" loading={detecting} onClick={() => void discover()}>检测</Button>}
                  onChange={(event) => syncDerivedURLs({ access_host: event.target.value })}
                />
              </Form.Item>
              <Form.Item
                name="idp_port"
                label={<HelpLabel label="认证入口本机端口" help={systemFieldHelp.idpPort} />}
                extra={fieldEffectHelp.idpPort}
                rules={[
                  { required: true },
                  ({ getFieldValue }) => ({
                    validator(_, value) {
                      const adminPort = Number(getFieldValue("admin_port") || 0);
                      if (adminPort > 0 && Number(value) === adminPort) {
                        return Promise.reject(new Error("认证入口本机端口不能与管理后台端口一致"));
                      }
                      return Promise.resolve();
                    }
                  })
                ]}
              >
                <InputNumber min={1025} max={65535} precision={0} onChange={(value) => syncDerivedURLs({ idp_port: Number(value) })} className="settings-full-input" />
              </Form.Item>
              <Form.Item
                name="public_base_url"
                label={<HelpLabel label="认证入口公网地址" help={systemFieldHelp.publicBaseURL} />}
                extra={publicBaseEditable ? fieldEffectHelp.publicBaseURLEditable : fieldEffectHelp.publicBaseURLLocked}
                rules={[{ required: true }]}
              >
                <Input disabled={!publicBaseEditable} placeholder="https://login.example.com" />
              </Form.Item>
            </div>
          </section>
        </>
      )}

      {(section === "all" || section === "dsm") && <section className="settings-section">
        <div className="settings-section-head">
          <div>
            <h3>DSM 登录链路</h3>
            <p>配置最终跳转到 DSM 的地址和 Helper 登录方式。</p>
          </div>
        </div>
        <ProtocolConsistencyNotice />
        <div className="form-grid">
          <Form.Item
            name="dsm_redirect_url"
            label={<HelpLabel label="DSM 地址" help={systemFieldHelp.dsmRedirectURL} />}
            extra={dsmEditable ? fieldEffectHelp.dsmRedirectURL : fieldEffectHelp.dsmLocked}
            rules={[{ required: true }]}
          >
            <Input disabled={!dsmEditable} placeholder="https://nas.example.com:5001/" />
          </Form.Item>
          <Form.Item
            name="helper_dsm_login_api"
            label={<HelpLabel label="DSM Auth API" help={systemFieldHelp.helperDSMLoginAPI} />}
            extra={dsmEditable ? fieldEffectHelp.helperDSMLoginAPI : fieldEffectHelp.dsmLocked}
            rules={[{ required: true }]}
          >
            <Input disabled={!dsmEditable} placeholder="https://nas.example.com:5001/webapi/entry.cgi" />
          </Form.Item>
          <Form.Item
            name="helper_dsm_login_mode"
            label={<HelpLabel label="DSM 登录模式" help={systemFieldHelp.helperDSMLoginMode} />}
            extra={fieldEffectHelp.helperDSMLoginMode}
            rules={[{ required: true }]}
          >
            <Select
              options={[
                { label: "直接连接", value: "browser" },
                { label: "Helper 连接", value: "helper" }
              ]}
            />
          </Form.Item>
          <Form.Item
            name="helper_dsm_browser_login_ttl_seconds"
            label={<HelpLabel label="直登 TTL 秒数" help={systemFieldHelp.helperDSMBrowserLoginTTL} />}
            extra={fieldEffectHelp.helperDSMBrowserLoginTTL}
            rules={[{ required: true }]}
          >
            <InputNumber min={1} max={60} precision={0} className="settings-full-input" />
          </Form.Item>
          <Form.Item
            name="helper_dsm_tls_skip_verify"
            label={<HelpLabel label="跳过 DSM TLS 校验" help={systemFieldHelp.helperDSMTLSSkipVerify} />}
            extra={fieldEffectHelp.helperDSMTLSSkipVerify}
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>
        </div>
      </section>}

      {(section === "all" || section === "security") && <section className="settings-section">
        <div className="settings-section-head">
          <div>
            <h3>访问安全</h3>
            <p>管理后台访问范围可在此配置；认证入口固定只接受 DSMPASS 实际看到的本机和内网来源。</p>
          </div>
        </div>
        <Form.Item extra={fieldEffectHelp.adminAllowedCIDRs}>
          <AdminAccessSwitch />
        </Form.Item>
      </section>}
    </Space>
  );
}

export function SystemSettings() {
  const [form] = Form.useForm<SystemSettingsUpdate>();
  const [passwordForm] = Form.useForm<AdminPasswordChange>();
  const { message } = AntApp.useApp();
  const { data, loading, error, reload } = useAsyncData(() => api.systemSettings(), []);
  const { data: overview, loading: overviewLoading, error: overviewError, reload: reloadOverview } = useAsyncData(() => api.systemSettingsOverview(), []);
  const [saving, setSaving] = useState(false);
  const [activeSection, setActiveSection] = useState<SettingsSectionKey>("overview");
  const [uploadingCert, setUploadingCert] = useState<CertificateScope | null>(null);
  const [restartingIDP, setRestartingIDP] = useState(false);
  const [refreshingTLS, setRefreshingTLS] = useState(false);
  const [adminCertFiles, setAdminCertFiles] = useState<UploadFile[]>([]);
  const [adminKeyFiles, setAdminKeyFiles] = useState<UploadFile[]>([]);
  const [idpCertFiles, setIDPCertFiles] = useState<UploadFile[]>([]);
  const [idpKeyFiles, setIDPKeyFiles] = useState<UploadFile[]>([]);

  useEffect(() => {
    if (data) {
      form.setFieldsValue({
        deployment_mode: data.deployment_mode || "direct",
        admin_port: data.admin_port,
        access_host: data.access_host,
        access_scheme: data.access_scheme || "https",
        idp_port: data.idp_port || defaultIDPPort,
        admin_allowed_cidrs: data.admin_allowed_cidrs,
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
    const protocolError = browserDSMProtocolMismatch(values);
    if (protocolError) {
      message.error(protocolError);
      return;
    }
    setSaving(true);
    try {
      const payload = { ...values };
      if (!payload.relay_helper_hmac_secret) {
        delete payload.relay_helper_hmac_secret;
      }
      const result = await api.updateSystemSettings(payload);
      if (result.idp_route_restart_required && result.idp_route_restarted === false) {
        message.warning(`配置已保存，但认证路由刷新失败：${result.idp_route_restart_error || "请检查端口占用后重试"}`);
      } else if (result.idp_route_restart_required) {
        message.success("已保存，认证路由已刷新");
      } else {
        message.success("已保存");
      }
      form.setFieldsValue({ relay_helper_hmac_secret: "" });
      await reload();
      await reloadOverview();
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

  async function uploadCertificate(scope: CertificateScope) {
    const certFiles = scope === "admin" ? adminCertFiles : idpCertFiles;
    const keyFiles = scope === "admin" ? adminKeyFiles : idpKeyFiles;
    const cert = selectedFile(certFiles);
    const key = selectedFile(keyFiles);
    if (!cert || !key) {
      message.error("请同时选择证书 PEM 和私钥 PEM");
      return;
    }
    setUploadingCert(scope);
    try {
      const result = await api.uploadCertificate(scope, cert, key);
      const certificateLabel = result.certificate_info?.label || "证书";
      const certificateName = result.certificate_info?.common_name || result.certificate_domains?.[0] || "";
      const certificateSuffix = certificateName ? `，识别为${certificateLabel}：${certificateName}` : `，识别为${certificateLabel}`;
      const refreshSuffix = result.connections_refreshed ? "，已断开空闲 HTTPS 连接，请刷新页面确认新证书" : "，请刷新页面确认新证书";
      if (scope === "admin") {
        message.success(`管理端证书已上传${certificateSuffix}，新建 HTTPS 连接会自动使用新证书${refreshSuffix}`);
        setAdminCertFiles([]);
        setAdminKeyFiles([]);
      } else if (result.applied_access_host) {
        message.success(`认证端证书已上传${certificateSuffix}，已自动将认证入口域名更新为 ${result.applied_access_host}，新建 HTTPS 连接会自动使用新证书${refreshSuffix}`);
        setIDPCertFiles([]);
        setIDPKeyFiles([]);
        await reload();
      } else {
        if (result.certificate_domains?.length) {
          message.success(`认证端证书已上传${certificateSuffix}，但未自动修改认证入口域名；请确认后手动设置认证入口域名，新建 HTTPS 连接会自动使用新证书${refreshSuffix}`);
        } else {
          message.success(`认证端证书已上传${certificateSuffix}，新建 HTTPS 连接会自动使用新证书${refreshSuffix}`);
        }
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

  async function refreshTLSConnections() {
    setRefreshingTLS(true);
    try {
      const result = await api.refreshTLSConnections();
      if (result.connections_refreshed) {
        message.success("已断开空闲 HTTPS 连接，请刷新页面确认新证书");
      } else {
        message.info("当前没有可刷新的 HTTPS 连接");
      }
    } catch (err) {
      message.error(err instanceof Error ? err.message : "刷新证书连接失败");
    } finally {
      setRefreshingTLS(false);
    }
  }

  async function refreshAll() {
    await Promise.all([reload(), reloadOverview()]);
  }

  return (
    <Space direction="vertical" size={16} className="page settings-page">
      <PageTitle title="系统设置" extra={<Button icon={<ReloadOutlined />} onClick={() => void refreshAll()}>刷新</Button>} />
      {error && <Alert type="error" showIcon message={error} />}
      {overviewError && <Alert type="error" showIcon message={overviewError} />}
      <div className="settings-console">
        <Menu
          mode="inline"
          className="settings-submenu"
          selectedKeys={[activeSection]}
          onClick={({ key }) => setActiveSection(key as SettingsSectionKey)}
          items={[
            { key: "overview", label: "系统说明" },
            { key: "access", label: "入口与域名" },
            { key: "dsm", label: "DSM 登录链路" },
            { key: "security", label: "访问安全" },
            { key: "certificates", label: "证书与路由" },
            { key: "account", label: "后台账号" }
          ]}
        />
        <div className="settings-console-body">
          {activeSection === "overview" && (
            <SystemOverviewCard overview={overview} loading={overviewLoading} />
          )}
          {(activeSection === "access" || activeSection === "dsm" || activeSection === "security") && (
            <Form form={form} layout="vertical" onFinish={(values) => void save(values)} disabled={loading || saving} className="settings-form">
              <Card
                title={settingsSectionTitle(activeSection)}
                className="module-card settings-card"
                extra={<Button type="primary" htmlType="submit" loading={saving}>保存配置</Button>}
              >
                <SystemSettingsFields section={activeSection} />
              </Card>
            </Form>
          )}
          {activeSection === "certificates" && (
            <Card title="证书与路由" className="module-card settings-card">
              <div className="settings-doc certificate-settings">
                <section className="settings-doc-intro">
                  <h2>证书作用范围</h2>
                  <p>管理端和认证端使用独立证书槽位。可以分别上传不同证书，也可以把同一张通配符证书分别上传到两个槽位。</p>
                  <p>证书上传后不需要重启套件，新建 HTTPS 连接会自动使用新证书。</p>
                </section>

                <section className="settings-doc-section">
                  <h3>证书槽位</h3>
                  <div className="certificate-slot-list">
                    <CertificateUploadFields
                      title="管理端证书"
                      description="用于管理后台 HTTPS，不会修改认证入口地址。"
                      certFiles={adminCertFiles}
                      keyFiles={adminKeyFiles}
                      onCertFiles={setAdminCertFiles}
                      onKeyFiles={setAdminKeyFiles}
                      disabled={loading || saving}
                      action={<Button icon={<UploadOutlined />} loading={uploadingCert === "admin"} onClick={() => void uploadCertificate("admin")}>上传管理端证书</Button>}
                    />
                    <CertificateUploadFields
                      title="认证端证书"
                      description="用于 /idp 登录入口；非通配符 DNS SAN 会同步为认证入口域名。"
                      certFiles={idpCertFiles}
                      keyFiles={idpKeyFiles}
                      onCertFiles={setIDPCertFiles}
                      onKeyFiles={setIDPKeyFiles}
                      disabled={loading || saving}
                      action={<Button icon={<UploadOutlined />} loading={uploadingCert === "idp"} onClick={() => void uploadCertificate("idp")}>上传认证端证书</Button>}
                    />
                  </div>
                </section>

                <section className="settings-doc-section">
                  <h3>路由维护</h3>
                  <div className="certificate-maintenance">
                    <p>通常上传证书后不需要手动操作。仅在浏览器仍复用旧连接，或认证入口路由需要重新绑定时使用下面的维护动作。</p>
                    <Flex gap={8} wrap>
                      <Button icon={<ReloadOutlined />} loading={refreshingTLS} onClick={() => void refreshTLSConnections()}>刷新证书连接</Button>
                      <Button icon={<SafetyCertificateOutlined />} loading={restartingIDP} onClick={() => void restartIDPRoute()}>重启认证路由</Button>
                    </Flex>
                  </div>
                </section>
              </div>
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

const overviewConfigSections = [
  {
    title: "入口与域名",
    keys: ["deployment_mode", "access_host", "access_scheme", "idp_port", "public_base_url"]
  },
  {
    title: "DSM 登录链路",
    keys: ["dsm_redirect_url", "helper_dsm_login_api", "helper_dsm_login_mode", "helper_dsm_browser_login_ttl_seconds", "helper_dsm_tls_skip_verify"]
  },
  {
    title: "访问安全",
    keys: ["admin_allowed_cidrs", "idp_access_boundary"]
  }
];

function settingsSectionTitle(section: SettingsSectionKey) {
  switch (section) {
    case "access":
      return "入口与域名";
    case "dsm":
      return "DSM 登录链路";
    case "security":
      return "访问安全";
    default:
      return "系统设置";
  }
}

function SystemOverviewCard({ overview, loading }: { overview: SystemSettingsOverview | null; loading: boolean }) {
  const summaryLead = overview?.summary.slice(0, 2) || [];
  const summaryDetails = overview?.summary.slice(2) || [];

  return (
    <Card title={overview?.title || "系统说明"} className="module-card settings-card" loading={loading && !overview}>
      {!overview ? (
        <Alert type="info" showIcon message="正在读取系统说明" />
      ) : (
        <div className="settings-doc">
          <section className="settings-doc-intro">
            <h2>系统运行边界</h2>
            {summaryLead.map((item) => (
              <p key={item}>{item}</p>
            ))}
            {summaryDetails.length > 0 && (
              <ul>
                {summaryDetails.map((item) => <li key={item}>{item}</li>)}
              </ul>
            )}
          </section>

          <OverviewRuntimeSection items={overview.runtime} />

          <OverviewModeSection items={overview.deployment_modes} />

          <OverviewConfigSections items={overview.configuration} certificates={overview.certificates} />

          <section className="settings-doc-section">
            <h3>操作注意</h3>
            <ol className="settings-note-list">
              {overview.operational_notes.map((item) => <li key={item}>{item}</li>)}
            </ol>
          </section>
        </div>
      )}
    </Card>
  );
}

function OverviewRuntimeSection({ items }: { items: SystemSettingsOverview["runtime"] }) {
  return (
    <section className="settings-doc-section">
      <h3>当前运行状态</h3>
      <div className="settings-definition-list">
        {items.map((item) => (
          <div className="settings-definition-row" key={item.title}>
            <div className="settings-definition-head">
              <span>{item.title}</span>
              <code>{item.value || "-"}</code>
            </div>
            <p>{item.description}</p>
            <OverviewMeta changeMethod={item.change_method} applies={item.applies} />
            {item.notes.length > 0 && (
              <ul>
                {item.notes.map((note) => <li key={note}>{note}</li>)}
              </ul>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}

function OverviewModeSection({ items }: { items: SystemSettingsOverview["deployment_modes"] }) {
  return (
    <section className="settings-doc-section">
      <h3>部署方式</h3>
      <div className="settings-mode-list">
        {items.map((item) => (
          <div className={item.value === "当前使用" ? "settings-mode-item active" : "settings-mode-item"} key={item.title}>
            <div>
              <strong>{item.title}</strong>
              <p>{item.description}</p>
            </div>
            <span>{item.value}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function OverviewConfigSections({
  items,
  certificates
}: {
  items: SystemSettingsOverview["configuration"];
  certificates: SystemSettingsOverview["certificates"];
}) {
  const itemsByKey = new Map(items.map((item) => [item.key, item]));
  const usedKeys = new Set<string>();
  const groupedSections = overviewConfigSections.map((section) => {
    const sectionItems = section.keys.flatMap((key) => {
      const item = itemsByKey.get(key);
      if (!item) {
        return [];
      }
      usedKeys.add(key);
      return [item];
    });
    return { ...section, items: sectionItems };
  });
  const remaining = items.filter((item) => !usedKeys.has(item.key));

  return (
    <>
      {groupedSections.map((section) => (
        section.items.length > 0 && (
          <section className="settings-doc-section" key={section.title}>
            <h3>{section.title}</h3>
            <OverviewConfigList items={section.items} />
          </section>
        )
      ))}
      {remaining.length > 0 && (
        <section className="settings-doc-section">
          <h3>其他配置</h3>
          <OverviewConfigList items={remaining} />
        </section>
      )}
      <section className="settings-doc-section">
        <h3>证书作用域</h3>
        <OverviewConfigList items={certificates} />
      </section>
    </>
  );
}

function OverviewConfigList({ items }: { items: SystemSettingsOverview["configuration"] }) {
  return (
    <div className="settings-policy-list">
      {items.map((item) => (
        <div className="settings-policy-row" key={item.key}>
          <div className="settings-policy-title">
            <span>{item.label}</span>
            <code>{item.value || "-"}</code>
          </div>
          <p>{item.effect}</p>
          <OverviewMeta changeMethod={item.change_method} applies={item.applies} />
          {item.notes.length > 0 && (
            <ul>
              {item.notes.map((note) => <li key={note}>{note}</li>)}
            </ul>
          )}
        </div>
      ))}
    </div>
  );
}

function OverviewMeta({ changeMethod, applies }: { changeMethod: string; applies: string }) {
  return (
    <div className="settings-meta-line">
      {changeMethod && <span>修改入口：{changeMethod}</span>}
      {applies && <span>生效方式：{applies}</span>}
    </div>
  );
}

function AdminAccessSwitch() {
  const form = Form.useFormInstance<SystemSettingsUpdate>();
  const value = Form.useWatch("admin_allowed_cidrs") as string | undefined;
  const intranetOnly = isPrivateCIDRSetting(value);

  function toggle(checked: boolean) {
    form.setFieldValue("admin_allowed_cidrs", checked ? privateCIDRs : allCIDRs);
  }

  return (
    <div className="settings-admin-access">
      <Form.Item name="admin_allowed_cidrs" hidden>
        <Input />
      </Form.Item>
      <div>
        <HelpLabel label={<strong>管理端仅允许内网访问</strong>} help={systemFieldHelp.adminAllowedCIDRs} />
        <p>关闭时管理后台不按来源网段限制；开启后仅允许本机、IPv4 内网和 IPv6 内网访问。</p>
      </div>
      <Switch checked={intranetOnly} onChange={toggle} checkedChildren="内网" unCheckedChildren="不限" />
    </div>
  );
}

function ProtocolConsistencyNotice() {
  const form = Form.useFormInstance<SystemSettingsUpdate>();
  const mode = Form.useWatch("helper_dsm_login_mode", form);
  const accessScheme = Form.useWatch("access_scheme", form);
  const dsmRedirectURL = Form.useWatch("dsm_redirect_url", form);
  const helperDSMLoginAPI = Form.useWatch("helper_dsm_login_api", form);
  const protocolError = browserDSMProtocolMismatch({
    helper_dsm_login_mode: mode,
    access_scheme: accessScheme,
    dsm_redirect_url: dsmRedirectURL,
    helper_dsm_login_api: helperDSMLoginAPI
  });

  if (mode !== "browser") {
    return null;
  }
  if (protocolError) {
    return <Alert type="error" showIcon className="settings-inline-alert" message={protocolError} />;
  }
  return (
    <Alert
      type="info"
      showIcon
      className="settings-inline-alert"
      message="浏览器直登模式下，DSM 地址和 DSM Auth API 会由浏览器直接访问，协议必须和 IDP 协议一致。"
    />
  );
}

function isPrivateCIDRSetting(value: string | undefined) {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized === "private" || normalized === "lan" || normalized === "local" || normalized === "intranet" || normalized === "内网") {
    return true;
  }
  const privateItems = privateCIDRs.split(",");
  return privateItems.every((item) => normalized.includes(item.toLowerCase()));
}

function CertificateUploadFields({
  title,
  description,
  certFiles,
  keyFiles,
  onCertFiles,
  onKeyFiles,
  disabled,
  action
}: {
  title: string;
  description: string;
  certFiles: UploadFile[];
  keyFiles: UploadFile[];
  onCertFiles: (files: UploadFile[]) => void;
  onKeyFiles: (files: UploadFile[]) => void;
  disabled?: boolean;
  action?: ReactNode;
}) {
  return (
    <div className="certificate-upload">
      <div className="certificate-upload-copy">
        <strong>{title}</strong>
        <p>{description}</p>
      </div>
      <div className="certificate-file-row">
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
      {action && <div className="certificate-upload-action">{action}</div>}
    </div>
  );
}
