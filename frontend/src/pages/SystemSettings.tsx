import { ReloadOutlined, SafetyCertificateOutlined, UploadOutlined } from "@ant-design/icons";
import { Alert, App as AntApp, Button, Card, Flex, Form, Input, InputNumber, Menu, Segmented, Select, Space, Switch, Tag, Upload } from "antd";
import type { UploadFile } from "antd/es/upload/interface";
import { useEffect, useState } from "react";
import { api } from "../api";
import { HelpLabel, PageTitle } from "../components/common";
import { useAsyncData } from "../hooks/useAsyncData";
import type { AdminPasswordChange, SystemSettingsUpdate } from "../types";

const privateCIDRs = "private";
const allCIDRs = "all";
type SettingsSectionKey = "base" | "dsm" | "certificates" | "account";
type DeploymentMode = "direct" | "reverse_proxy" | "advanced";
type CertificateScope = "admin" | "idp";

const systemFieldHelp = {
  deploymentMode: "直接访问会自动生成所有地址；反向代理允许单独填写公网 IDP 地址；高级自定义允许分别填写 IDP、DSM 和 DSM Auth API 地址。",
  accessHost: "NAS 的 IP 或域名，用于检测并生成默认 DSM 地址和 DSM Auth API；填写主机名，不包含协议和路径。",
  accessScheme: "DSMPASS IDP 入口实际监听使用的协议。反向代理场景下，它可以不同于 IDP 对外地址的协议。",
  idpPort: "DSMPASS IDP 实际监听端口，必须大于 1024 且不能被占用。反向代理时公网地址可以不带这个端口。",
  adminAllowedCIDRs: "开启后，管理后台仅允许本机和内网访问。保存时后端会确认当前访问 IP 仍可访问，避免把自己锁在外面。",
  publicBaseURL: "用户浏览器和外部身份平台看到的 IDP 对外地址，用于生成 redirect_uri。反向代理时通常填写 https://login.example.com。",
  dsmRedirectURL: "登录完成后跳回的 DSM 访问地址。直接访问和反向代理模式会自动生成，高级自定义可手动填写。",
  helperDSMLoginMode: "直接连接：前端浏览器用临时密码调用 DSM Auth API，DSM 看到的是用户真实访问 IP；此模式下 DSM 地址协议必须和 IDP 协议一致。Helper 连接：由 NAS 上的 helper 后台调用 DSM Auth API。",
  helperDSMBrowserLoginTTL: "浏览器直登时临时密码保留的秒数，到期后 helper 自动恢复 shadow。",
  helperDSMLoginAPI: "需要登录的 NAS 的 DSM 登录接口地址。直接访问和反向代理模式会自动生成，高级自定义可手动填写。",
  helperDSMTLSSkipVerify: "控制辅助程序访问需要登录的 NAS 时是否跳过 DSM 证书校验。"
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
  return `${scheme}://${accessHost}:${idpPort || 25000}`;
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

export function SystemSettingsFields({ section = "all" }: { section?: "all" | "base" | "dsm" } = {}) {
  const form = Form.useFormInstance<SystemSettingsUpdate>();
  const { message } = AntApp.useApp();
  const [detecting, setDetecting] = useState(false);
  const deploymentMode = normalizedDeploymentMode(Form.useWatch("deployment_mode", form));
  const publicBaseEditable = deploymentMode !== "direct";
  const dsmEditable = deploymentMode === "advanced";

  function syncDerivedURLs(next?: Partial<{ deployment_mode: DeploymentMode; access_host: string; access_scheme: "http" | "https"; idp_port: number }>) {
    const mode = normalizedDeploymentMode(next?.deployment_mode ?? form.getFieldValue("deployment_mode"));
    const scheme = next?.access_scheme || (form.getFieldValue("access_scheme") || "https") as "http" | "https";
    const host = next?.access_host ?? String(form.getFieldValue("access_host") || "");
    const idpPort = Number(next?.idp_port ?? form.getFieldValue("idp_port") ?? 25000);
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
    const idpPort = Number(form.getFieldValue("idp_port") || 25000);
    if (!host) {
      message.error("请先填写访问 IP / 域名");
      return;
    }
    setDetecting(true);
    try {
      const result = await api.discoverSettings({ access_host: host, access_scheme: scheme, idp_port: idpPort });
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
      message.success(result.dsm_detected ? "已检测到 DSM" : "未检测到 DSM，已填入默认值");
    } catch (err) {
      message.error(err instanceof Error ? err.message : "检测失败");
    } finally {
      setDetecting(false);
    }
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
          <Form.Item name="deployment_mode" label={<HelpLabel label="部署方式" help={systemFieldHelp.deploymentMode} />} rules={[{ required: true }]}>
            <Segmented
              block
              options={deploymentOptions}
              onChange={(value) => syncDerivedURLs({ deployment_mode: value as DeploymentMode })}
            />
          </Form.Item>
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
          <Form.Item name="access_host" label={<HelpLabel label="NAS IP / 域名" help={systemFieldHelp.accessHost} />} rules={[{ required: true }]}>
            <Input
              addonAfter={<Button htmlType="button" type="link" size="small" loading={detecting} onClick={() => void discover()}>检测</Button>}
              onChange={(event) => syncDerivedURLs({ access_host: event.target.value })}
            />
          </Form.Item>
          <Form.Item name="idp_port" label={<HelpLabel label="IDP 监听端口" help={systemFieldHelp.idpPort} />} rules={[{ required: true }]}>
            <InputNumber min={1025} max={65535} precision={0} onChange={(value) => syncDerivedURLs({ idp_port: Number(value) })} />
          </Form.Item>
          <Form.Item name="public_base_url" label={<HelpLabel label="IDP 对外地址" help={systemFieldHelp.publicBaseURL} />} rules={[{ required: true }]}>
            <Input readOnly={!publicBaseEditable} placeholder="https://login.example.com" />
          </Form.Item>
        </div>
        <AdminAccessSwitch />
      </section>}

      {(section === "all" || section === "dsm") && <section className="settings-section">
        <div className="settings-section-head">
          <div>
            <h3>DSM 登录</h3>
            <p>配置最终跳转到 DSM 的地址和 Helper 登录方式。</p>
          </div>
          <Tag color="purple">DSM</Tag>
        </div>
        <ProtocolConsistencyNotice />
        <div className="form-grid">
          <Form.Item name="dsm_redirect_url" label={<HelpLabel label="DSM 地址" help={systemFieldHelp.dsmRedirectURL} />} rules={[{ required: true }]}>
            <Input readOnly={!dsmEditable} placeholder="https://nas.example.com:5001/" />
          </Form.Item>
          <Form.Item name="helper_dsm_login_api" label={<HelpLabel label="DSM Auth API" help={systemFieldHelp.helperDSMLoginAPI} />} rules={[{ required: true }]}>
            <Input readOnly={!dsmEditable} placeholder="https://nas.example.com:5001/webapi/entry.cgi" />
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
  const { message } = AntApp.useApp();
  const { data, loading, error, reload } = useAsyncData(() => api.systemSettings(), []);
  const [saving, setSaving] = useState(false);
  const [activeSection, setActiveSection] = useState<SettingsSectionKey>("base");
  const [uploadingCert, setUploadingCert] = useState<CertificateScope | null>(null);
  const [restartingIDP, setRestartingIDP] = useState(false);
  const [adminCertFiles, setAdminCertFiles] = useState<UploadFile[]>([]);
  const [adminKeyFiles, setAdminKeyFiles] = useState<UploadFile[]>([]);
  const [idpCertFiles, setIDPCertFiles] = useState<UploadFile[]>([]);
  const [idpKeyFiles, setIDPKeyFiles] = useState<UploadFile[]>([]);

  useEffect(() => {
    if (data) {
      form.setFieldsValue({
        deployment_mode: data.deployment_mode || "direct",
        access_host: data.access_host,
        access_scheme: data.access_scheme || "https",
        idp_port: data.idp_port || 25000,
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
      if (scope === "admin") {
        message.success(`管理端证书已上传${certificateSuffix}，重启 DSMPASS 套件后证书生效`);
        setAdminCertFiles([]);
        setAdminKeyFiles([]);
      } else if (result.applied_access_host) {
        message.success(`认证端证书已上传${certificateSuffix}，已自动将认证入口域名更新为 ${result.applied_access_host}，重启认证路由后证书生效`);
        setIDPCertFiles([]);
        setIDPKeyFiles([]);
        await reload();
      } else {
        if (result.certificate_domains?.length) {
          message.success(`认证端证书已上传${certificateSuffix}，但未自动修改认证入口域名；请确认后手动设置认证入口域名并重启认证路由`);
        } else {
          message.success(`认证端证书已上传${certificateSuffix}，可重启认证路由生效`);
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
            { key: "dsm", label: "DSM 登录" },
            { key: "certificates", label: "证书与路由" },
            { key: "account", label: "后台账号" }
          ]}
        />
        <div className="settings-console-body">
          {(activeSection === "base" || activeSection === "dsm") && (
            <Form form={form} layout="vertical" onFinish={(values) => void save(values)} disabled={loading || saving} className="settings-form">
              <Card
                title={activeSection === "base" ? "基础配置" : "DSM 登录"}
                className="module-card settings-card"
                extra={<Button type="primary" htmlType="submit" loading={saving}>保存配置</Button>}
              >
                <SystemSettingsFields section={activeSection} />
              </Card>
            </Form>
          )}
          {activeSection === "certificates" && (
            <Card title="证书与路由" className="module-card settings-card">
              <Alert
                type="info"
                showIcon
                className="settings-inline-alert"
                message="管理端和认证端可以分别上传证书；如果使用同一张通配符证书，也可以把同一套证书 PEM 和私钥 PEM 分别上传到两端。管理端证书需要重启 DSMPASS 套件后生效，认证端证书可重启认证路由生效。"
              />
              <div className="certificate-grid">
                <CertificateUploadFields
                  title="管理端证书"
                  description="用于管理后台 HTTPS。上传后不会修改 IDP 地址；需要重启 DSMPASS 套件后生效。"
                  certFiles={adminCertFiles}
                  keyFiles={adminKeyFiles}
                  onCertFiles={setAdminCertFiles}
                  onKeyFiles={setAdminKeyFiles}
                  disabled={loading || saving}
                />
                <CertificateUploadFields
                  title="认证端口证书"
                  description="用于 /idp 登录入口。优先读取非通配符 DNS SAN，并自动同步到 IDP 地址；通配符证书不会自动改写访问域名。"
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
