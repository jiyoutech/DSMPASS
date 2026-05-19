import { ReloadOutlined, UploadOutlined } from "@ant-design/icons";
import { Alert, App as AntApp, Button, Card, Flex, Form, Input, InputNumber, Segmented, Select, Space, Switch, Upload } from "antd";
import type { UploadFile } from "antd/es/upload/interface";
import { useEffect, useState } from "react";
import { api } from "../api";
import { HelpLabel, PageTitle } from "../components/common";
import { useAsyncData } from "../hooks/useAsyncData";
import type { AdminPasswordChange, SystemSettingsUpdate } from "../types";

const systemFieldHelp = {
  accessHost: "需要登录的 NAS 的 IP 或域名，用于检测并生成 IDP 地址、DSM 地址和 DSM Auth API；填写主机名，不包含协议和路径。",
  accessScheme: "IDP 登录入口使用的协议。/idp/.../launch、OAuth callback 和 redirect_uri 会使用这个协议；管理后台协议由 SPK 安装配置决定。",
  idpPort: "用户登录入口对外端口，必须大于 1024 且不能被占用。登录入口 /idp/.../launch 和 OAuth callback 会使用 IDP 地址里的这个端口。",
  adminAllowedCIDRs: "管理后台允许访问的来源网段。默认仅允许本机、IPv4 内网和 IPv6 内网。多个网段用逗号、空格或换行分隔。",
  idpAllowedCIDRs: "认证入口允许访问的来源网段。默认允许所有网络访问；如只给内网使用，可以填写内网 CIDR。",
  publicBaseURL: "IDP 对外入口地址，由 IDP 协议、访问 IP / 域名和 IDP 入口端口自动生成，不能手动修改协议。",
  dsmRedirectURL: "需要登录的 NAS 的 DSM 访问地址，由 IDP 协议和访问 IP / 域名自动生成。HTTP 使用 5000，HTTPS 使用 5001。",
  helperDSMLoginMode: "直接连接：前端浏览器用临时密码调用 DSM Auth API，DSM 看到的是用户真实访问 IP，适合开启 DSM IP 验证。Helper 连接：由 NAS 上的 helper 后台调用 DSM Auth API，DSM 看到的是 NAS 本机请求；不依赖浏览器跨域，但 IP 验证不会按用户来源判断。",
  helperDSMBrowserLoginTTL: "浏览器直登时临时密码保留的秒数，到期后 helper 自动恢复 shadow。",
  helperDSMLoginAPI: "需要登录的 NAS 的 DSM 登录接口地址，由 DSM 地址自动生成。浏览器直登和辅助程序后台登录都会使用这个接口。",
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

export function SystemSettingsFields() {
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

  return (
    <div className="form-grid">
      <Form.Item
        name="access_scheme"
        label={<HelpLabel label="IDP 协议" help={systemFieldHelp.accessScheme} />}
        rules={[{ required: true }]}
      >
        <Segmented
          block
          options={[
            { label: "HTTP", value: "http" },
            { label: "HTTPS", value: "https" }
          ]}
          onChange={(value) => {
            const scheme = value as "http" | "https";
            syncDerivedURLs({ access_scheme: scheme });
          }}
        />
      </Form.Item>
      <Form.Item
        name="access_host"
        label={<HelpLabel label="访问 IP / 域名" help={systemFieldHelp.accessHost} />}
        rules={[{ required: true }]}
      >
        <Input
          addonAfter={<Button htmlType="button" type="link" size="small" loading={detecting} onClick={() => void discover()}>检测</Button>}
          onChange={(event) => syncDerivedURLs({ access_host: event.target.value })}
        />
      </Form.Item>
      <Form.Item
        name="idp_port"
        label={<HelpLabel label="IDP 入口端口" help={systemFieldHelp.idpPort} />}
        rules={[{ required: true }]}
      >
        <InputNumber
          min={1025}
          max={65535}
          precision={0}
          style={{ width: "100%" }}
          onChange={(value) => {
            syncDerivedURLs({ idp_port: Number(value) });
          }}
        />
      </Form.Item>
      <Form.Item
        name="admin_allowed_cidrs"
        label={<HelpLabel label="管理端口允许网段" help={systemFieldHelp.adminAllowedCIDRs} />}
        rules={[{ required: true }]}
      >
        <Input.TextArea autoSize={{ minRows: 2, maxRows: 5 }} />
      </Form.Item>
      <Form.Item
        name="idp_allowed_cidrs"
        label={<HelpLabel label="认证端口允许网段" help={systemFieldHelp.idpAllowedCIDRs} />}
        rules={[{ required: true }]}
      >
        <Input.TextArea autoSize={{ minRows: 2, maxRows: 5 }} />
      </Form.Item>
      <Form.Item
        name="public_base_url"
        label={<HelpLabel label="IDP 地址" help={systemFieldHelp.publicBaseURL} />}
        rules={[{ required: true }]}
      >
        <Input readOnly />
      </Form.Item>
      <Form.Item
        name="dsm_redirect_url"
        label={<HelpLabel label="DSM 地址" help={systemFieldHelp.dsmRedirectURL} />}
        rules={[{ required: true }]}
      >
        <Input readOnly />
      </Form.Item>
      <Form.Item
        name="helper_dsm_login_api"
        label={<HelpLabel label="DSM Auth API" help={systemFieldHelp.helperDSMLoginAPI} />}
        rules={[{ required: true }]}
      >
        <Input readOnly />
      </Form.Item>
      <Form.Item
        name="helper_dsm_login_mode"
        label={<HelpLabel label="DSM 登录模式" help={systemFieldHelp.helperDSMLoginMode} />}
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
        rules={[{ required: true }]}
      >
        <InputNumber min={1} max={60} precision={0} style={{ width: "100%" }} />
      </Form.Item>
      <Form.Item
        name="helper_dsm_tls_skip_verify"
        label={<HelpLabel label="跳过 DSM TLS 校验" help={systemFieldHelp.helperDSMTLSSkipVerify} />}
        valuePropName="checked"
      >
        <Switch />
      </Form.Item>
    </div>
  );
}

export function SystemSettings() {
  const [form] = Form.useForm<SystemSettingsUpdate>();
  const [passwordForm] = Form.useForm<AdminPasswordChange>();
  const { message } = AntApp.useApp();
  const { data, loading, error, reload } = useAsyncData(() => api.systemSettings(), []);
  const [saving, setSaving] = useState(false);
  const [uploadingCert, setUploadingCert] = useState<"admin" | "idp" | null>(null);
  const [restartingIDP, setRestartingIDP] = useState(false);
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
        message.success("管理端证书已上传，重启套件后生效");
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

  return (
    <Space direction="vertical" size={16} className="page">
      <PageTitle title="系统设置" extra={<Button icon={<ReloadOutlined />} onClick={() => void reload()}>刷新</Button>} />
      {error && <Alert type="error" showIcon message={error} />}
      <Form form={form} layout="vertical" onFinish={(values) => void save(values)} disabled={loading || saving} className="settings-form">
        <Space direction="vertical" size={16} className="page">
          <Card title="DSM" className="module-card">
            <SystemSettingsFields />
            <Flex justify="end">
              <Button type="primary" htmlType="submit" loading={saving}>保存</Button>
            </Flex>
          </Card>
          <Card title="证书" className="module-card">
            <div className="form-grid">
              <CertificateUploadFields
                title="管理端口证书"
                certFiles={adminCertFiles}
                keyFiles={adminKeyFiles}
                onCertFiles={setAdminCertFiles}
                onKeyFiles={setAdminKeyFiles}
                disabled={loading || saving}
              />
              <CertificateUploadFields
                title="认证端口证书"
                certFiles={idpCertFiles}
                keyFiles={idpKeyFiles}
                onCertFiles={setIDPCertFiles}
                onKeyFiles={setIDPKeyFiles}
                disabled={loading || saving}
              />
            </div>
            <Flex justify="end" gap={8} wrap>
              <Button loading={uploadingCert === "admin"} onClick={() => void uploadCertificate("admin")}>上传管理端证书</Button>
              <Button loading={uploadingCert === "idp"} onClick={() => void uploadCertificate("idp")}>上传认证端证书</Button>
              <Button type="primary" loading={restartingIDP} onClick={() => void restartIDPRoute()}>重启认证路由</Button>
            </Flex>
          </Card>
        </Space>
      </Form>
      <Card title="后台账号" className="module-card">
        <Form form={passwordForm} layout="vertical" onFinish={(values) => void changePassword(values)} disabled={saving}>
          <div className="form-grid">
            <Form.Item name="username" label="账号"><Input autoComplete="username" /></Form.Item>
            <Form.Item name="current_password" label="当前密码" rules={[{ required: true }]}><Input.Password autoComplete="current-password" /></Form.Item>
            <Form.Item name="new_password" label="新密码" rules={[{ required: true }]}><Input.Password autoComplete="new-password" /></Form.Item>
          </div>
          <Flex justify="end">
            <Button type="primary" htmlType="submit" loading={saving}>保存</Button>
          </Flex>
        </Form>
      </Card>
    </Space>
  );
}

function selectedFile(files: UploadFile[]) {
  return files[0]?.originFileObj;
}

function CertificateUploadFields({
  title,
  certFiles,
  keyFiles,
  onCertFiles,
  onKeyFiles,
  disabled
}: {
  title: string;
  certFiles: UploadFile[];
  keyFiles: UploadFile[];
  onCertFiles: (files: UploadFile[]) => void;
  onKeyFiles: (files: UploadFile[]) => void;
  disabled?: boolean;
}) {
  return (
    <div className="certificate-upload">
      <strong>{title}</strong>
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
