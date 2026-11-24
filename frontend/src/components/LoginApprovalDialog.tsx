import { Alert, Button, Modal, Space, Spin, Typography } from "antd";
import { useEffect, useState } from "react";
import { api } from "../api";
import type { LoginAuditLog } from "../types";

interface Props {
  record: LoginAuditLog;
  onClose: () => void;
}

export function LoginApprovalDialog({ record, onClose }: Props) {
  const [ticket, setTicket] = useState<Awaited<ReturnType<typeof api.webLoginApproval>> | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true;
    setTicket(null);
    setError("");
    api.webLoginApproval(record.provider_slug, record.id, false)
      .then((result) => { if (active) setTicket(result); })
      .catch((cause: Error) => { if (active) setError(cause.message); });
    return () => { active = false; };
  }, [record.provider_slug, record.id, attempt]);

  async function verify() {
    if (ticket?.approved) { onClose(); return; }
    setBusy(true);
    setError("");
    try {
      const result = await api.webLoginApproval(record.provider_slug, record.id, true);
      if (!result.approved) throw new Error("登录归属尚未核实");
      setTicket(result);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "核实失败");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open title={`核实登录归属 · ${record.dsm_username}`} onCancel={onClose}
      okText={ticket?.approved ? "完成" : "验证并保存"} cancelText="关闭" onOk={verify}
      okButtonProps={{ disabled: !ticket }} confirmLoading={busy} closable={!busy}
      maskClosable={!busy} cancelButtonProps={{ disabled: busy }}>
      <Space direction="vertical" style={{ width: "100%" }}>
        {!ticket && !error && <Spin />}
        {ticket?.approved && <Alert type="success" showIcon message="已有有效登录绑定，可重新扫码登录。" />}
        {ticket && !ticket.approved && <>
          <Typography.Text>请核对钉钉员工 ID <Typography.Text code>{ticket.subject}</Typography.Text> 是否属于 DSM 用户「{record.dsm_username}」。确认后，该员工可以登录这个账号，并参与身份源的全量改密。</Typography.Text>
          <Typography.Text>在 DSM 控制面板的「用户与群组」中编辑此用户，在描述末尾加一个空格，粘贴下方确认码并保存，再点击「验证并保存」。</Typography.Text>
          <Typography.Text code copyable>{ticket.code}</Typography.Text>
          <Typography.Text type="secondary">确认码有效至 {ticket.expires_at && new Date(ticket.expires_at).toLocaleTimeString()}。验证后可从描述中移除。</Typography.Text>
        </>}
        {error && <Alert type="error" showIcon message={error} action={<Button size="small" onClick={() => setAttempt((n) => n + 1)}>重新获取</Button>} />}
      </Space>
    </Modal>
  );
}
