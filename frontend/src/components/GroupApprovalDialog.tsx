import { Alert, Button, Modal, Space, Spin, Typography } from "antd";
import { useEffect, useState } from "react";
import { api } from "../api";
import type { DSMGroup } from "../types";

interface Props {
  group: DSMGroup;
  onClose: () => void;
  onApproved: () => Promise<void>;
}

export function GroupApprovalDialog({ group, onClose, onApproved }: Props) {
  const [ticket, setTicket] = useState<Awaited<ReturnType<typeof api.webGroupApproval>> | null>(null);
  const [error, setError] = useState("");
  const [verifying, setVerifying] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let active = true;
    setTicket(null);
    setError("");
    api.webGroupApproval(group.id, group.dsm_groupname, false)
      .then((result) => { if (active) setTicket(result); })
      .catch((cause: Error) => { if (active) setError(cause.message); });
    return () => { active = false; };
  }, [group.id, group.dsm_groupname, attempt]);

  async function confirm() {
    setVerifying(true);
    setError("");
    try {
      if (!ticket?.approved) {
        const result = await api.webGroupApproval(group.id, group.dsm_groupname, true);
        if (!result.approved) throw new Error("群组授权尚未完成");
      }
      await onApproved();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "群组验证失败");
    } finally {
      setVerifying(false);
    }
  }

  return (
    <Modal title={`网页授权 · ${group.dsm_groupname}`} open onCancel={onClose}
      maskClosable={!verifying} closable={!verifying} cancelText="关闭" cancelButtonProps={{ disabled: verifying }}
      okText={ticket?.approved ? "增量同步" : "验证并同步"} onOk={confirm}
      okButtonProps={{ disabled: !ticket }} confirmLoading={verifying}>
      <Space direction="vertical" size="middle" style={{ width: "100%" }}>
        {!ticket && !error && <Spin />}
        {ticket?.approved && <Typography.Text>这个群组已授权，可以直接同步。</Typography.Text>}
        {ticket && !ticket.approved && <>
          <Typography.Text>在群晖网页打开「控制面板 → 用户与群组 → 群组」，编辑「{ticket.groupname}」。在描述末尾加一个空格，粘贴下面的授权码并保存。</Typography.Text>
          <Typography.Text code copyable={{ text: ticket.code }}>{ticket.code}</Typography.Text>
          <Typography.Text type="secondary">授权码有效至 {ticket.expires_at && new Date(ticket.expires_at).toLocaleTimeString()}。验证成功后可从描述中删除。同步成员会继承该组已有的共享文件夹权限。</Typography.Text>
        </>}
        {error && <Alert type="error" showIcon message={error} action={<Button size="small" onClick={() => setAttempt((n) => n + 1)}>重新获取</Button>} />}
      </Space>
    </Modal>
  );
}
