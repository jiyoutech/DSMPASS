import { Tag } from "antd";
import type { ProvisionStatus } from "../types";

const statusLabels: Record<string, string> = {
  pending: "待处理",
  created: "已创建",
  linked_existing: "已关联",
  disabled: "已禁用",
  conflict: "冲突",
  success: "成功",
  fail: "失败",
  failed: "失败",
  warning: "警告",
  pass: "通过",
  missing: "缺失",
  configured: "已配置",
  user: "用户",
  group: "群组",
  member: "成员",
  reachable: "可连接",
  unreachable: "不可连接",
  socket: "本地套接字"
};

const actionLabels: Record<string, string> = {
  create_identity: "创建身份",
  create_dsm_account: "创建 DSM 用户",
  create_dsm_group: "创建 DSM 群组",
  create_group_member: "创建成员关系",
  update_identity: "更新身份",
  link_existing: "关联已有对象",
  sync_dsm_user: "同步 DSM 用户",
  sync_dsm_group: "同步 DSM 群组",
  sync_dsm_group_member: "同步成员关系",
  disable_missing_dsm_user: "禁用已删除用户",
  create_or_update: "创建或更新",
  disable_missing: "禁用已删除",
  ensure_dsm_user: "准备 DSM 用户",
  ensure_dsm_group: "准备 DSM 群组",
  ensure_group_member: "准备成员关系",
  update_external_account: "更新外部账号",
  update_provider_group: "更新部门"
};

export function labelOf(value: unknown) {
  const text = String(value ?? "");
  return statusLabels[text] ?? actionLabels[text] ?? text;
}

export function statusTag(status: ProvisionStatus) {
  const color =
    status === "created" ? "success" : status === "pending" ? "processing" : status === "conflict" ? "error" : "default";
  return <Tag color={color}>{labelOf(status)}</Tag>;
}

export function actionTag(action: string) {
  const color = action.includes("member") ? "purple" : action.includes("group") ? "blue" : "cyan";
  return <Tag color={color}>{labelOf(action)}</Tag>;
}

export function resultTag(result: string) {
  const normalized = result.toLowerCase();
  const color = normalized === "success" || normalized === "pass" ? "success" : normalized === "fail" || normalized === "failed" ? "error" : "default";
  return <Tag color={color}>{labelOf(result)}</Tag>;
}

export function includesQuery(values: unknown[], query: string) {
  const text = query.trim().toLowerCase();
  if (!text) {
    return true;
  }
  return values.some((value) => String(value ?? "").toLowerCase().includes(text));
}
