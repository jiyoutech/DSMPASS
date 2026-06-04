import { QuestionCircleOutlined, ReloadOutlined } from "@ant-design/icons";
import { Alert, Button, Card, Flex, Popover, Space, Tooltip, Typography } from "antd";
import { useState } from "react";
import type { ReactNode } from "react";

const { Title } = Typography;

export function EntityList({ values, limit = 4, empty = "-" }: { values: string[]; limit?: number; empty?: ReactNode }) {
  if (values.length === 0) {
    return <>{empty}</>;
  }
  const visible = values.slice(0, limit);
  const hidden = values.length - visible.length;
  return (
    <div className="entity-list">
      {visible.map((value) => (
        <span className="entity-chip" key={value} title={value}>{value}</span>
      ))}
      {hidden > 0 && (
        <Popover
          trigger="click"
          placement="bottomLeft"
          content={
            <div className="entity-popover">
              {values.map((value) => <span className="entity-chip" key={value} title={value}>{value}</span>)}
            </div>
          }
        >
          <button type="button" className="entity-more">+{hidden}</button>
        </Popover>
      )}
    </div>
  );
}

export function IdentityCell({ primary, secondary }: { primary: ReactNode; secondary?: ReactNode }) {
  return (
    <div className="identity-cell">
      <strong>{primary}</strong>
      {secondary && <span>{secondary}</span>}
    </div>
  );
}

export function MetricStrip({ items }: { items: Array<{ label: string; value: ReactNode; tone?: "default" | "success" | "warning" | "danger" }> }) {
  return (
    <div className="metric-strip">
      {items.map((item) => (
        <div className={`metric-item metric-${item.tone ?? "default"}`} key={item.label}>
          <span>{item.label}</span>
          <strong>{item.value}</strong>
        </div>
      ))}
    </div>
  );
}

export function RelationCount({ value, label }: { value: number; label: string }) {
  return (
    <div className="relation-count">
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}

export function PageTitle({ title, extra }: { title: string; extra?: ReactNode }) {
  return (
    <div className="page-title">
      <Title level={3}>{title}</Title>
      {extra && <div className="page-actions">{extra}</div>}
    </div>
  );
}

export function HelpLabel({ label, help }: { label: ReactNode; help: ReactNode }) {
  return (
    <span className="field-help-label">
      <span>{label}</span>
      <Tooltip title={help} placement="top">
        <QuestionCircleOutlined className="field-help-icon" />
      </Tooltip>
    </span>
  );
}

export function SourceTable({
  error,
  reload,
  table,
  toolbar,
  metrics
}: {
  error: string | null;
  reload: () => Promise<void>;
  table: ReactNode;
  toolbar?: ReactNode;
  metrics?: ReactNode;
}) {
  const [refreshing, setRefreshing] = useState(false);

  async function handleReload() {
    setRefreshing(true);
    try {
      await reload();
    } finally {
      setRefreshing(false);
    }
  }

  return (
    <Space direction="vertical" size={16} className="page">
      {metrics}
      <Flex className="section-toolbar" justify="space-between" gap={12} wrap="wrap">
        <div>{toolbar}</div>
        <Button icon={<ReloadOutlined />} loading={refreshing} onClick={() => void handleReload()}>刷新</Button>
      </Flex>
      {error && <Alert type="error" showIcon message={error} />}
      <Card className="data-card">{table}</Card>
    </Space>
  );
}

export function LogBlock({ title, value, empty, tone }: { title: string; value: string | null | undefined; empty: string; tone?: "danger" }) {
  const hasValue = Boolean(value && value.trim());
  return (
    <div className={tone === "danger" && hasValue ? "log-block log-block-danger" : "log-block"}>
      <div className="log-block-title">{title}</div>
      <div className={hasValue ? "log-block-value" : "log-block-empty"}>{hasValue ? value : empty}</div>
    </div>
  );
}
