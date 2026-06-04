const localTimeFormatter = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false
});

export function formatLocalTime(value: string | null | undefined) {
  if (!value) {
    return "-";
  }
  const parsed = parseServerTime(value);
  if (!parsed) {
    return value;
  }
  return localTimeFormatter.format(parsed);
}

function parseServerTime(value: string) {
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  const hasTimezone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(trimmed);
  const normalized = trimmed.includes("T") ? trimmed : trimmed.replace(" ", "T");
  const input = hasTimezone ? normalized : `${normalized}Z`;
  const date = new Date(input);
  if (Number.isNaN(date.getTime())) {
    return null;
  }
  return date;
}
