import React from "react";

const COLORS: Record<string, { bg: string; text: string }> = {
  CRITICAL: { bg: "#dc2626", text: "#fff" },
  HIGH:     { bg: "#ea580c", text: "#fff" },
  MEDIUM:   { bg: "#ca8a04", text: "#fff" },
  LOW:      { bg: "#16a34a", text: "#fff" },
  NONE:     { bg: "#6b7280", text: "#fff" },
};

interface Props {
  level: string;
}

export default function RiskBadge({ level }: Props) {
  const { bg, text } = COLORS[level] || COLORS.NONE;
  return (
    <span style={{
      background: bg,
      color: text,
      padding: "2px 10px",
      borderRadius: 12,
      fontWeight: 700,
      fontSize: 12,
      letterSpacing: "0.05em",
      textTransform: "uppercase",
    }}>
      {level}
    </span>
  );
}
