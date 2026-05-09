import React, { useEffect, useRef } from "react";
import cytoscape from "cytoscape";

interface GraphData {
  nodes: Array<{
    id: string;
    label: string;
    type: string;
    service?: string;
  }>;
  edges: Array<{
    source: string;
    target: string;
    type: string;
  }>;
}

interface Props {
  data: GraphData;
  height?: number;
}

const TYPE_COLOR: Record<string, string> = {
  Function: "#3b82f6",
  APIEndpoint: "#10b981",
  Vulnerability: "#ef4444",
  Dependency: "#f59e0b",
  Service: "#8b5cf6",
};

export default function CytoscapeGraph({ data, height = 500 }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const elements: cytoscape.ElementDefinition[] = [
      ...data.nodes.map(n => ({
        data: {
          id: n.id,
          label: n.label,
          type: n.type,
          color: TYPE_COLOR[n.type] || "#6b7280",
        },
      })),
      ...data.edges.map((e, i) => ({
        data: {
          id: `e-${i}`,
          source: e.source,
          target: e.target,
          type: e.type,
        },
      })),
    ];

    cyRef.current = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "background-color": "data(color)",
            color: "#fff",
            "text-valign": "center",
            "text-halign": "center",
            "font-size": "10px",
            width: 50,
            height: 50,
            "text-wrap": "wrap",
            "text-max-width": "80px",
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "line-color": "#94a3b8",
            "target-arrow-color": "#94a3b8",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(type)",
            "font-size": "8px",
            color: "#64748b",
          },
        },
        {
          selector: "node:selected",
          style: {
            "border-width": 3,
            "border-color": "#fbbf24",
          },
        },
      ],
      layout: {
        name: data.nodes.length > 30 ? "cose" : "breadthfirst",
        directed: true,
        padding: 20,
      } as any,
    });

    return () => {
      cyRef.current?.destroy();
    };
  }, [data]);

  return (
    <div
      ref={containerRef}
      style={{ width: "100%", height, border: "1px solid #e2e8f0", borderRadius: 8 }}
    />
  );
}
