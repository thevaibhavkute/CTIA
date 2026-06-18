import { ConfidenceBadge } from "@/components/chat/confidence-badge";
import { cn } from "@/lib/utils";
import type { ToolResultSummary } from "@/lib/types";

export function EvidenceTable({ results }: { results: ToolResultSummary[] }) {
  if (results.length === 0) return null;

  return (
    <div className="glass mt-3 rounded-xl p-3">
      <p className="mb-2 text-xs font-medium tracking-wide text-muted-foreground uppercase">
        Evidence sources
      </p>
      <div className="flex flex-col gap-1.5">
        {results.map((result) => (
          <div
            key={result.tool_name}
            className="flex items-center justify-between gap-3 text-sm"
          >
            <span className="capitalize">{result.tool_name}</span>
            <div className="flex items-center gap-2">
              <span
                className={cn(
                  "text-xs",
                  result.success ? "text-emerald-400" : "text-rose-400",
                )}
              >
                {result.success ? "OK" : "FAILED"}
              </span>
              {result.success && <ConfidenceBadge level={result.confidence_level} />}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
