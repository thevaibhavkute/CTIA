import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { ConfidenceLevel } from "@/lib/types";

const LEVEL_STYLES: Record<ConfidenceLevel, string> = {
  HIGH: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  MEDIUM: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  LOW: "bg-rose-500/15 text-rose-300 border-rose-500/30",
};

export function ConfidenceBadge({ level }: { level: ConfidenceLevel }) {
  return (
    <Badge variant="outline" className={cn("font-medium", LEVEL_STYLES[level])}>
      {level}
    </Badge>
  );
}
