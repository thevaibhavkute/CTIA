"use client";

import { useEffect, useState } from "react";
import { ShieldAlert, SquarePen } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { getHealth } from "@/lib/api";

export function Header({ onNewSession }: { onNewSession: () => void }) {
  const [mockMode, setMockMode] = useState<boolean | null>(null);
  const [connected, setConnected] = useState<boolean | null>(null);

  useEffect(() => {
    getHealth()
      .then((health) => {
        setMockMode(health.mock_mode);
        setConnected(true);
      })
      .catch(() => setConnected(false));
  }, []);

  return (
    <header className="glass mx-4 mt-4 flex items-center justify-between rounded-2xl px-4 py-3">
      <div className="flex items-center gap-2">
        <ShieldAlert className="size-5 text-[var(--gradient-from)]" />
        <span className="gradient-text font-semibold tracking-tight">
          Threat Intelligence Agent
        </span>
      </div>
      <div className="flex items-center gap-3">
        {connected === false && (
          <Badge variant="outline" className="border-rose-500/40 bg-rose-500/15 text-rose-300">
            Backend unreachable
          </Badge>
        )}
        {mockMode && (
          <Badge variant="outline" className="border-amber-500/40 bg-amber-500/15 text-amber-300">
            Mock mode
          </Badge>
        )}
        <Separator orientation="vertical" className="h-5" />
        <button
          type="button"
          onClick={onNewSession}
          className="flex items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          <SquarePen className="size-4" />
          New chat
        </button>
      </div>
    </header>
  );
}
