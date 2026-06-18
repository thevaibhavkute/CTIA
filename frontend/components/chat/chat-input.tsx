"use client";

import { useState } from "react";
import { ArrowUp } from "lucide-react";

import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";

export function ChatInput({
  onSend,
  disabled,
}: {
  onSend: (text: string) => void;
  disabled: boolean;
}) {
  const [value, setValue] = useState("");

  const handleSend = () => {
    if (disabled || !value.trim()) return;
    onSend(value);
    setValue("");
  };

  return (
    <div className="mx-auto w-full max-w-3xl px-4 pb-6">
      <div className="glass gradient-border flex items-end gap-2 rounded-2xl p-2">
        <Textarea
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              handleSend();
            }
          }}
          placeholder="Ask about an IP, domain, hash, actor, or CVE..."
          rows={1}
          className="max-h-40 min-h-10 resize-none border-none bg-transparent shadow-none focus-visible:ring-0"
        />
        <button
          type="button"
          onClick={handleSend}
          disabled={disabled || !value.trim()}
          className={cn(
            "flex size-9 shrink-0 items-center justify-center rounded-full transition-opacity",
            "bg-gradient-to-br from-[var(--gradient-from)] to-[var(--gradient-to)] text-white",
            (disabled || !value.trim()) && "opacity-40",
          )}
        >
          <ArrowUp className="size-4" />
        </button>
      </div>
    </div>
  );
}
