import { motion } from "framer-motion";
import ReactMarkdown from "react-markdown";

import { EvidenceTable } from "@/components/chat/evidence-table";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { ChatMessage } from "@/lib/types";

export function MessageBubble({ message }: { message: ChatMessage }) {
  const isUser = message.role === "user";

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className={cn("flex w-full", isUser ? "justify-end" : "justify-start")}
    >
      <div className={cn("flex max-w-[80%] flex-col gap-1", isUser && "items-end")}>
        {message.injectionFlagged && (
          <Badge variant="outline" className="border-amber-500/40 bg-amber-500/15 text-amber-300">
            Prompt injection flagged
          </Badge>
        )}
        <div
          className={cn(
            "rounded-2xl px-4 py-3 text-sm leading-relaxed",
            isUser
              ? "gradient-border bg-gradient-to-br from-[var(--gradient-from)]/25 to-[var(--gradient-to)]/25 text-foreground whitespace-pre-wrap"
              : "glass text-foreground [&_ol]:list-decimal [&_ul]:list-disc [&_ol]:pl-5 [&_ul]:pl-5 [&_p:not(:last-child)]:mb-2 [&_strong]:font-semibold",
            message.isError && "border-rose-500/40 bg-rose-500/10 text-rose-200",
          )}
        >
          {isUser ? message.text : <ReactMarkdown>{message.text}</ReactMarkdown>}
        </div>
        {message.toolResults && message.toolResults.length > 0 && (
          <EvidenceTable results={message.toolResults} />
        )}
      </div>
    </motion.div>
  );
}
