"use client";

import { useCallback, useState } from "react";

import { postChat } from "@/lib/api";
import { clearStoredSessionId, getStoredSessionId, setStoredSessionId } from "@/lib/session";
import type { ChatMessage } from "@/lib/types";

export function useChat() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const send = useCallback(async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed) return;

    const userMessage: ChatMessage = {
      id: crypto.randomUUID(),
      role: "user",
      text: trimmed,
    };
    setMessages((prev) => [...prev, userMessage]);
    setIsLoading(true);

    try {
      const response = await postChat({
        message: trimmed,
        session_id: getStoredSessionId(),
      });
      setStoredSessionId(response.session_id);

      const assistantMessage: ChatMessage = {
        id: crypto.randomUUID(),
        role: "assistant",
        text: response.error ?? response.message,
        toolResults: response.tool_results,
        injectionFlagged: response.injection_flagged,
        isError: response.error !== null,
      };
      setMessages((prev) => [...prev, assistantMessage]);
    } catch (err) {
      const assistantMessage: ChatMessage = {
        id: crypto.randomUUID(),
        role: "assistant",
        text: err instanceof Error ? err.message : "Could not reach the agent.",
        isError: true,
      };
      setMessages((prev) => [...prev, assistantMessage]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const newSession = useCallback(() => {
    clearStoredSessionId();
    setMessages([]);
  }, []);

  return { messages, isLoading, send, newSession };
}
