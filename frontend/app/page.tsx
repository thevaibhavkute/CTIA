"use client";

import { ChatInput } from "@/components/chat/chat-input";
import { ChatWindow } from "@/components/chat/chat-window";
import { Header } from "@/components/layout/header";
import { useChat } from "@/hooks/use-chat";

export default function Home() {
  const { messages, isLoading, send, newSession } = useChat();

  return (
    <div className="flex flex-1 flex-col">
      <Header onNewSession={newSession} />
      <ChatWindow messages={messages} isLoading={isLoading} />
      <ChatInput onSend={send} disabled={isLoading} />
    </div>
  );
}
