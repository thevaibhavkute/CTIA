export type ConfidenceLevel = "HIGH" | "MEDIUM" | "LOW";

export interface ChatRequest {
  message: string;
  session_id?: string | null;
}

export interface ToolResultSummary {
  tool_name: string;
  success: boolean;
  confidence: number;
  confidence_level: ConfidenceLevel;
}

export interface ChatResponse {
  session_id: string;
  message: string;
  confidence: Record<string, number>;
  tool_results: ToolResultSummary[];
  injection_flagged: boolean;
  turn: number;
  error: string | null;
}

export interface HealthResponse {
  status: "ok";
  mock_mode: boolean;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  username: string;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  text: string;
  toolResults?: ToolResultSummary[];
  injectionFlagged?: boolean;
  isError?: boolean;
}
