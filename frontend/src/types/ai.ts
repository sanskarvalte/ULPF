/**
 * ULPF Real AI Telemetry & Resolution Data Types.
 * 
 * Accurately models observable backend AI telemetry from:
 * - GET /api/v1/ai/status
 * - GET /api/v1/ai/metrics
 * - GET /api/v1/ai/resolutions
 */

export type OllamaStatusType = 'CONNECTED' | 'UNAVAILABLE' | 'TIMEOUT' | 'MODEL_NOT_FOUND' | 'UNKNOWN';

export type ParserSourceType = 'rule_based' | 'learned_cache' | 'ai_generated_dynamic' | 'deterministic_generic' | 'review_fallback' | 'unknown';

export type ResolutionStatusType = 'promoted' | 'cached' | 'skipped_known' | 'skipped_sufficient_confidence' | 'pending_review' | 'rejected' | 'unavailable' | 'timeout';

export interface AiStatus {
  provider: 'ollama';
  model: string;
  available: boolean;
  status: OllamaStatusType;
  air_gap_mode: boolean;
  models_detected: string[];
  host: string;
  timeout_seconds: number;
  error?: string;
}

export interface AiMetrics {
  ollama_calls: number;
  ollama_attempts: number;
  ollama_successes: number;
  ollama_failures: number;
  ollama_timeouts: number;
  ollama_latency_ms: number;
  last_latency_ms: number;
  ai_generated_parsers: number;
  learned_parser_reuses: number;
  review_required: number;
  parser_accuracy: number | null;
  validation_rate: number;
  semantic_classification_status: string;
  provider: 'ollama';
  model: string;
  air_gap_mode: boolean;
}

export interface AiResolution {
  fingerprint: string;
  source: string;
  format: string;
  parser_type: string;
  ai_used: boolean;
  model: string;
  ollama_calls: number;
  latency_ms: number;
  resolution_status: ResolutionStatusType | string;
  accuracy: number | null;
  confidence: number | null;
  promoted_status: 'promoted' | 'pending_review' | 'rejected' | string;
  timestamp: string;
}

export interface AiWorkbenchStats {
  status: string;
  ai_engine: 'READY' | 'UNAVAILABLE' | 'CONNECTING';
  ollama_status: OllamaStatusType;
  model: string;
  mode: string;
  unknown_formats_count: number;
  analyzed_samples_count: number;
  approved_parsers_count: number;
  learned_parser_reuses: number;
  ollama_latency_ms: number;
  avg_confidence_percent: number | null;
  validation_rate: number;
}
