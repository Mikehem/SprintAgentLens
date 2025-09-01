/**
 * LLM Provider management type definitions with enterprise authentication
 * All operations include workspace isolation and API key security
 */

import type { AuthenticatedUser } from './auth';

export interface LLMProviderConfiguration {
  name: string;
  type: LLMProviderType;
  endpoint?: string;
  apiVersion?: string;
  region?: string;
  defaultModel?: string;
  supportedModels: string[];
  capabilities: LLMCapabilities;
  rateLimits: LLMRateLimits;
  costConfig: LLMCostConfiguration;
  metadata?: Record<string, any>;
}

export type LLMProviderType = 
  | 'openai'
  | 'anthropic'
  | 'google'
  | 'azure'
  | 'huggingface'
  | 'cohere'
  | 'custom';

export interface LLMCapabilities {
  chat: boolean;
  completion: boolean;
  embedding: boolean;
  functionCalling: boolean;
  vision: boolean;
  streaming: boolean;
  jsonMode: boolean;
  systemMessages: boolean;
  maxTokens: number;
  maxContextLength: number;
  supportedLanguages?: string[];
}

export interface LLMRateLimits {
  requestsPerMinute: number;
  tokensPerMinute: number;
  requestsPerDay?: number;
  tokensPerDay?: number;
  concurrentRequests: number;
}

export interface LLMCostConfiguration {
  inputTokenCost: number;  // Cost per 1K input tokens
  outputTokenCost: number; // Cost per 1K output tokens
  requestCost?: number;    // Fixed cost per request
  currency: string;
  billingUnit: 'token' | 'character' | 'request';
}

export interface CreateLLMProviderRequest {
  name: string;
  type: LLMProviderType;
  workspaceId: string;
  configuration: LLMProviderConfiguration;
  encryptedApiKey: string;
  isActive?: boolean;
  tags?: string[];
}

export interface UpdateLLMProviderRequest {
  name?: string;
  configuration?: Partial<LLMProviderConfiguration>;
  encryptedApiKey?: string;
  isActive?: boolean;
  tags?: string[];
}

export interface LLMProviderResponse {
  id: string;
  name: string;
  type: LLMProviderType;
  workspaceId: string;
  workspaceName: string;
  configuration: LLMProviderConfiguration;
  hasApiKey: boolean; // Don't expose actual key
  isActive: boolean;
  tags: string[];
  status: LLMProviderStatus;
  lastUsedAt?: Date;
  usageCount: number;
  totalCost: number;
  createdAt: Date;
  createdBy: string;
  createdByName: string;
  lastUpdatedAt: Date;
  lastUpdatedBy: string | null;
  lastUpdatedByName: string | null;
  // Health check information
  healthStatus?: LLMProviderHealthStatus;
  lastHealthCheck?: Date;
  // Permissions
  canRead: boolean;
  canEdit: boolean;
  canDelete: boolean;
  canUse: boolean;
  canViewUsage: boolean;
  canManageKeys: boolean;
}

export type LLMProviderStatus = 
  | 'active'
  | 'inactive'
  | 'error'
  | 'rate_limited'
  | 'maintenance'
  | 'suspended';

export interface LLMProviderHealthStatus {
  isHealthy: boolean;
  latency: number; // milliseconds
  errorRate: number; // percentage
  lastError?: string;
  lastErrorAt?: Date;
  uptime: number; // percentage
}

export interface LLMProviderListRequest {
  workspaceId?: string;
  type?: LLMProviderType[];
  status?: LLMProviderStatus[];
  tags?: string[];
  search?: string;
  isActive?: boolean;
  sortBy?: 'name' | 'type' | 'created_at' | 'last_used_at' | 'usage_count' | 'status';
  sortOrder?: 'asc' | 'desc';
  page?: number;
  limit?: number;
}

export interface LLMProviderListResponse {
  providers: LLMProviderResponse[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
  filters: {
    workspaceId?: string;
    type?: LLMProviderType[];
    status?: LLMProviderStatus[];
    tags?: string[];
  };
  sorting: {
    sortBy: string;
    sortOrder: 'asc' | 'desc';
  };
  aggregations: {
    typeCounts: Record<LLMProviderType, number>;
    statusCounts: Record<LLMProviderStatus, number>;
    totalCost: number;
    totalUsage: number;
  };
}

// Chat Completion Types
export interface LLMChatRequest {
  providerId: string;
  model: string;
  messages: LLMMessage[];
  parameters?: LLMChatParameters;
  metadata?: LLMRequestMetadata;
}

export interface LLMMessage {
  role: 'system' | 'user' | 'assistant' | 'function';
  content: string;
  name?: string; // For function calls
  functionCall?: LLMFunctionCall;
}

export interface LLMFunctionCall {
  name: string;
  arguments: string; // JSON string
}

export interface LLMChatParameters {
  temperature?: number;
  maxTokens?: number;
  topP?: number;
  topK?: number;
  frequencyPenalty?: number;
  presencePenalty?: number;
  stopSequences?: string[];
  stream?: boolean;
  functions?: LLMFunction[];
  functionCall?: 'auto' | 'none' | { name: string };
}

export interface LLMFunction {
  name: string;
  description: string;
  parameters: {
    type: 'object';
    properties: Record<string, any>;
    required?: string[];
  };
}

export interface LLMRequestMetadata {
  experimentId?: string;
  datasetItemId?: string;
  userId: string;
  workspaceId: string;
  tags?: string[];
  customFields?: Record<string, any>;
}

export interface LLMChatResponse {
  id: string;
  model: string;
  choices: LLMChoice[];
  usage: LLMUsage;
  cost: LLMCost;
  latency: number; // milliseconds
  metadata: LLMResponseMetadata;
}

export interface LLMChoice {
  index: number;
  message: LLMMessage;
  finishReason: 'stop' | 'length' | 'function_call' | 'content_filter' | 'error';
}

export interface LLMUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
}

export interface LLMCost {
  inputCost: number;
  outputCost: number;
  totalCost: number;
  currency: string;
}

export interface LLMResponseMetadata {
  providerId: string;
  providerType: LLMProviderType;
  requestId: string;
  timestamp: Date;
  cached?: boolean;
  retryCount?: number;
}

// Streaming Types
export interface LLMStreamRequest extends LLMChatRequest {
  parameters: LLMChatParameters & { stream: true };
}

export interface LLMStreamChunk {
  id: string;
  choices: Array<{
    index: number;
    delta: {
      role?: string;
      content?: string;
      functionCall?: Partial<LLMFunctionCall>;
    };
    finishReason?: string;
  }>;
}

// Embedding Types
export interface LLMEmbeddingRequest {
  providerId: string;
  model: string;
  input: string | string[];
  metadata?: LLMRequestMetadata;
}

export interface LLMEmbeddingResponse {
  id: string;
  model: string;
  embeddings: number[][];
  usage: {
    tokens: number;
  };
  cost: LLMCost;
  metadata: LLMResponseMetadata;
}

// Provider Management
export interface LLMProviderUsageStats {
  providerId: string;
  timeRange: {
    start: Date;
    end: Date;
  };
  metrics: {
    totalRequests: number;
    totalTokens: number;
    totalCost: number;
    averageLatency: number;
    errorRate: number;
    successRate: number;
  };
  breakdown: {
    byModel: Record<string, {
      requests: number;
      tokens: number;
      cost: number;
    }>;
    byUser: Record<string, {
      requests: number;
      tokens: number;
      cost: number;
    }>;
    byExperiment: Record<string, {
      requests: number;
      tokens: number;
      cost: number;
    }>;
  };
  trends: Array<{
    timestamp: Date;
    requests: number;
    tokens: number;
    cost: number;
    latency: number;
  }>;
}

export interface LLMProviderHealthCheckRequest {
  providerId: string;
  includeLatencyTest?: boolean;
  testModel?: string;
}

export interface LLMProviderHealthCheckResponse {
  providerId: string;
  isHealthy: boolean;
  status: LLMProviderStatus;
  checks: {
    connectivity: {
      success: boolean;
      latency?: number;
      error?: string;
    };
    authentication: {
      success: boolean;
      error?: string;
    };
    modelAvailability: {
      success: boolean;
      availableModels: string[];
      error?: string;
    };
    rateLimits: {
      remainingRequests?: number;
      remainingTokens?: number;
      resetTime?: Date;
    };
  };
  timestamp: Date;
}

// Bulk Operations
export interface BulkLLMProviderOperationRequest {
  providerIds: string[];
  operation: 'activate' | 'deactivate' | 'delete' | 'health_check' | 'update_config';
  options?: {
    configuration?: Partial<LLMProviderConfiguration>;
    force?: boolean;
  };
}

export interface BulkLLMProviderOperationResponse {
  requestId: string;
  operation: string;
  status: 'completed' | 'partial_success' | 'failed';
  processedCount: number;
  totalCount: number;
  results: Array<{
    providerId: string;
    status: 'success' | 'failed';
    error?: string;
  }>;
}

// Permission checking functions
export interface LLMProviderPermissionChecker {
  canCreateProvider(user: AuthenticatedUser, workspaceId: string): boolean;
  canReadProvider(user: AuthenticatedUser, provider: any): boolean;
  canEditProvider(user: AuthenticatedUser, provider: any): boolean;
  canDeleteProvider(user: AuthenticatedUser, provider: any): boolean;
  canUseProvider(user: AuthenticatedUser, provider: any): boolean;
  canViewUsage(user: AuthenticatedUser, provider: any): boolean;
  canManageKeys(user: AuthenticatedUser, provider: any): boolean;
}

// Error types
export class LLMProviderNotFoundError extends Error {
  constructor(providerId: string) {
    super(`LLM provider not found: ${providerId}`);
    this.name = 'LLMProviderNotFoundError';
  }
}

export class LLMProviderPermissionError extends Error {
  constructor(action: string, providerId: string) {
    super(`Permission denied: ${action} on LLM provider ${providerId}`);
    this.name = 'LLMProviderPermissionError';
  }
}

export class LLMProviderValidationError extends Error {
  constructor(field: string, message: string) {
    super(`Validation error on ${field}: ${message}`);
    this.name = 'LLMProviderValidationError';
  }
}

export class LLMProviderConfigurationError extends Error {
  constructor(provider: string, message: string) {
    super(`Configuration error for ${provider}: ${message}`);
    this.name = 'LLMProviderConfigurationError';
  }
}

export class LLMProviderRateLimitError extends Error {
  constructor(provider: string, retryAfter?: number) {
    super(`Rate limit exceeded for ${provider}${retryAfter ? `, retry after ${retryAfter}s` : ''}`);
    this.name = 'LLMProviderRateLimitError';
  }
}

export class LLMProviderQuotaExceededError extends Error {
  constructor(provider: string, quotaType: string) {
    super(`Quota exceeded for ${provider}: ${quotaType}`);
    this.name = 'LLMProviderQuotaExceededError';
  }
}

// Default configurations for popular providers
export const DEFAULT_LLM_PROVIDERS: Record<LLMProviderType, Partial<LLMProviderConfiguration>> = {
  openai: {
    type: 'openai',
    endpoint: 'https://api.openai.com/v1',
    apiVersion: 'v1',
    supportedModels: ['gpt-4', 'gpt-4-turbo', 'gpt-3.5-turbo'],
    capabilities: {
      chat: true,
      completion: true,
      embedding: true,
      functionCalling: true,
      vision: true,
      streaming: true,
      jsonMode: true,
      systemMessages: true,
      maxTokens: 4096,
      maxContextLength: 128000,
    },
    rateLimits: {
      requestsPerMinute: 3500,
      tokensPerMinute: 90000,
      concurrentRequests: 10,
    },
    costConfig: {
      inputTokenCost: 0.01,
      outputTokenCost: 0.03,
      currency: 'USD',
      billingUnit: 'token',
    },
  },
  anthropic: {
    type: 'anthropic',
    endpoint: 'https://api.anthropic.com/v1',
    apiVersion: 'v1',
    supportedModels: ['claude-3-opus', 'claude-3-sonnet', 'claude-3-haiku'],
    capabilities: {
      chat: true,
      completion: true,
      embedding: false,
      functionCalling: true,
      vision: true,
      streaming: true,
      jsonMode: false,
      systemMessages: true,
      maxTokens: 4096,
      maxContextLength: 200000,
    },
    rateLimits: {
      requestsPerMinute: 1000,
      tokensPerMinute: 40000,
      concurrentRequests: 5,
    },
    costConfig: {
      inputTokenCost: 0.015,
      outputTokenCost: 0.075,
      currency: 'USD',
      billingUnit: 'token',
    },
  },
  google: {
    type: 'google',
    endpoint: 'https://generativelanguage.googleapis.com/v1',
    supportedModels: ['gemini-pro', 'gemini-pro-vision'],
    capabilities: {
      chat: true,
      completion: true,
      embedding: true,
      functionCalling: true,
      vision: true,
      streaming: true,
      jsonMode: false,
      systemMessages: true,
      maxTokens: 8192,
      maxContextLength: 30720,
    },
    rateLimits: {
      requestsPerMinute: 60,
      tokensPerMinute: 32000,
      concurrentRequests: 5,
    },
    costConfig: {
      inputTokenCost: 0.0005,
      outputTokenCost: 0.0015,
      currency: 'USD',
      billingUnit: 'token',
    },
  },
  azure: {
    type: 'azure',
    supportedModels: ['gpt-4', 'gpt-35-turbo'],
    capabilities: {
      chat: true,
      completion: true,
      embedding: true,
      functionCalling: true,
      vision: false,
      streaming: true,
      jsonMode: true,
      systemMessages: true,
      maxTokens: 4096,
      maxContextLength: 32768,
    },
    rateLimits: {
      requestsPerMinute: 240,
      tokensPerMinute: 40000,
      concurrentRequests: 10,
    },
    costConfig: {
      inputTokenCost: 0.01,
      outputTokenCost: 0.03,
      currency: 'USD',
      billingUnit: 'token',
    },
  },
  huggingface: {
    type: 'huggingface',
    endpoint: 'https://api-inference.huggingface.co',
    supportedModels: ['meta-llama/Llama-2-70b-chat-hf'],
    capabilities: {
      chat: true,
      completion: true,
      embedding: true,
      functionCalling: false,
      vision: false,
      streaming: false,
      jsonMode: false,
      systemMessages: true,
      maxTokens: 4096,
      maxContextLength: 4096,
    },
    rateLimits: {
      requestsPerMinute: 1000,
      tokensPerMinute: 100000,
      concurrentRequests: 1,
    },
    costConfig: {
      inputTokenCost: 0.0007,
      outputTokenCost: 0.0028,
      currency: 'USD',
      billingUnit: 'token',
    },
  },
  cohere: {
    type: 'cohere',
    endpoint: 'https://api.cohere.ai/v1',
    supportedModels: ['command', 'command-light'],
    capabilities: {
      chat: true,
      completion: true,
      embedding: true,
      functionCalling: false,
      vision: false,
      streaming: true,
      jsonMode: false,
      systemMessages: true,
      maxTokens: 4096,
      maxContextLength: 4096,
    },
    rateLimits: {
      requestsPerMinute: 1000,
      tokensPerMinute: 40000,
      concurrentRequests: 10,
    },
    costConfig: {
      inputTokenCost: 0.0015,
      outputTokenCost: 0.002,
      currency: 'USD',
      billingUnit: 'token',
    },
  },
  custom: {
    type: 'custom',
    supportedModels: [],
    capabilities: {
      chat: false,
      completion: false,
      embedding: false,
      functionCalling: false,
      vision: false,
      streaming: false,
      jsonMode: false,
      systemMessages: false,
      maxTokens: 1024,
      maxContextLength: 2048,
    },
    rateLimits: {
      requestsPerMinute: 100,
      tokensPerMinute: 10000,
      concurrentRequests: 1,
    },
    costConfig: {
      inputTokenCost: 0.001,
      outputTokenCost: 0.001,
      currency: 'USD',
      billingUnit: 'token',
    },
  },
};

export const LLM_VALIDATION_RULES = {
  name: {
    minLength: 1,
    maxLength: 100,
    pattern: /^[a-zA-Z0-9\s\-_\.]+$/,
  },
  apiKey: {
    minLength: 10,
    maxLength: 500,
  },
  configuration: {
    maxSizeBytes: 10 * 1024, // 10KB
  },
  tags: {
    maxCount: 10,
    maxTagLength: 50,
  },
} as const;