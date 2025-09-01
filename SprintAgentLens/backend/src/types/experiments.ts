/**
 * Experiment management type definitions with enterprise authentication
 * All operations include workspace isolation and RBAC
 */

import type { AuthenticatedUser } from './auth';

export interface CreateExperimentRequest {
  name: string;
  description?: string;
  projectId: string;
  workspaceId: string;
  datasetId?: string;
  configuration?: ExperimentConfiguration;
  tags?: string[];
  metadata?: ExperimentMetadata;
}

export interface UpdateExperimentRequest {
  name?: string;
  description?: string;
  datasetId?: string;
  configuration?: Partial<ExperimentConfiguration>;
  tags?: string[];
  metadata?: Partial<ExperimentMetadata>;
  status?: ExperimentStatus;
}

export interface ExperimentConfiguration {
  modelProvider: 'openai' | 'anthropic' | 'google' | 'azure' | 'huggingface' | 'custom';
  modelName: string;
  modelVersion?: string;
  parameters: {
    temperature?: number;
    maxTokens?: number;
    topP?: number;
    topK?: number;
    frequencyPenalty?: number;
    presencePenalty?: number;
    stopSequences?: string[];
    systemPrompt?: string;
    promptTemplate?: string;
  };
  evaluation: {
    metrics: string[];
    evaluators?: ExperimentEvaluator[];
    customScoring?: CustomScoringConfig;
    batchSize?: number;
    timeout?: number;
  };
  sampling: {
    strategy: 'sequential' | 'random' | 'stratified';
    sampleSize?: number;
    seed?: number;
  };
}

export interface ExperimentEvaluator {
  name: string;
  type: 'llm_judge' | 'rule_based' | 'similarity' | 'custom';
  config: {
    judgeModel?: string;
    criteria?: string;
    rubric?: string;
    threshold?: number;
    weight?: number;
  };
}

export interface CustomScoringConfig {
  scriptPath?: string;
  functionName?: string;
  parameters?: Record<string, any>;
  timeout?: number;
}

export interface ExperimentMetadata {
  objective: string;
  hypothesis?: string;
  expectedOutcome?: string;
  author: string;
  reviewedBy?: string;
  approvedBy?: string;
  version: string;
  category?: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  environment: 'development' | 'staging' | 'production';
  computeResources?: {
    estimatedCost?: number;
    expectedDuration?: number;
    memoryMB?: number;
    cpuCores?: number;
    gpuRequired?: boolean;
  };
  dependencies?: string[];
}

export interface ExperimentResponse {
  id: string;
  name: string;
  description: string | null;
  projectId: string;
  projectName: string;
  workspaceId: string;
  workspaceName: string;
  datasetId: string | null;
  datasetName: string | null;
  configuration: ExperimentConfiguration;
  metadata: ExperimentMetadata;
  tags: string[];
  status: ExperimentStatus;
  progress: ExperimentProgress;
  results?: ExperimentResults;
  createdAt: Date;
  createdBy: string;
  createdByName: string;
  lastUpdatedAt: Date;
  lastUpdatedBy: string | null;
  lastUpdatedByName: string | null;
  startedAt?: Date;
  completedAt?: Date;
  // Statistics
  totalItems?: number;
  processedItems?: number;
  successfulItems?: number;
  failedItems?: number;
  averageLatency?: number;
  totalCost?: number;
  // Permissions (computed based on user role and workspace)
  canRead: boolean;
  canEdit: boolean;
  canDelete: boolean;
  canStart: boolean;
  canStop: boolean;
  canReset: boolean;
  canClone: boolean;
  canExport: boolean;
  canViewResults: boolean;
  canViewLogs: boolean;
}

export interface ExperimentListRequest {
  projectId?: string;
  workspaceId?: string;
  datasetId?: string;
  status?: ExperimentStatus[];
  tags?: string[];
  search?: string;
  modelProvider?: string[];
  createdBy?: string;
  dateRange?: {
    start: Date;
    end: Date;
  };
  sortBy?: 'name' | 'created_at' | 'updated_at' | 'started_at' | 'completed_at' | 'status' | 'progress';
  sortOrder?: 'asc' | 'desc';
  page?: number;
  limit?: number;
}

export interface ExperimentListResponse {
  experiments: ExperimentResponse[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
  filters: {
    projectId?: string;
    workspaceId?: string;
    datasetId?: string;
    status?: ExperimentStatus[];
    tags?: string[];
    modelProvider?: string[];
  };
  sorting: {
    sortBy: string;
    sortOrder: 'asc' | 'desc';
  };
  aggregations: {
    statusCounts: Record<ExperimentStatus, number>;
    providerCounts: Record<string, number>;
    totalCost: number;
    averageDuration: number;
  };
}

export type ExperimentStatus = 
  | 'draft'          // Created but not started
  | 'queued'         // Queued for execution
  | 'running'        // Currently executing
  | 'paused'         // Temporarily paused
  | 'completed'      // Successfully completed
  | 'failed'         // Failed with errors
  | 'cancelled'      // Manually cancelled
  | 'timeout'        // Timed out during execution
  | 'archived';      // Archived for reference

export interface ExperimentProgress {
  status: ExperimentStatus;
  percentage: number;
  currentStage: string;
  itemsProcessed: number;
  itemsTotal: number;
  estimatedTimeRemaining?: number;
  lastActivity?: Date;
  errors: ExperimentError[];
  warnings: ExperimentWarning[];
}

export interface ExperimentError {
  id: string;
  timestamp: Date;
  stage: string;
  itemId?: string;
  message: string;
  details?: string;
  stackTrace?: string;
  retryCount: number;
  resolved: boolean;
}

export interface ExperimentWarning {
  id: string;
  timestamp: Date;
  stage: string;
  message: string;
  details?: string;
  severity: 'low' | 'medium' | 'high';
  acknowledged: boolean;
}

export interface ExperimentResults {
  summary: ExperimentSummary;
  metrics: ExperimentMetric[];
  evaluations: EvaluationResult[];
  costAnalysis: CostAnalysis;
  performanceStats: PerformanceStats;
  exportUrls?: {
    csv?: string;
    json?: string;
    report?: string;
  };
}

export interface ExperimentSummary {
  totalItems: number;
  successfulItems: number;
  failedItems: number;
  averageScore: number;
  medianScore: number;
  minScore: number;
  maxScore: number;
  scoreDistribution: Array<{ range: string; count: number }>;
  overallGrade: 'A' | 'B' | 'C' | 'D' | 'F';
  keyFindings: string[];
  recommendations: string[];
}

export interface ExperimentMetric {
  name: string;
  displayName: string;
  value: number;
  unit?: string;
  description?: string;
  trend?: 'up' | 'down' | 'stable';
  comparison?: {
    baseline?: number;
    improvement?: number;
    percentChange?: number;
  };
  breakdown?: Array<{
    label: string;
    value: number;
    percentage: number;
  }>;
}

export interface EvaluationResult {
  evaluatorName: string;
  evaluatorType: string;
  overallScore: number;
  maxScore: number;
  passRate: number;
  items: Array<{
    itemId: string;
    score: number;
    passed: boolean;
    feedback?: string;
    reasoning?: string;
  }>;
  insights: string[];
  recommendations: string[];
}

export interface CostAnalysis {
  totalCost: number;
  currency: string;
  breakdown: {
    llmCosts: number;
    computeCosts: number;
    storageCosts: number;
    other: number;
  };
  costPerItem: number;
  budgetUtilization?: number;
  estimatedSavings?: number;
}

export interface PerformanceStats {
  totalDuration: number; // seconds
  averageLatency: number; // milliseconds
  throughput: number; // items per second
  peakMemoryUsage: number; // MB
  totalTokensUsed: number;
  tokensPerSecond: number;
  errorRate: number;
  timeouts: number;
  retries: number;
}

export interface ExperimentStatisticsResponse {
  experimentId: string;
  itemCount: number;
  progress: ExperimentProgress;
  results?: ExperimentResults;
  recentActivity: Array<{
    timestamp: Date;
    action: string;
    details: string;
    user?: string;
  }>;
  resourceUsage: {
    cpuUsage: number;
    memoryUsage: number;
    networkIO: number;
    diskIO: number;
  };
}

export interface ExperimentMetricsRequest {
  experimentId: string;
  metrics: string[];
  startDate?: Date;
  endDate?: Date;
  granularity?: 'minute' | 'hour' | 'day';
  includeComparison?: boolean;
}

export interface ExperimentMetricsResponse {
  experimentId: string;
  metrics: Array<{
    name: string;
    data: Array<{
      timestamp: Date;
      value: number;
      details?: Record<string, any>;
    }>;
    aggregation: {
      min: number;
      max: number;
      avg: number;
      total: number;
      trend: 'up' | 'down' | 'stable';
    };
  }>;
  timeRange: {
    start: Date;
    end: Date;
  };
  comparison?: {
    baselineExperiment?: string;
    improvements: Record<string, number>;
  };
}

export interface BulkExperimentOperationRequest {
  experimentIds: string[];
  operation: 'start' | 'stop' | 'pause' | 'resume' | 'cancel' | 'archive' | 'delete' | 'clone';
  options?: {
    force?: boolean;
    targetProjectId?: string; // For clone operation
    namePrefix?: string; // For clone operation
    preserveConfiguration?: boolean;
  };
}

export interface BulkExperimentOperationResponse {
  requestId: string;
  operation: string;
  status: 'queued' | 'processing' | 'completed' | 'partial_success' | 'failed';
  processedCount: number;
  totalCount: number;
  errors: Array<{
    experimentId: string;
    error: string;
  }>;
  results?: Array<{
    experimentId: string;
    status: 'success' | 'failed';
    newExperimentId?: string; // For clone operation
  }>;
  estimatedCompletion?: Date;
}

// Experiment Execution Control
export interface StartExperimentRequest {
  force?: boolean; // Force start even if validation fails
  priority?: 'low' | 'normal' | 'high';
  scheduledStart?: Date;
  notifications?: {
    onComplete?: boolean;
    onError?: boolean;
    webhookUrl?: string;
  };
}

export interface StopExperimentRequest {
  reason?: string;
  saveProgress?: boolean;
  force?: boolean;
}

export interface PauseExperimentRequest {
  reason?: string;
  maxPauseDuration?: number; // seconds
}

export interface CloneExperimentRequest {
  name: string;
  description?: string;
  targetProjectId?: string;
  preserveDataset?: boolean;
  modifyConfiguration?: Partial<ExperimentConfiguration>;
}

// Permission checking functions
export interface ExperimentPermissionChecker {
  canCreateExperiment(user: AuthenticatedUser, projectId: string): boolean;
  canReadExperiment(user: AuthenticatedUser, experimentId: string): boolean;
  canEditExperiment(user: AuthenticatedUser, experimentId: string): boolean;
  canDeleteExperiment(user: AuthenticatedUser, experimentId: string): boolean;
  canStartExperiment(user: AuthenticatedUser, experimentId: string): boolean;
  canStopExperiment(user: AuthenticatedUser, experimentId: string): boolean;
  canViewResults(user: AuthenticatedUser, experimentId: string): boolean;
  canExportResults(user: AuthenticatedUser, experimentId: string): boolean;
}

// Error types
export class ExperimentNotFoundError extends Error {
  constructor(experimentId: string) {
    super(`Experiment not found: ${experimentId}`);
    this.name = 'ExperimentNotFoundError';
  }
}

export class ExperimentPermissionError extends Error {
  constructor(action: string, experimentId: string) {
    super(`Permission denied: ${action} on experiment ${experimentId}`);
    this.name = 'ExperimentPermissionError';
  }
}

export class ExperimentValidationError extends Error {
  constructor(field: string, message: string) {
    super(`Validation error on ${field}: ${message}`);
    this.name = 'ExperimentValidationError';
  }
}

export class ExperimentStatusError extends Error {
  constructor(currentStatus: ExperimentStatus, requiredStatus: ExperimentStatus) {
    super(`Invalid experiment status: expected ${requiredStatus}, got ${currentStatus}`);
    this.name = 'ExperimentStatusError';
  }
}

export class ExperimentResourceError extends Error {
  constructor(resource: string, message: string) {
    super(`Resource error for ${resource}: ${message}`);
    this.name = 'ExperimentResourceError';
  }
}

export class ExperimentLimitError extends Error {
  constructor(limit: string, current: number, max: number) {
    super(`Experiment limit exceeded: ${limit} (${current}/${max})`);
    this.name = 'ExperimentLimitError';
  }
}

// Default configurations
export const DEFAULT_EXPERIMENT_CONFIGURATION: Partial<ExperimentConfiguration> = {
  parameters: {
    temperature: 0.7,
    maxTokens: 1000,
    topP: 0.9,
  },
  evaluation: {
    metrics: ['accuracy', 'latency'],
    batchSize: 10,
    timeout: 300,
  },
  sampling: {
    strategy: 'sequential',
  },
};

export const DEFAULT_EXPERIMENT_METADATA: Partial<ExperimentMetadata> = {
  version: '1.0.0',
  priority: 'medium',
  environment: 'development',
  author: '',
  computeResources: {
    estimatedCost: 0,
    expectedDuration: 0,
    memoryMB: 512,
    cpuCores: 1,
    gpuRequired: false,
  },
};

export const EXPERIMENT_LIMITS = {
  maxExperimentsPerProject: 1000,
  maxConcurrentExperiments: 10,
  maxExperimentDuration: 24 * 60 * 60, // 24 hours in seconds
  maxItemsPerExperiment: 100000,
  maxConfigurationSize: 1024 * 1024, // 1MB
} as const;

export const EXPERIMENT_VALIDATION_RULES = {
  name: {
    minLength: 1,
    maxLength: 255,
    pattern: /^[a-zA-Z0-9\s\-_\.]+$/,
  },
  description: {
    maxLength: 2000,
  },
  tags: {
    maxCount: 20,
    maxTagLength: 50,
  },
  configuration: {
    maxSizeBytes: 1024 * 1024, // 1MB
  },
} as const;