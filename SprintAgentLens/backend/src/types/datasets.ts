/**
 * Dataset management type definitions with enterprise authentication
 * All operations include workspace isolation and RBAC
 */

import type { AuthenticatedUser } from './auth';

export interface CreateDatasetRequest {
  name: string;
  description?: string;
  projectId: string;
  workspaceId: string;
  metadata?: DatasetMetadata;
  tags?: string[];
}

export interface UpdateDatasetRequest {
  name?: string;
  description?: string;
  metadata?: Partial<DatasetMetadata>;
  tags?: string[];
}

export interface DatasetMetadata {
  version: string;
  source: string;
  format: 'json' | 'csv' | 'parquet' | 'txt' | 'custom';
  schema?: Record<string, any>;
  quality: {
    completeness: number; // 0-100
    consistency: number; // 0-100
    validity: number; // 0-100
    lastChecked?: Date;
  };
  lineage: {
    sourceDatasets?: string[];
    derivedFrom?: string;
    transformations?: string[];
  };
  annotations: {
    author: string;
    reviewedBy?: string;
    approvedBy?: string;
    reviewDate?: Date;
    approvalDate?: Date;
  };
}

export interface DatasetResponse {
  id: string;
  name: string;
  description: string | null;
  projectId: string;
  projectName: string;
  workspaceId: string;
  workspaceName: string;
  metadata: DatasetMetadata;
  tags: string[];
  itemCount: number;
  status: DatasetStatus;
  createdAt: Date;
  createdBy: string;
  createdByName: string;
  lastUpdatedAt: Date;
  lastUpdatedBy: string | null;
  lastUpdatedByName: string | null;
  // Statistics
  averageItemSize?: number;
  totalSizeBytes?: number;
  uniqueItemsCount?: number;
  duplicatesCount?: number;
  // Permissions (computed based on user role and workspace)
  canRead: boolean;
  canEdit: boolean;
  canDelete: boolean;
  canAddItems: boolean;
  canRemoveItems: boolean;
  canExport: boolean;
  canShare: boolean;
  canViewMetrics: boolean;
}

export interface DatasetListRequest {
  projectId?: string;
  workspaceId?: string;
  status?: DatasetStatus[];
  tags?: string[];
  search?: string;
  sortBy?: 'name' | 'created_at' | 'updated_at' | 'item_count' | 'size';
  sortOrder?: 'asc' | 'desc';
  page?: number;
  limit?: number;
}

export interface DatasetListResponse {
  datasets: DatasetResponse[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
  filters: {
    projectId?: string;
    workspaceId?: string;
    status?: DatasetStatus[];
    tags?: string[];
  };
  sorting: {
    sortBy: string;
    sortOrder: 'asc' | 'desc';
  };
}

export interface DatasetStatisticsResponse {
  datasetId: string;
  itemCount: number;
  totalSizeBytes: number;
  averageItemSize: number;
  uniqueItemsCount: number;
  duplicatesCount: number;
  qualityMetrics: {
    completeness: number;
    consistency: number;
    validity: number;
    lastChecked: Date;
  };
  itemTypes: Array<{
    type: string;
    count: number;
    percentage: number;
  }>;
  recentActivity: {
    itemsAddedLast7Days: number;
    itemsRemovedLast7Days: number;
    lastModified: Date;
  };
  usage: {
    experimentsUsing: number;
    tracesGenerated: number;
    lastUsed?: Date;
  };
}

export interface DatasetMetricsRequest {
  datasetId: string;
  metrics: string[];
  startDate?: Date;
  endDate?: Date;
  granularity?: 'hour' | 'day' | 'week' | 'month';
}

export interface DatasetMetricsResponse {
  datasetId: string;
  metrics: Array<{
    name: string;
    data: Array<{
      timestamp: Date;
      value: number;
    }>;
    aggregation: {
      min: number;
      max: number;
      avg: number;
      total: number;
    };
  }>;
  timeRange: {
    start: Date;
    end: Date;
  };
}

export type DatasetStatus = 
  | 'draft'          // Being created/edited
  | 'ready'          // Ready for use
  | 'processing'     // Being processed/validated
  | 'error'          // Processing failed
  | 'archived'       // Archived but not deleted
  | 'deprecated';    // Marked for replacement

export interface BulkDatasetOperationRequest {
  datasetIds: string[];
  operation: 'delete' | 'archive' | 'restore' | 'export' | 'duplicate';
  options?: {
    exportFormat?: 'json' | 'csv' | 'parquet';
    targetProjectId?: string; // For duplicate operation
    includeMetadata?: boolean;
  };
}

export interface BulkDatasetOperationResponse {
  requestId: string;
  operation: string;
  status: 'queued' | 'processing' | 'completed' | 'failed';
  processedCount: number;
  totalCount: number;
  errors: Array<{
    datasetId: string;
    error: string;
  }>;
  results?: Array<{
    datasetId: string;
    status: 'success' | 'failed';
    newDatasetId?: string; // For duplicate operation
    exportUrl?: string; // For export operation
  }>;
}

// Dataset Items
export interface CreateDatasetItemRequest {
  datasetId: string;
  input: Record<string, any>;
  expectedOutput?: Record<string, any>;
  metadata?: DatasetItemMetadata;
  tags?: string[];
}

export interface UpdateDatasetItemRequest {
  input?: Record<string, any>;
  expectedOutput?: Record<string, any>;
  metadata?: Partial<DatasetItemMetadata>;
  tags?: string[];
}

export interface DatasetItemMetadata {
  source: string;
  sourceId?: string;
  quality: {
    confidence: number; // 0-100
    validated: boolean;
    validatedBy?: string;
    validatedAt?: Date;
  };
  annotations: {
    difficulty?: 'easy' | 'medium' | 'hard';
    category?: string;
    subcategory?: string;
    notes?: string;
  };
  provenance: {
    generatedBy?: string;
    derivedFrom?: string;
    transformations?: string[];
  };
}

export interface DatasetItemResponse {
  id: string;
  datasetId: string;
  datasetName: string;
  input: Record<string, any>;
  expectedOutput: Record<string, any> | null;
  metadata: DatasetItemMetadata;
  tags: string[];
  createdAt: Date;
  createdBy: string;
  createdByName: string;
  lastUpdatedAt: Date;
  lastUpdatedBy: string | null;
  lastUpdatedByName: string | null;
  // Permissions
  canEdit: boolean;
  canDelete: boolean;
}

export interface DatasetItemListRequest {
  datasetId: string;
  tags?: string[];
  search?: string;
  searchFields?: ('input' | 'expected_output' | 'metadata')[];
  quality?: {
    minConfidence?: number;
    validated?: boolean;
  };
  sortBy?: 'created_at' | 'updated_at' | 'confidence';
  sortOrder?: 'asc' | 'desc';
  page?: number;
  limit?: number;
}

export interface DatasetItemListResponse {
  items: DatasetItemResponse[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
  datasetInfo: {
    id: string;
    name: string;
    totalItems: number;
    canAddItems: boolean;
    canEditItems: boolean;
  };
}

// Permission checking functions
export interface DatasetPermissionChecker {
  canCreateDataset(user: AuthenticatedUser, projectId: string): boolean;
  canReadDataset(user: AuthenticatedUser, datasetId: string): boolean;
  canEditDataset(user: AuthenticatedUser, datasetId: string): boolean;
  canDeleteDataset(user: AuthenticatedUser, datasetId: string): boolean;
  canAddItems(user: AuthenticatedUser, datasetId: string): boolean;
  canEditItems(user: AuthenticatedUser, datasetId: string): boolean;
  canViewMetrics(user: AuthenticatedUser, datasetId: string): boolean;
  canExportDataset(user: AuthenticatedUser, datasetId: string): boolean;
}

// Error types
export class DatasetNotFoundError extends Error {
  constructor(datasetId: string) {
    super(`Dataset not found: ${datasetId}`);
    this.name = 'DatasetNotFoundError';
  }
}

export class DatasetPermissionError extends Error {
  constructor(action: string, datasetId: string) {
    super(`Permission denied: ${action} on dataset ${datasetId}`);
    this.name = 'DatasetPermissionError';
  }
}

export class DatasetValidationError extends Error {
  constructor(field: string, message: string) {
    super(`Validation error on ${field}: ${message}`);
    this.name = 'DatasetValidationError';
  }
}

export class DatasetStatusError extends Error {
  constructor(currentStatus: DatasetStatus, requiredStatus: DatasetStatus) {
    super(`Invalid dataset status: expected ${requiredStatus}, got ${currentStatus}`);
    this.name = 'DatasetStatusError';
  }
}

export class DatasetItemNotFoundError extends Error {
  constructor(itemId: string) {
    super(`Dataset item not found: ${itemId}`);
    this.name = 'DatasetItemNotFoundError';
  }
}

export class DatasetLimitError extends Error {
  constructor(limit: string, current: number, max: number) {
    super(`Dataset limit exceeded: ${limit} (${current}/${max})`);
    this.name = 'DatasetLimitError';
  }
}

// Default configurations
export const DEFAULT_DATASET_METADATA: Partial<DatasetMetadata> = {
  version: '1.0.0',
  format: 'json',
  quality: {
    completeness: 0,
    consistency: 0,
    validity: 0,
  },
  lineage: {},
  annotations: {
    author: '',
  },
};

export const DATASET_ITEM_LIMITS = {
  maxItemsPerDataset: 100000,
  maxItemSizeBytes: 10 * 1024 * 1024, // 10MB
  maxBatchSize: 1000,
} as const;

export const DATASET_VALIDATION_RULES = {
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
} as const;