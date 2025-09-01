/**
 * Project management type definitions
 * All operations include authentication and authorization
 */

export interface CreateProjectRequest {
  name: string;
  description?: string;
  workspaceId?: string;
}

export interface UpdateProjectRequest {
  name?: string;
  description?: string;
}

export interface ProjectResponse {
  id: string;
  name: string;
  description: string | null;
  workspaceId: string;
  createdAt: Date;
  createdBy: string;
  lastUpdatedAt: Date;
  lastUpdatedBy: string | null;
  // Statistics
  datasetCount?: number;
  experimentCount?: number;
  // Permissions
  canEdit: boolean;
  canDelete: boolean;
  canCreateDatasets: boolean;
  canCreateExperiments: boolean;
}

export interface ProjectListResponse {
  projects: ProjectResponse[];
  pagination: PaginationInfo;
  filters?: ProjectFilters;
}

export interface ProjectFilters {
  workspaceName?: string;
  createdBy?: string;
  name?: string;
  createdAfter?: Date;
  createdBefore?: Date;
}

export interface ProjectSortOptions {
  field: 'name' | 'createdAt' | 'lastUpdatedAt' | 'datasetCount' | 'experimentCount';
  order: 'asc' | 'desc';
}

export interface PaginationInfo {
  page: number;
  size: number;
  total: number;
  totalPages: number;
  hasNext: boolean;
  hasPrevious: boolean;
}

export interface BulkDeleteRequest {
  projectIds: string[];
  force?: boolean; // Admin only - delete even if has datasets/experiments
}

export interface BulkDeleteResponse {
  deleted: string[];
  failed: Array<{
    projectId: string;
    reason: string;
  }>;
  summary: {
    requested: number;
    deleted: number;
    failed: number;
  };
}

export interface ProjectStatsResponse {
  id: string;
  name: string;
  statistics: {
    datasets: {
      total: number;
      recentlyCreated: number; // Last 30 days
    };
    experiments: {
      total: number;
      running: number;
      completed: number;
      failed: number;
      recentlyCreated: number;
    };
    traces: {
      total: number;
      recentlyCreated: number;
    };
    feedback: {
      totalScores: number;
      averageRating?: number;
    };
  };
  activity: {
    lastDatasetCreated?: Date;
    lastExperimentCreated?: Date;
    lastTraceCreated?: Date;
    lastActivity?: Date;
  };
}

export interface FeedbackScoreNamesResponse {
  scoreNames: string[];
  workspaceId: string;
  projectId: string;
}

export interface ProjectMetricRequest {
  metricNames: string[];
  startDate?: Date;
  endDate?: Date;
  groupBy?: 'day' | 'week' | 'month';
  filters?: {
    experimentIds?: string[];
    datasetIds?: string[];
    tags?: string[];
  };
}

export interface ProjectMetricResponse {
  projectId: string;
  metrics: Array<{
    name: string;
    data: Array<{
      timestamp: Date;
      value: number;
      metadata?: Record<string, any>;
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

// Permission checking types
export interface ProjectPermissions {
  canRead: boolean;
  canEdit: boolean;
  canDelete: boolean;
  canCreateDatasets: boolean;
  canCreateExperiments: boolean;
  canViewMetrics: boolean;
  canManageUsers: boolean; // Admin only
  isOwner: boolean;
}

// Audit logging types
export interface ProjectAuditEvent {
  projectId: string;
  userId: string;
  action: ProjectAuditAction;
  details?: Record<string, any>;
  timestamp: Date;
}

export enum ProjectAuditAction {
  CREATED = 'CREATED',
  UPDATED = 'UPDATED',
  DELETED = 'DELETED',
  BULK_DELETED = 'BULK_DELETED',
  VIEWED = 'VIEWED',
  STATS_ACCESSED = 'STATS_ACCESSED',
  METRICS_ACCESSED = 'METRICS_ACCESSED',
  PERMISSION_DENIED = 'PERMISSION_DENIED',
}

// Error types
export interface ProjectError {
  code: string;
  message: string;
  details?: Record<string, any>;
}

export class ProjectNotFoundError extends Error {
  constructor(projectId: string) {
    super(`Project not found: ${projectId}`);
    this.name = 'ProjectNotFoundError';
  }
}

export class ProjectPermissionError extends Error {
  constructor(action: string, projectId: string) {
    super(`Permission denied: ${action} on project ${projectId}`);
    this.name = 'ProjectPermissionError';
  }
}

export class ProjectValidationError extends Error {
  constructor(field: string, message: string) {
    super(`Validation error on ${field}: ${message}`);
    this.name = 'ProjectValidationError';
  }
}

export class WorkspaceAccessError extends Error {
  constructor(workspaceId: string) {
    super(`Access denied to workspace: ${workspaceId}`);
    this.name = 'WorkspaceAccessError';
  }
}