/**
 * Workspace management type definitions
 * All operations include authentication and authorization
 */

export interface WorkspaceConfigurationRequest {
  name: string;
  description?: string;
  settings?: WorkspaceSettings;
  features?: WorkspaceFeatures;
}

export interface UpdateWorkspaceRequest {
  name?: string;
  description?: string;
  settings?: Partial<WorkspaceSettings>;
  features?: Partial<WorkspaceFeatures>;
}

export interface WorkspaceSettings {
  theme: 'light' | 'dark' | 'auto';
  timezone: string;
  dateFormat: string;
  timeFormat: '12h' | '24h';
  language: string;
  notifications: {
    email: boolean;
    push: boolean;
    experimentCompletion: boolean;
    datasetUpdates: boolean;
    systemAlerts: boolean;
  };
  privacy: {
    shareUsageData: boolean;
    allowTelemetry: boolean;
  };
  limits: {
    maxProjectsPerUser: number;
    maxDatasetsPerProject: number;
    maxExperimentsPerProject: number;
    storageQuotaGB: number;
  };
}

export interface WorkspaceFeatures {
  experiments: boolean;
  tracing: boolean;
  analytics: boolean;
  llmProviders: boolean;
  collaboration: boolean;
  apiAccess: boolean;
  customIntegrations: boolean;
  advancedMetrics: boolean;
  auditLogs: boolean;
  sso: boolean;
}

export interface WorkspaceResponse {
  id: string;
  workspaceId: string;
  name: string;
  description: string | null;
  settings: WorkspaceSettings;
  features: WorkspaceFeatures;
  createdAt: Date;
  createdBy: string;
  lastUpdatedAt: Date;
  lastUpdatedBy: string | null;
  // Statistics
  userCount?: number;
  projectCount?: number;
  datasetCount?: number;
  experimentCount?: number;
  // Permissions
  canEdit: boolean;
  canDelete: boolean;
  canInviteUsers: boolean;
  canManageSettings: boolean;
}

export interface WorkspaceListResponse {
  workspaces: WorkspaceResponse[];
  currentWorkspace: string;
  permissions: WorkspacePermissions;
}

export interface WorkspaceMetadataResponse {
  workspaceId: string;
  name: string;
  description: string | null;
  settings: WorkspaceSettings;
  features: WorkspaceFeatures;
  statistics: WorkspaceStatistics;
  limits: WorkspaceLimits;
  usage: WorkspaceUsage;
}

export interface WorkspaceStatistics {
  users: {
    total: number;
    active: number;
    admins: number;
    viewers: number;
  };
  projects: {
    total: number;
    recentlyCreated: number; // Last 30 days
  };
  datasets: {
    total: number;
    totalItems: number;
    recentlyCreated: number;
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
  storage: {
    usedGB: number;
    attachmentsGB: number;
  };
}

export interface WorkspaceLimits {
  maxUsers: number;
  maxProjects: number;
  maxDatasetsPerProject: number;
  maxExperimentsPerProject: number;
  storageQuotaGB: number;
  apiCallsPerMonth: number;
}

export interface WorkspaceUsage {
  users: {
    current: number;
    limit: number;
    percentUsed: number;
  };
  projects: {
    current: number;
    limit: number;
    percentUsed: number;
  };
  storage: {
    currentGB: number;
    limitGB: number;
    percentUsed: number;
  };
  apiCalls: {
    currentMonth: number;
    limit: number;
    percentUsed: number;
  };
}

export interface WorkspaceMetricRequest {
  metricNames: string[];
  startDate?: Date;
  endDate?: Date;
  groupBy?: 'day' | 'week' | 'month';
  includeProjects?: boolean;
}

export interface WorkspaceMetricResponse {
  workspaceId: string;
  metrics: Array<{
    name: string;
    data: Array<{
      timestamp: Date;
      value: number;
      breakdown?: Record<string, number>;
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
  projects?: Array<{
    projectId: string;
    name: string;
    metrics: Record<string, number>;
  }>;
}

export interface WorkspaceMetricsSummaryRequest {
  period: 'day' | 'week' | 'month' | 'quarter' | 'year';
  includeComparison?: boolean;
}

export interface WorkspaceMetricsSummaryResponse {
  period: string;
  summary: {
    projects: {
      total: number;
      created: number;
      active: number;
    };
    experiments: {
      total: number;
      created: number;
      completed: number;
      successRate: number;
    };
    traces: {
      total: number;
      created: number;
      averageLatency: number;
    };
    users: {
      total: number;
      active: number;
      newSignups: number;
    };
    storage: {
      totalGB: number;
      growth: number;
    };
  };
  comparison?: {
    period: string;
    changes: Record<string, {
      value: number;
      change: number;
      changePercent: number;
    }>;
  };
  trends: Array<{
    metric: string;
    trend: 'up' | 'down' | 'stable';
    changePercent: number;
  }>;
}

// Permission checking types
export interface WorkspacePermissions {
  canRead: boolean;
  canEdit: boolean;
  canDelete: boolean;
  canInviteUsers: boolean;
  canManageUsers: boolean;
  canManageSettings: boolean;
  canViewMetrics: boolean;
  canViewAuditLogs: boolean;
  isOwner: boolean;
  isAdmin: boolean;
}

// Error types
export class WorkspaceNotFoundError extends Error {
  constructor(workspaceId: string) {
    super(`Workspace not found: ${workspaceId}`);
    this.name = 'WorkspaceNotFoundError';
  }
}

export class WorkspacePermissionError extends Error {
  constructor(action: string, workspaceId: string) {
    super(`Permission denied: ${action} on workspace ${workspaceId}`);
    this.name = 'WorkspacePermissionError';
  }
}

export class WorkspaceValidationError extends Error {
  constructor(field: string, message: string) {
    super(`Validation error on ${field}: ${message}`);
    this.name = 'WorkspaceValidationError';
  }
}

export class WorkspaceLimitError extends Error {
  constructor(limit: string, current: number, max: number) {
    super(`Workspace limit exceeded: ${limit} (${current}/${max})`);
    this.name = 'WorkspaceLimitError';
  }
}

// Default configurations
export const DEFAULT_WORKSPACE_SETTINGS: WorkspaceSettings = {
  theme: 'light',
  timezone: 'UTC',
  dateFormat: 'YYYY-MM-DD',
  timeFormat: '24h',
  language: 'en',
  notifications: {
    email: true,
    push: false,
    experimentCompletion: true,
    datasetUpdates: true,
    systemAlerts: true,
  },
  privacy: {
    shareUsageData: false,
    allowTelemetry: false,
  },
  limits: {
    maxProjectsPerUser: 100,
    maxDatasetsPerProject: 50,
    maxExperimentsPerProject: 100,
    storageQuotaGB: 10,
  },
};

export const DEFAULT_WORKSPACE_FEATURES: WorkspaceFeatures = {
  experiments: true,
  tracing: true,
  analytics: true,
  llmProviders: true,
  collaboration: true,
  apiAccess: true,
  customIntegrations: false,
  advancedMetrics: false,
  auditLogs: false,
  sso: false,
};