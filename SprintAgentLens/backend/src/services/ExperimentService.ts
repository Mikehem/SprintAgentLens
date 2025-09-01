/**
 * Experiment Service - Enterprise experiment management with authentication
 * Provides comprehensive CRUD operations with workspace isolation and RBAC
 */

import { PrismaClient } from '@prisma/client';
import { logger } from '@/utils/logger';
import type { AuthenticatedUser } from '@/types/auth';
import type {
  CreateExperimentRequest,
  UpdateExperimentRequest,
  ExperimentResponse,
  ExperimentListRequest,
  ExperimentListResponse,
  ExperimentStatisticsResponse,
  ExperimentMetricsRequest,
  ExperimentMetricsResponse,
  BulkExperimentOperationRequest,
  BulkExperimentOperationResponse,
  StartExperimentRequest,
  StopExperimentRequest,
  PauseExperimentRequest,
  CloneExperimentRequest,
  ExperimentStatus,
  ExperimentConfiguration,
  ExperimentMetadata,
  ExperimentProgress,
  ExperimentPermissionChecker,
  ExperimentNotFoundError,
  ExperimentPermissionError,
  ExperimentValidationError,
  ExperimentStatusError,
  ExperimentResourceError,
  ExperimentLimitError,
  DEFAULT_EXPERIMENT_CONFIGURATION,
  DEFAULT_EXPERIMENT_METADATA,
  EXPERIMENT_LIMITS,
  EXPERIMENT_VALIDATION_RULES,
} from '@/types/experiments';
import { ProjectService } from './ProjectService';
import { DatasetService } from './DatasetService';

export class ExperimentService implements ExperimentPermissionChecker {
  private static prisma = new PrismaClient();

  // Permission checking methods
  static canCreateExperiment(user: AuthenticatedUser, projectId: string): boolean {
    if (user.role === 'admin') return true;
    if (user.role === 'viewer') return false;
    return user.role === 'user';
  }

  static canReadExperiment(user: AuthenticatedUser, experiment: any): boolean {
    if (user.role === 'admin') return true;
    return experiment.workspaceId === user.workspaceId;
  }

  static canEditExperiment(user: AuthenticatedUser, experiment: any): boolean {
    if (user.role === 'admin') return true;
    if (user.role === 'viewer') return false;
    return experiment.workspaceId === user.workspaceId && user.role === 'user';
  }

  static canDeleteExperiment(user: AuthenticatedUser, experiment: any): boolean {
    if (user.role === 'admin') return true;
    if (user.role === 'viewer') return false;
    return experiment.workspaceId === user.workspaceId && user.role === 'user';
  }

  static canStartExperiment(user: AuthenticatedUser, experiment: any): boolean {
    if (user.role === 'admin') return true;
    if (user.role === 'viewer') return false;
    return experiment.workspaceId === user.workspaceId && user.role === 'user';
  }

  static canStopExperiment(user: AuthenticatedUser, experiment: any): boolean {
    return this.canStartExperiment(user, experiment);
  }

  static canViewResults(user: AuthenticatedUser, experiment: any): boolean {
    return this.canReadExperiment(user, experiment);
  }

  static canExportResults(user: AuthenticatedUser, experiment: any): boolean {
    return this.canReadExperiment(user, experiment);
  }

  // Validation methods
  private static validateExperimentName(name: string): void {
    const { minLength, maxLength, pattern } = EXPERIMENT_VALIDATION_RULES.name;
    
    if (!name || name.length < minLength) {
      throw new ExperimentValidationError('name', `Name must be at least ${minLength} characters`);
    }
    if (name.length > maxLength) {
      throw new ExperimentValidationError('name', `Name cannot exceed ${maxLength} characters`);
    }
    if (!pattern.test(name)) {
      throw new ExperimentValidationError('name', 'Name contains invalid characters');
    }
  }

  private static validateDescription(description?: string): void {
    if (description && description.length > EXPERIMENT_VALIDATION_RULES.description.maxLength) {
      throw new ExperimentValidationError('description', 
        `Description cannot exceed ${EXPERIMENT_VALIDATION_RULES.description.maxLength} characters`);
    }
  }

  private static validateTags(tags?: string[]): void {
    if (!tags) return;
    
    const { maxCount, maxTagLength } = EXPERIMENT_VALIDATION_RULES.tags;
    
    if (tags.length > maxCount) {
      throw new ExperimentValidationError('tags', `Cannot have more than ${maxCount} tags`);
    }
    
    for (const tag of tags) {
      if (tag.length > maxTagLength) {
        throw new ExperimentValidationError('tags', 
          `Tag "${tag}" cannot exceed ${maxTagLength} characters`);
      }
    }
  }

  private static validateConfiguration(configuration?: ExperimentConfiguration): void {
    if (!configuration) return;
    
    const configString = JSON.stringify(configuration);
    if (configString.length > EXPERIMENT_VALIDATION_RULES.configuration.maxSizeBytes) {
      throw new ExperimentValidationError('configuration', 
        `Configuration size exceeds maximum of ${EXPERIMENT_VALIDATION_RULES.configuration.maxSizeBytes} bytes`);
    }

    // Validate model parameters
    const { parameters } = configuration;
    if (parameters) {
      if (parameters.temperature !== undefined && (parameters.temperature < 0 || parameters.temperature > 2)) {
        throw new ExperimentValidationError('configuration.parameters.temperature', 
          'Temperature must be between 0 and 2');
      }
      if (parameters.maxTokens !== undefined && (parameters.maxTokens < 1 || parameters.maxTokens > 100000)) {
        throw new ExperimentValidationError('configuration.parameters.maxTokens', 
          'Max tokens must be between 1 and 100000');
      }
      if (parameters.topP !== undefined && (parameters.topP < 0 || parameters.topP > 1)) {
        throw new ExperimentValidationError('configuration.parameters.topP', 
          'Top P must be between 0 and 1');
      }
    }
  }

  // Core CRUD operations
  static async createExperiment(
    request: CreateExperimentRequest,
    user: AuthenticatedUser
  ): Promise<ExperimentResponse> {
    logger.info('Creating experiment', { 
      name: request.name, 
      projectId: request.projectId, 
      userId: user.id 
    });

    // Validate request
    this.validateExperimentName(request.name);
    this.validateDescription(request.description);
    this.validateTags(request.tags);
    this.validateConfiguration(request.configuration);

    // Check project permissions
    const project = await ProjectService.getProjectById(request.projectId, user);
    if (!project) {
      throw new ExperimentValidationError('projectId', 'Project not found or access denied');
    }

    // Check workspace permissions
    if (project.workspaceId !== user.workspaceId) {
      throw new ExperimentPermissionError('create', 'project workspace mismatch');
    }

    // Check if user can create experiments
    if (!this.canCreateExperiment(user, request.projectId)) {
      throw new ExperimentPermissionError('create', request.projectId);
    }

    // Validate dataset if provided
    if (request.datasetId) {
      try {
        const dataset = await DatasetService.getDatasetById(request.datasetId, user);
        if (dataset.projectId !== request.projectId) {
          throw new ExperimentValidationError('datasetId', 'Dataset must belong to the same project');
        }
      } catch (error) {
        throw new ExperimentValidationError('datasetId', 'Dataset not found or access denied');
      }
    }

    // Check experiment limits
    const existingExperimentsCount = await this.prisma.experiment.count({
      where: {
        projectId: request.projectId,
        workspaceId: user.workspaceId,
      },
    });

    if (existingExperimentsCount >= EXPERIMENT_LIMITS.maxExperimentsPerProject) {
      throw new ExperimentLimitError('experiments per project', 
        existingExperimentsCount, EXPERIMENT_LIMITS.maxExperimentsPerProject);
    }

    // Check concurrent experiment limits
    const runningExperimentsCount = await this.prisma.experiment.count({
      where: {
        workspaceId: user.workspaceId,
        status: { in: ['running', 'queued'] },
      },
    });

    if (runningExperimentsCount >= EXPERIMENT_LIMITS.maxConcurrentExperiments) {
      throw new ExperimentLimitError('concurrent experiments', 
        runningExperimentsCount, EXPERIMENT_LIMITS.maxConcurrentExperiments);
    }

    // Merge configuration and metadata with defaults
    const configuration: ExperimentConfiguration = {
      ...DEFAULT_EXPERIMENT_CONFIGURATION,
      ...request.configuration,
    } as ExperimentConfiguration;

    const metadata: ExperimentMetadata = {
      ...DEFAULT_EXPERIMENT_METADATA,
      ...request.metadata,
      author: user.fullName || user.username,
    } as ExperimentMetadata;

    const initialProgress: ExperimentProgress = {
      status: 'draft',
      percentage: 0,
      currentStage: 'initialization',
      itemsProcessed: 0,
      itemsTotal: 0,
      errors: [],
      warnings: [],
    };

    try {
      const experiment = await this.prisma.experiment.create({
        data: {
          name: request.name,
          description: request.description || null,
          projectId: request.projectId,
          workspaceId: user.workspaceId,
          datasetId: request.datasetId || null,
          configuration: JSON.stringify(configuration),
          metadata: JSON.stringify(metadata),
          tags: request.tags || [],
          status: 'draft',
          progress: JSON.stringify(initialProgress),
          itemCount: 0,
          createdBy: user.id,
          lastUpdatedBy: user.id,
        },
        include: {
          project: {
            select: { name: true, workspaceName: true },
          },
          dataset: {
            select: { name: true },
          },
          creator: {
            select: { fullName: true, username: true },
          },
          updater: {
            select: { fullName: true, username: true },
          },
        },
      });

      logger.info('Experiment created successfully', { 
        experimentId: experiment.id, 
        name: experiment.name,
        userId: user.id 
      });

      return this.formatExperimentResponse(experiment, user);
    } catch (error) {
      logger.error('Failed to create experiment', { 
        name: request.name, 
        projectId: request.projectId, 
        error 
      });
      throw error;
    }
  }

  static async getExperimentById(
    experimentId: string,
    user: AuthenticatedUser
  ): Promise<ExperimentResponse> {
    const experiment = await this.prisma.experiment.findUnique({
      where: { id: experimentId },
      include: {
        project: {
          select: { name: true, workspaceName: true },
        },
        dataset: {
          select: { name: true },
        },
        creator: {
          select: { fullName: true, username: true },
        },
        updater: {
          select: { fullName: true, username: true },
        },
      },
    });

    if (!experiment) {
      throw new ExperimentNotFoundError(experimentId);
    }

    // Check workspace isolation
    if (!this.canReadExperiment(user, experiment)) {
      throw new ExperimentPermissionError('read', experimentId);
    }

    return this.formatExperimentResponse(experiment, user);
  }

  static async updateExperiment(
    experimentId: string,
    request: UpdateExperimentRequest,
    user: AuthenticatedUser
  ): Promise<ExperimentResponse> {
    logger.info('Updating experiment', { experimentId, userId: user.id });

    const experiment = await this.prisma.experiment.findUnique({
      where: { id: experimentId },
    });

    if (!experiment) {
      throw new ExperimentNotFoundError(experimentId);
    }

    if (!this.canEditExperiment(user, experiment)) {
      throw new ExperimentPermissionError('update', experimentId);
    }

    // Check if experiment is in a state that allows updates
    if (experiment.status === 'running') {
      throw new ExperimentStatusError(experiment.status as ExperimentStatus, 'draft');
    }

    // Validate updates
    if (request.name !== undefined) {
      this.validateExperimentName(request.name);
    }
    if (request.description !== undefined) {
      this.validateDescription(request.description);
    }
    if (request.tags !== undefined) {
      this.validateTags(request.tags);
    }
    if (request.configuration !== undefined) {
      this.validateConfiguration(request.configuration as ExperimentConfiguration);
    }

    // Update configuration
    let updatedConfiguration = experiment.configuration ? JSON.parse(experiment.configuration as string) : {};
    if (request.configuration) {
      updatedConfiguration = {
        ...updatedConfiguration,
        ...request.configuration,
      };
    }

    // Update metadata
    let updatedMetadata = experiment.metadata ? JSON.parse(experiment.metadata as string) : {};
    if (request.metadata) {
      updatedMetadata = {
        ...updatedMetadata,
        ...request.metadata,
      };
    }

    const updatedExperiment = await this.prisma.experiment.update({
      where: { id: experimentId },
      data: {
        ...(request.name && { name: request.name }),
        ...(request.description !== undefined && { description: request.description }),
        ...(request.datasetId !== undefined && { datasetId: request.datasetId }),
        ...(request.tags && { tags: request.tags }),
        ...(request.configuration && { configuration: JSON.stringify(updatedConfiguration) }),
        ...(request.metadata && { metadata: JSON.stringify(updatedMetadata) }),
        ...(request.status && { status: request.status }),
        lastUpdatedBy: user.id,
        lastUpdatedAt: new Date(),
      },
      include: {
        project: {
          select: { name: true, workspaceName: true },
        },
        dataset: {
          select: { name: true },
        },
        creator: {
          select: { fullName: true, username: true },
        },
        updater: {
          select: { fullName: true, username: true },
        },
      },
    });

    logger.info('Experiment updated successfully', { experimentId, userId: user.id });
    return this.formatExperimentResponse(updatedExperiment, user);
  }

  static async deleteExperiment(
    experimentId: string,
    user: AuthenticatedUser
  ): Promise<void> {
    logger.info('Deleting experiment', { experimentId, userId: user.id });

    const experiment = await this.prisma.experiment.findUnique({
      where: { id: experimentId },
    });

    if (!experiment) {
      throw new ExperimentNotFoundError(experimentId);
    }

    if (!this.canDeleteExperiment(user, experiment)) {
      throw new ExperimentPermissionError('delete', experimentId);
    }

    // Check if experiment is running
    if (experiment.status === 'running') {
      throw new ExperimentStatusError(experiment.status as ExperimentStatus, 'stopped' as ExperimentStatus);
    }

    // Delete experiment
    await this.prisma.experiment.delete({
      where: { id: experimentId },
    });

    logger.info('Experiment deleted successfully', { experimentId, userId: user.id });
  }

  static async listExperiments(
    request: ExperimentListRequest,
    user: AuthenticatedUser
  ): Promise<ExperimentListResponse> {
    const page = Math.max(1, request.page || 1);
    const limit = Math.min(100, Math.max(1, request.limit || 20));
    const offset = (page - 1) * limit;

    // Build where conditions with workspace isolation
    const whereConditions: any = {
      workspaceId: user.workspaceId, // Enforce workspace isolation
    };

    if (request.projectId) {
      // Verify user has access to the project
      const project = await ProjectService.getProjectById(request.projectId, user);
      if (project) {
        whereConditions.projectId = request.projectId;
      } else {
        // Return empty result if no access
        return this.emptyExperimentListResponse(request, page, limit);
      }
    }

    if (request.datasetId) {
      whereConditions.datasetId = request.datasetId;
    }

    if (request.status?.length) {
      whereConditions.status = { in: request.status };
    }

    if (request.tags?.length) {
      whereConditions.tags = { hasSome: request.tags };
    }

    if (request.createdBy) {
      whereConditions.createdBy = request.createdBy;
    }

    if (request.search) {
      whereConditions.OR = [
        { name: { contains: request.search, mode: 'insensitive' } },
        { description: { contains: request.search, mode: 'insensitive' } },
      ];
    }

    if (request.dateRange) {
      whereConditions.createdAt = {
        gte: request.dateRange.start,
        lte: request.dateRange.end,
      };
    }

    // Build order by
    const orderBy: any = {};
    const sortBy = request.sortBy || 'created_at';
    const sortOrder = request.sortOrder || 'desc';
    
    if (sortBy === 'created_at') {
      orderBy.createdAt = sortOrder;
    } else if (sortBy === 'updated_at') {
      orderBy.lastUpdatedAt = sortOrder;
    } else if (sortBy === 'name') {
      orderBy.name = sortOrder;
    } else if (sortBy === 'status') {
      orderBy.status = sortOrder;
    }

    const [experiments, total] = await Promise.all([
      this.prisma.experiment.findMany({
        where: whereConditions,
        orderBy,
        skip: offset,
        take: limit,
        include: {
          project: {
            select: { name: true, workspaceName: true },
          },
          dataset: {
            select: { name: true },
          },
          creator: {
            select: { fullName: true, username: true },
          },
          updater: {
            select: { fullName: true, username: true },
          },
        },
      }),
      this.prisma.experiment.count({ where: whereConditions }),
    ]);

    const formattedExperiments = experiments.map(experiment => 
      this.formatExperimentResponse(experiment, user)
    );

    // Calculate aggregations
    const statusCounts = await this.calculateStatusCounts(whereConditions);
    const providerCounts = await this.calculateProviderCounts(whereConditions);
    const costAndDuration = await this.calculateCostAndDuration(whereConditions);

    return {
      experiments: formattedExperiments,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
      filters: {
        projectId: request.projectId,
        workspaceId: request.workspaceId,
        datasetId: request.datasetId,
        status: request.status,
        tags: request.tags,
        modelProvider: request.modelProvider,
      },
      sorting: {
        sortBy,
        sortOrder,
      },
      aggregations: {
        statusCounts,
        providerCounts,
        totalCost: costAndDuration.totalCost,
        averageDuration: costAndDuration.averageDuration,
      },
    };
  }

  // Helper methods
  private static formatExperimentResponse(experiment: any, user: AuthenticatedUser): ExperimentResponse {
    const configuration = experiment.configuration ? JSON.parse(experiment.configuration) : DEFAULT_EXPERIMENT_CONFIGURATION;
    const metadata = experiment.metadata ? JSON.parse(experiment.metadata) : DEFAULT_EXPERIMENT_METADATA;
    const progress = experiment.progress ? JSON.parse(experiment.progress) : { status: experiment.status, percentage: 0, currentStage: 'unknown', itemsProcessed: 0, itemsTotal: 0, errors: [], warnings: [] };
    
    return {
      id: experiment.id,
      name: experiment.name,
      description: experiment.description,
      projectId: experiment.projectId,
      projectName: experiment.project?.name || '',
      workspaceId: experiment.workspaceId,
      workspaceName: experiment.project?.workspaceName || '',
      datasetId: experiment.datasetId,
      datasetName: experiment.dataset?.name || null,
      configuration,
      metadata,
      tags: experiment.tags || [],
      status: experiment.status,
      progress,
      results: experiment.results ? JSON.parse(experiment.results) : undefined,
      createdAt: experiment.createdAt,
      createdBy: experiment.createdBy,
      createdByName: experiment.creator?.fullName || experiment.creator?.username || '',
      lastUpdatedAt: experiment.lastUpdatedAt,
      lastUpdatedBy: experiment.lastUpdatedBy,
      lastUpdatedByName: experiment.updater?.fullName || experiment.updater?.username || '',
      startedAt: experiment.startedAt,
      completedAt: experiment.completedAt,
      // Statistics
      totalItems: experiment.itemCount,
      processedItems: progress.itemsProcessed,
      successfulItems: experiment.successfulItems || 0,
      failedItems: experiment.failedItems || 0,
      averageLatency: experiment.averageLatency || 0,
      totalCost: experiment.totalCost || 0,
      // Permissions
      canRead: this.canReadExperiment(user, experiment),
      canEdit: this.canEditExperiment(user, experiment),
      canDelete: this.canDeleteExperiment(user, experiment),
      canStart: this.canStartExperiment(user, experiment),
      canStop: this.canStopExperiment(user, experiment),
      canReset: this.canEditExperiment(user, experiment),
      canClone: this.canReadExperiment(user, experiment),
      canExport: this.canExportResults(user, experiment),
      canViewResults: this.canViewResults(user, experiment),
      canViewLogs: this.canReadExperiment(user, experiment),
    };
  }

  private static emptyExperimentListResponse(
    request: ExperimentListRequest,
    page: number,
    limit: number
  ): ExperimentListResponse {
    return {
      experiments: [],
      pagination: { page, limit, total: 0, totalPages: 0 },
      filters: {
        projectId: request.projectId,
        workspaceId: request.workspaceId,
        datasetId: request.datasetId,
        status: request.status,
        tags: request.tags,
        modelProvider: request.modelProvider,
      },
      sorting: {
        sortBy: request.sortBy || 'created_at',
        sortOrder: request.sortOrder || 'desc',
      },
      aggregations: {
        statusCounts: {} as any,
        providerCounts: {},
        totalCost: 0,
        averageDuration: 0,
      },
    };
  }

  private static async calculateStatusCounts(whereConditions: any): Promise<Record<ExperimentStatus, number>> {
    const counts = await this.prisma.experiment.groupBy({
      by: ['status'],
      where: whereConditions,
      _count: true,
    });

    const statusCounts: any = {};
    counts.forEach(count => {
      statusCounts[count.status] = count._count;
    });

    return statusCounts;
  }

  private static async calculateProviderCounts(whereConditions: any): Promise<Record<string, number>> {
    // This would require parsing configuration JSON to extract model providers
    // For now, return empty object
    return {};
  }

  private static async calculateCostAndDuration(whereConditions: any): Promise<{ totalCost: number; averageDuration: number }> {
    // This would calculate actual costs and durations
    // For now, return default values
    return { totalCost: 0, averageDuration: 0 };
  }

  // Placeholder methods for future implementation
  static async startExperiment(
    experimentId: string,
    request: StartExperimentRequest,
    user: AuthenticatedUser
  ): Promise<void> {
    // Implementation would start experiment execution
    throw new Error('Not implemented yet');
  }

  static async stopExperiment(
    experimentId: string,
    request: StopExperimentRequest,
    user: AuthenticatedUser
  ): Promise<void> {
    // Implementation would stop experiment execution
    throw new Error('Not implemented yet');
  }

  static async pauseExperiment(
    experimentId: string,
    request: PauseExperimentRequest,
    user: AuthenticatedUser
  ): Promise<void> {
    // Implementation would pause experiment execution
    throw new Error('Not implemented yet');
  }

  static async cloneExperiment(
    experimentId: string,
    request: CloneExperimentRequest,
    user: AuthenticatedUser
  ): Promise<ExperimentResponse> {
    // Implementation would clone experiment
    throw new Error('Not implemented yet');
  }

  static async getExperimentStatistics(
    experimentId: string,
    user: AuthenticatedUser
  ): Promise<ExperimentStatisticsResponse> {
    // Implementation would calculate comprehensive statistics
    throw new Error('Not implemented yet');
  }

  static async getExperimentMetrics(
    request: ExperimentMetricsRequest,
    user: AuthenticatedUser
  ): Promise<ExperimentMetricsResponse> {
    // Implementation would fetch metrics from ClickHouse
    throw new Error('Not implemented yet');
  }

  static async bulkExperimentOperation(
    request: BulkExperimentOperationRequest,
    user: AuthenticatedUser
  ): Promise<BulkExperimentOperationResponse> {
    // Implementation would handle bulk operations
    throw new Error('Not implemented yet');
  }
}