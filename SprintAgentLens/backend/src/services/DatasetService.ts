/**
 * Dataset Service - Enterprise dataset management with authentication
 * Provides comprehensive CRUD operations with workspace isolation and RBAC
 */

import { PrismaClient } from '@prisma/client';
import { logger } from '@/utils/logger';
import type { AuthenticatedUser } from '@/types/auth';
import type {
  CreateDatasetRequest,
  UpdateDatasetRequest,
  DatasetResponse,
  DatasetListRequest,
  DatasetListResponse,
  DatasetStatisticsResponse,
  DatasetMetricsRequest,
  DatasetMetricsResponse,
  BulkDatasetOperationRequest,
  BulkDatasetOperationResponse,
  CreateDatasetItemRequest,
  UpdateDatasetItemRequest,
  DatasetItemResponse,
  DatasetItemListRequest,
  DatasetItemListResponse,
  DatasetStatus,
  DatasetMetadata,
  DatasetPermissionChecker,
  DatasetNotFoundError,
  DatasetPermissionError,
  DatasetValidationError,
  DatasetStatusError,
  DatasetLimitError,
  DEFAULT_DATASET_METADATA,
  DATASET_ITEM_LIMITS,
  DATASET_VALIDATION_RULES,
} from '@/types/datasets';
import { ProjectService } from './ProjectService';

export class DatasetService implements DatasetPermissionChecker {
  private static prisma = new PrismaClient();

  // Permission checking methods
  static canCreateDataset(user: AuthenticatedUser, projectId: string): boolean {
    if (user.role === 'admin') return true;
    if (user.role === 'viewer') return false;
    return user.role === 'user';
  }

  static canReadDataset(user: AuthenticatedUser, dataset: any): boolean {
    if (user.role === 'admin') return true;
    return dataset.workspaceId === user.workspaceId;
  }

  static canEditDataset(user: AuthenticatedUser, dataset: any): boolean {
    if (user.role === 'admin') return true;
    if (user.role === 'viewer') return false;
    return dataset.workspaceId === user.workspaceId && user.role === 'user';
  }

  static canDeleteDataset(user: AuthenticatedUser, dataset: any): boolean {
    if (user.role === 'admin') return true;
    if (user.role === 'viewer') return false;
    return dataset.workspaceId === user.workspaceId && user.role === 'user';
  }

  static canAddItems(user: AuthenticatedUser, dataset: any): boolean {
    return this.canEditDataset(user, dataset);
  }

  static canEditItems(user: AuthenticatedUser, dataset: any): boolean {
    return this.canEditDataset(user, dataset);
  }

  static canViewMetrics(user: AuthenticatedUser, dataset: any): boolean {
    return this.canReadDataset(user, dataset);
  }

  static canExportDataset(user: AuthenticatedUser, dataset: any): boolean {
    return this.canReadDataset(user, dataset);
  }

  // Validation methods
  private static validateDatasetName(name: string): void {
    const { minLength, maxLength, pattern } = DATASET_VALIDATION_RULES.name;
    
    if (!name || name.length < minLength) {
      throw new DatasetValidationError('name', `Name must be at least ${minLength} characters`);
    }
    if (name.length > maxLength) {
      throw new DatasetValidationError('name', `Name cannot exceed ${maxLength} characters`);
    }
    if (!pattern.test(name)) {
      throw new DatasetValidationError('name', 'Name contains invalid characters');
    }
  }

  private static validateDescription(description?: string): void {
    if (description && description.length > DATASET_VALIDATION_RULES.description.maxLength) {
      throw new DatasetValidationError('description', 
        `Description cannot exceed ${DATASET_VALIDATION_RULES.description.maxLength} characters`);
    }
  }

  private static validateTags(tags?: string[]): void {
    if (!tags) return;
    
    const { maxCount, maxTagLength } = DATASET_VALIDATION_RULES.tags;
    
    if (tags.length > maxCount) {
      throw new DatasetValidationError('tags', `Cannot have more than ${maxCount} tags`);
    }
    
    for (const tag of tags) {
      if (tag.length > maxTagLength) {
        throw new DatasetValidationError('tags', 
          `Tag "${tag}" cannot exceed ${maxTagLength} characters`);
      }
    }
  }

  // Core CRUD operations
  static async createDataset(
    request: CreateDatasetRequest,
    user: AuthenticatedUser
  ): Promise<DatasetResponse> {
    logger.info('Creating dataset', { 
      name: request.name, 
      projectId: request.projectId, 
      userId: user.id 
    });

    // Validate request
    this.validateDatasetName(request.name);
    this.validateDescription(request.description);
    this.validateTags(request.tags);

    // Check project permissions
    const project = await ProjectService.getProjectById(request.projectId, user);
    if (!project) {
      throw new DatasetValidationError('projectId', 'Project not found or access denied');
    }

    // Check workspace permissions
    if (project.workspaceId !== user.workspaceId) {
      throw new DatasetPermissionError('create', 'project workspace mismatch');
    }

    // Check if user can create datasets
    if (!this.canCreateDataset(user, request.projectId)) {
      throw new DatasetPermissionError('create', request.projectId);
    }

    // Check dataset limits
    const existingDatasetsCount = await this.prisma.dataset.count({
      where: {
        projectId: request.projectId,
        workspaceId: user.workspaceId,
      },
    });

    // Get workspace limits (assuming from project service or workspace settings)
    const workspaceSettings = await this.getWorkspaceSettings(user.workspaceId);
    const maxDatasetsPerProject = workspaceSettings?.limits?.maxDatasetsPerProject || 50;

    if (existingDatasetsCount >= maxDatasetsPerProject) {
      throw new DatasetLimitError('datasets per project', existingDatasetsCount, maxDatasetsPerProject);
    }

    // Merge metadata with defaults
    const metadata: DatasetMetadata = {
      ...DEFAULT_DATASET_METADATA,
      ...request.metadata,
      annotations: {
        ...DEFAULT_DATASET_METADATA.annotations,
        author: user.fullName || user.username,
        ...request.metadata?.annotations,
      },
    } as DatasetMetadata;

    try {
      const dataset = await this.prisma.dataset.create({
        data: {
          name: request.name,
          description: request.description || null,
          projectId: request.projectId,
          workspaceId: user.workspaceId,
          metadata: JSON.stringify(metadata),
          tags: request.tags || [],
          status: 'draft',
          createdBy: user.id,
          lastUpdatedBy: user.id,
        },
        include: {
          project: {
            select: { name: true, workspaceName: true },
          },
          creator: {
            select: { fullName: true, username: true },
          },
          updater: {
            select: { fullName: true, username: true },
          },
        },
      });

      logger.info('Dataset created successfully', { 
        datasetId: dataset.id, 
        name: dataset.name,
        userId: user.id 
      });

      return this.formatDatasetResponse(dataset, user);
    } catch (error) {
      logger.error('Failed to create dataset', { 
        name: request.name, 
        projectId: request.projectId, 
        error 
      });
      throw error;
    }
  }

  static async getDatasetById(
    datasetId: string,
    user: AuthenticatedUser
  ): Promise<DatasetResponse> {
    const dataset = await this.prisma.dataset.findUnique({
      where: { id: datasetId },
      include: {
        project: {
          select: { name: true, workspaceName: true },
        },
        creator: {
          select: { fullName: true, username: true },
        },
        updater: {
          select: { fullName: true, username: true },
        },
        _count: {
          select: { items: true },
        },
      },
    });

    if (!dataset) {
      throw new DatasetNotFoundError(datasetId);
    }

    // Check workspace isolation
    if (!this.canReadDataset(user, dataset)) {
      throw new DatasetPermissionError('read', datasetId);
    }

    return this.formatDatasetResponse(dataset, user);
  }

  static async updateDataset(
    datasetId: string,
    request: UpdateDatasetRequest,
    user: AuthenticatedUser
  ): Promise<DatasetResponse> {
    logger.info('Updating dataset', { datasetId, userId: user.id });

    const dataset = await this.prisma.dataset.findUnique({
      where: { id: datasetId },
    });

    if (!dataset) {
      throw new DatasetNotFoundError(datasetId);
    }

    if (!this.canEditDataset(user, dataset)) {
      throw new DatasetPermissionError('update', datasetId);
    }

    // Validate updates
    if (request.name !== undefined) {
      this.validateDatasetName(request.name);
    }
    if (request.description !== undefined) {
      this.validateDescription(request.description);
    }
    if (request.tags !== undefined) {
      this.validateTags(request.tags);
    }

    // Update metadata
    let updatedMetadata = dataset.metadata ? JSON.parse(dataset.metadata as string) : {};
    if (request.metadata) {
      updatedMetadata = {
        ...updatedMetadata,
        ...request.metadata,
      };
    }

    const updatedDataset = await this.prisma.dataset.update({
      where: { id: datasetId },
      data: {
        ...(request.name && { name: request.name }),
        ...(request.description !== undefined && { description: request.description }),
        ...(request.tags && { tags: request.tags }),
        ...(request.metadata && { metadata: JSON.stringify(updatedMetadata) }),
        lastUpdatedBy: user.id,
        lastUpdatedAt: new Date(),
      },
      include: {
        project: {
          select: { name: true, workspaceName: true },
        },
        creator: {
          select: { fullName: true, username: true },
        },
        updater: {
          select: { fullName: true, username: true },
        },
        _count: {
          select: { items: true },
        },
      },
    });

    logger.info('Dataset updated successfully', { datasetId, userId: user.id });
    return this.formatDatasetResponse(updatedDataset, user);
  }

  static async deleteDataset(
    datasetId: string,
    user: AuthenticatedUser
  ): Promise<void> {
    logger.info('Deleting dataset', { datasetId, userId: user.id });

    const dataset = await this.prisma.dataset.findUnique({
      where: { id: datasetId },
    });

    if (!dataset) {
      throw new DatasetNotFoundError(datasetId);
    }

    if (!this.canDeleteDataset(user, dataset)) {
      throw new DatasetPermissionError('delete', datasetId);
    }

    // Check if dataset is being used by experiments
    const experimentsUsingDataset = await this.prisma.experiment.count({
      where: { datasetId: datasetId },
    });

    if (experimentsUsingDataset > 0) {
      throw new DatasetStatusError('in_use' as DatasetStatus, 'unused' as DatasetStatus);
    }

    // Delete dataset and all its items (cascade)
    await this.prisma.dataset.delete({
      where: { id: datasetId },
    });

    logger.info('Dataset deleted successfully', { datasetId, userId: user.id });
  }

  static async listDatasets(
    request: DatasetListRequest,
    user: AuthenticatedUser
  ): Promise<DatasetListResponse> {
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
        return {
          datasets: [],
          pagination: { page, limit, total: 0, totalPages: 0 },
          filters: request,
          sorting: {
            sortBy: request.sortBy || 'created_at',
            sortOrder: request.sortOrder || 'desc',
          },
        };
      }
    }

    if (request.status?.length) {
      whereConditions.status = { in: request.status };
    }

    if (request.tags?.length) {
      whereConditions.tags = { hasSome: request.tags };
    }

    if (request.search) {
      whereConditions.OR = [
        { name: { contains: request.search, mode: 'insensitive' } },
        { description: { contains: request.search, mode: 'insensitive' } },
      ];
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
    } else if (sortBy === 'item_count') {
      // This requires a more complex query, will be handled differently
      orderBy.createdAt = sortOrder; // Fallback
    }

    const [datasets, total] = await Promise.all([
      this.prisma.dataset.findMany({
        where: whereConditions,
        orderBy,
        skip: offset,
        take: limit,
        include: {
          project: {
            select: { name: true, workspaceName: true },
          },
          creator: {
            select: { fullName: true, username: true },
          },
          updater: {
            select: { fullName: true, username: true },
          },
          _count: {
            select: { items: true },
          },
        },
      }),
      this.prisma.dataset.count({ where: whereConditions }),
    ]);

    const formattedDatasets = datasets.map(dataset => 
      this.formatDatasetResponse(dataset, user)
    );

    return {
      datasets: formattedDatasets,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
      filters: {
        projectId: request.projectId,
        workspaceId: request.workspaceId,
        status: request.status,
        tags: request.tags,
      },
      sorting: {
        sortBy,
        sortOrder,
      },
    };
  }

  // Helper methods
  private static formatDatasetResponse(dataset: any, user: AuthenticatedUser): DatasetResponse {
    const metadata = dataset.metadata ? JSON.parse(dataset.metadata) : DEFAULT_DATASET_METADATA;
    
    return {
      id: dataset.id,
      name: dataset.name,
      description: dataset.description,
      projectId: dataset.projectId,
      projectName: dataset.project?.name || '',
      workspaceId: dataset.workspaceId,
      workspaceName: dataset.project?.workspaceName || '',
      metadata,
      tags: dataset.tags || [],
      itemCount: dataset._count?.items || 0,
      status: dataset.status,
      createdAt: dataset.createdAt,
      createdBy: dataset.createdBy,
      createdByName: dataset.creator?.fullName || dataset.creator?.username || '',
      lastUpdatedAt: dataset.lastUpdatedAt,
      lastUpdatedBy: dataset.lastUpdatedBy,
      lastUpdatedByName: dataset.updater?.fullName || dataset.updater?.username || '',
      // Permissions
      canRead: this.canReadDataset(user, dataset),
      canEdit: this.canEditDataset(user, dataset),
      canDelete: this.canDeleteDataset(user, dataset),
      canAddItems: this.canAddItems(user, dataset),
      canRemoveItems: this.canEditItems(user, dataset),
      canExport: this.canExportDataset(user, dataset),
      canShare: this.canEditDataset(user, dataset),
      canViewMetrics: this.canViewMetrics(user, dataset),
    };
  }

  private static async getWorkspaceSettings(workspaceId: string) {
    // This would fetch workspace settings - placeholder implementation
    return {
      limits: {
        maxDatasetsPerProject: 50,
        maxItemsPerDataset: DATASET_ITEM_LIMITS.maxItemsPerDataset,
      },
    };
  }

  // Placeholder methods for future implementation
  static async getDatasetStatistics(
    datasetId: string,
    user: AuthenticatedUser
  ): Promise<DatasetStatisticsResponse> {
    // Implementation would calculate comprehensive statistics
    throw new Error('Not implemented yet');
  }

  static async getDatasetMetrics(
    request: DatasetMetricsRequest,
    user: AuthenticatedUser
  ): Promise<DatasetMetricsResponse> {
    // Implementation would fetch metrics from ClickHouse
    throw new Error('Not implemented yet');
  }

  static async bulkDatasetOperation(
    request: BulkDatasetOperationRequest,
    user: AuthenticatedUser
  ): Promise<BulkDatasetOperationResponse> {
    // Implementation would handle bulk operations
    throw new Error('Not implemented yet');
  }
}