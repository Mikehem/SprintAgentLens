import { prisma } from '@/config/database';
import { logger, dbLogger } from '@/utils/logger';
import { AuthenticatedUser } from '@/types/auth';
import {
  CreateProjectRequest,
  UpdateProjectRequest,
  ProjectResponse,
  ProjectListResponse,
  ProjectFilters,
  ProjectSortOptions,
  PaginationInfo,
  BulkDeleteRequest,
  BulkDeleteResponse,
  ProjectStatsResponse,
  FeedbackScoreNamesResponse,
  ProjectMetricRequest,
  ProjectMetricResponse,
  ProjectPermissions,
  ProjectAuditAction,
  ProjectNotFoundError,
  ProjectPermissionError,
  ProjectValidationError,
  WorkspaceAccessError,
} from '@/types/projects';
import { UserRole } from '@/types/auth';

/**
 * Project Service with Enterprise Authentication Integration
 * All operations include workspace isolation, RBAC, and audit logging
 */
export class ProjectService {
  /**
   * Create a new project with authentication and authorization
   */
  static async createProject(
    request: CreateProjectRequest,
    user: AuthenticatedUser
  ): Promise<ProjectResponse> {
    try {
      logger.info(`Creating project: ${request.name}`, {
        userId: user.id,
        username: user.username,
        workspaceId: request.workspaceId || user.workspaceId,
      });

      // Validate permissions
      if (!this.canCreateProject(user)) {
        throw new ProjectPermissionError('create', 'new project');
      }

      // Determine workspace
      const workspaceId = request.workspaceId || user.workspaceId;
      
      // Verify workspace access
      if (!this.canAccessWorkspace(user, workspaceId)) {
        throw new WorkspaceAccessError(workspaceId);
      }

      // Validate input
      this.validateCreateRequest(request);

      // Check for duplicate project name in workspace
      const existingProject = await prisma.project.findFirst({
        where: {
          name: request.name,
          workspaceId: workspaceId,
        },
      });

      if (existingProject) {
        throw new ProjectValidationError('name', `Project name '${request.name}' already exists in workspace`);
      }

      // Create project
      const project = await prisma.project.create({
        data: {
          name: request.name.trim(),
          description: request.description?.trim() || null,
          workspaceId: workspaceId,
          createdBy: user.id,
        },
      });

      // Log audit event
      await this.logAuditEvent(project.id, user.id, ProjectAuditAction.CREATED, {
        projectName: request.name,
        workspaceId: workspaceId,
      });

      logger.info(`Project created successfully: ${project.id}`, {
        projectId: project.id,
        projectName: project.name,
        userId: user.id,
      });

      return this.toProjectResponse(project, user);
    } catch (error) {
      logger.error('Project creation failed:', error);
      throw error;
    }
  }

  /**
   * List projects with authentication, filtering, and pagination
   */
  static async listProjects(
    user: AuthenticatedUser,
    filters?: ProjectFilters,
    sort?: ProjectSortOptions,
    page = 1,
    size = 10
  ): Promise<ProjectListResponse> {
    try {
      logger.debug(`Listing projects for user: ${user.username}`, {
        userId: user.id,
        workspaceId: user.workspaceId,
        filters,
        sort,
        page,
        size,
      });

      // Build where clause with workspace isolation
      const whereClause: any = {};
      
      // Workspace isolation - critical security requirement
      if (user.role === UserRole.ADMIN) {
        // Admin can see all workspaces or filter by specific workspace
        if (filters?.workspaceName) {
          whereClause.workspaceId = filters.workspaceName;
        }
      } else {
        // Regular users can only see their workspace
        whereClause.workspaceId = user.workspaceId;
      }

      // Apply additional filters
      if (filters?.name) {
        whereClause.name = {
          contains: filters.name,
          mode: 'insensitive',
        };
      }

      if (filters?.createdBy) {
        whereClause.createdBy = filters.createdBy;
      }

      if (filters?.createdAfter || filters?.createdBefore) {
        whereClause.createdAt = {};
        if (filters.createdAfter) {
          whereClause.createdAt.gte = filters.createdAfter;
        }
        if (filters.createdBefore) {
          whereClause.createdAt.lte = filters.createdBefore;
        }
      }

      // Build sort order
      const orderBy: any = {};
      if (sort) {
        orderBy[sort.field] = sort.order;
      } else {
        orderBy.createdAt = 'desc'; // Default sort
      }

      // Execute query with pagination
      const [projects, totalCount] = await Promise.all([
        prisma.project.findMany({
          where: whereClause,
          orderBy: orderBy,
          skip: (page - 1) * size,
          take: size,
          include: {
            creator: {
              select: { username: true, fullName: true },
            },
            _count: {
              select: {
                datasets: true,
                experiments: true,
              },
            },
          },
        }),
        prisma.project.count({ where: whereClause }),
      ]);

      // Transform to response format
      const projectResponses = projects.map(project => 
        this.toProjectResponse(project, user, {
          datasetCount: project._count.datasets,
          experimentCount: project._count.experiments,
        })
      );

      const pagination: PaginationInfo = {
        page,
        size,
        total: totalCount,
        totalPages: Math.ceil(totalCount / size),
        hasNext: page < Math.ceil(totalCount / size),
        hasPrevious: page > 1,
      };

      dbLogger.debug(`Listed ${projects.length} projects`, {
        userId: user.id,
        totalCount,
        page,
        size,
      });

      return {
        projects: projectResponses,
        pagination,
        filters,
      };
    } catch (error) {
      logger.error('Project listing failed:', error);
      throw error;
    }
  }

  /**
   * Get project by ID with authentication and authorization
   */
  static async getProject(
    projectId: string,
    user: AuthenticatedUser
  ): Promise<ProjectResponse> {
    try {
      logger.debug(`Getting project: ${projectId}`, {
        projectId,
        userId: user.id,
      });

      const project = await prisma.project.findUnique({
        where: { id: projectId },
        include: {
          creator: {
            select: { username: true, fullName: true },
          },
          _count: {
            select: {
              datasets: true,
              experiments: true,
            },
          },
        },
      });

      if (!project) {
        throw new ProjectNotFoundError(projectId);
      }

      // Check permissions
      if (!this.canReadProject(user, project)) {
        await this.logAuditEvent(projectId, user.id, ProjectAuditAction.PERMISSION_DENIED, {
          action: 'read',
          reason: 'workspace_access_denied',
        });
        throw new ProjectPermissionError('read', projectId);
      }

      // Log audit event for viewing
      await this.logAuditEvent(projectId, user.id, ProjectAuditAction.VIEWED);

      return this.toProjectResponse(project, user, {
        datasetCount: project._count.datasets,
        experimentCount: project._count.experiments,
      });
    } catch (error) {
      logger.error(`Project retrieval failed for ${projectId}:`, error);
      throw error;
    }
  }

  /**
   * Update project with authentication and authorization
   */
  static async updateProject(
    projectId: string,
    updates: UpdateProjectRequest,
    user: AuthenticatedUser
  ): Promise<ProjectResponse> {
    try {
      logger.info(`Updating project: ${projectId}`, {
        projectId,
        userId: user.id,
        updates,
      });

      const project = await prisma.project.findUnique({
        where: { id: projectId },
      });

      if (!project) {
        throw new ProjectNotFoundError(projectId);
      }

      // Check permissions
      if (!this.canEditProject(user, project)) {
        await this.logAuditEvent(projectId, user.id, ProjectAuditAction.PERMISSION_DENIED, {
          action: 'update',
          reason: 'insufficient_permissions',
        });
        throw new ProjectPermissionError('update', projectId);
      }

      // Validate updates
      this.validateUpdateRequest(updates);

      // Check for name conflicts if name is being changed
      if (updates.name && updates.name !== project.name) {
        const existingProject = await prisma.project.findFirst({
          where: {
            name: updates.name,
            workspaceId: project.workspaceId,
            id: { not: projectId },
          },
        });

        if (existingProject) {
          throw new ProjectValidationError('name', `Project name '${updates.name}' already exists in workspace`);
        }
      }

      // Update project
      const updatedProject = await prisma.project.update({
        where: { id: projectId },
        data: {
          ...(updates.name && { name: updates.name.trim() }),
          ...(updates.description !== undefined && { description: updates.description?.trim() || null }),
          lastUpdatedBy: user.id,
        },
        include: {
          creator: {
            select: { username: true, fullName: true },
          },
          _count: {
            select: {
              datasets: true,
              experiments: true,
            },
          },
        },
      });

      // Log audit event
      await this.logAuditEvent(projectId, user.id, ProjectAuditAction.UPDATED, {
        changes: updates,
      });

      logger.info(`Project updated successfully: ${projectId}`, {
        projectId,
        userId: user.id,
      });

      return this.toProjectResponse(updatedProject, user, {
        datasetCount: updatedProject._count.datasets,
        experimentCount: updatedProject._count.experiments,
      });
    } catch (error) {
      logger.error(`Project update failed for ${projectId}:`, error);
      throw error;
    }
  }

  /**
   * Delete project with authentication and authorization
   */
  static async deleteProject(
    projectId: string,
    user: AuthenticatedUser,
    force = false
  ): Promise<void> {
    try {
      logger.info(`Deleting project: ${projectId}`, {
        projectId,
        userId: user.id,
        force,
      });

      const project = await prisma.project.findUnique({
        where: { id: projectId },
        include: {
          _count: {
            select: {
              datasets: true,
              experiments: true,
            },
          },
        },
      });

      if (!project) {
        throw new ProjectNotFoundError(projectId);
      }

      // Check permissions
      if (!this.canDeleteProject(user, project)) {
        await this.logAuditEvent(projectId, user.id, ProjectAuditAction.PERMISSION_DENIED, {
          action: 'delete',
          reason: 'insufficient_permissions',
        });
        throw new ProjectPermissionError('delete', projectId);
      }

      // Check if project has dependencies
      const hasDatasets = project._count.datasets > 0;
      const hasExperiments = project._count.experiments > 0;

      if ((hasDatasets || hasExperiments) && !force) {
        throw new ProjectValidationError(
          'dependencies', 
          `Project has ${project._count.datasets} datasets and ${project._count.experiments} experiments. Use force=true to delete anyway.`
        );
      }

      if (force && (hasDatasets || hasExperiments) && user.role !== UserRole.ADMIN) {
        throw new ProjectPermissionError('force delete', projectId);
      }

      // Delete project (CASCADE will handle related records)
      await prisma.project.delete({
        where: { id: projectId },
      });

      // Log audit event
      await this.logAuditEvent(projectId, user.id, ProjectAuditAction.DELETED, {
        projectName: project.name,
        datasetsDeleted: project._count.datasets,
        experimentsDeleted: project._count.experiments,
        force,
      });

      logger.info(`Project deleted successfully: ${projectId}`, {
        projectId,
        userId: user.id,
        datasetsDeleted: project._count.datasets,
        experimentsDeleted: project._count.experiments,
      });
    } catch (error) {
      logger.error(`Project deletion failed for ${projectId}:`, error);
      throw error;
    }
  }

  /**
   * Permission checking methods
   */
  private static canCreateProject(user: AuthenticatedUser): boolean {
    return user.permissions.includes('projects:create');
  }

  private static canReadProject(user: AuthenticatedUser, project: any): boolean {
    // Admin can read any project
    if (user.role === UserRole.ADMIN) {
      return true;
    }
    
    // Users can only read projects in their workspace
    return project.workspaceId === user.workspaceId;
  }

  private static canEditProject(user: AuthenticatedUser, project: any): boolean {
    // Admin can edit any project
    if (user.role === UserRole.ADMIN) {
      return true;
    }
    
    // Users can only edit projects in their workspace and have edit permission
    return project.workspaceId === user.workspaceId && 
           user.permissions.includes('projects:update');
  }

  private static canDeleteProject(user: AuthenticatedUser, project: any): boolean {
    // Admin can delete any project
    if (user.role === UserRole.ADMIN) {
      return true;
    }
    
    // Users can delete their own projects or if they have delete permission
    return project.workspaceId === user.workspaceId && 
           (project.createdBy === user.id || user.permissions.includes('projects:delete'));
  }

  private static canAccessWorkspace(user: AuthenticatedUser, workspaceId: string): boolean {
    // Admin can access any workspace
    if (user.role === UserRole.ADMIN) {
      return true;
    }
    
    // Regular users can only access their own workspace
    return user.workspaceId === workspaceId;
  }

  /**
   * Get user permissions for a project
   */
  private static getProjectPermissions(user: AuthenticatedUser, project: any): ProjectPermissions {
    const isOwner = project.createdBy === user.id;
    const isAdmin = user.role === UserRole.ADMIN;
    const canAccess = this.canReadProject(user, project);

    return {
      canRead: canAccess,
      canEdit: canAccess && (isAdmin || user.permissions.includes('projects:update')),
      canDelete: canAccess && (isAdmin || isOwner || user.permissions.includes('projects:delete')),
      canCreateDatasets: canAccess && user.permissions.includes('datasets:create'),
      canCreateExperiments: canAccess && user.permissions.includes('experiments:create'),
      canViewMetrics: canAccess && user.permissions.includes('projects:read'),
      canManageUsers: isAdmin,
      isOwner,
    };
  }

  /**
   * Transform database project to response format
   */
  private static toProjectResponse(
    project: any,
    user: AuthenticatedUser,
    stats?: { datasetCount?: number; experimentCount?: number }
  ): ProjectResponse {
    const permissions = this.getProjectPermissions(user, project);

    return {
      id: project.id,
      name: project.name,
      description: project.description,
      workspaceId: project.workspaceId,
      createdAt: project.createdAt,
      createdBy: project.createdBy,
      lastUpdatedAt: project.lastUpdatedAt,
      lastUpdatedBy: project.lastUpdatedBy,
      ...(stats && {
        datasetCount: stats.datasetCount,
        experimentCount: stats.experimentCount,
      }),
      canEdit: permissions.canEdit,
      canDelete: permissions.canDelete,
      canCreateDatasets: permissions.canCreateDatasets,
      canCreateExperiments: permissions.canCreateExperiments,
    };
  }

  /**
   * Validation methods
   */
  private static validateCreateRequest(request: CreateProjectRequest): void {
    if (!request.name || request.name.trim().length === 0) {
      throw new ProjectValidationError('name', 'Project name is required');
    }

    if (request.name.length > 100) {
      throw new ProjectValidationError('name', 'Project name cannot exceed 100 characters');
    }

    if (request.description && request.description.length > 1000) {
      throw new ProjectValidationError('description', 'Project description cannot exceed 1000 characters');
    }
  }

  private static validateUpdateRequest(updates: UpdateProjectRequest): void {
    if (updates.name !== undefined) {
      if (!updates.name || updates.name.trim().length === 0) {
        throw new ProjectValidationError('name', 'Project name cannot be empty');
      }

      if (updates.name.length > 100) {
        throw new ProjectValidationError('name', 'Project name cannot exceed 100 characters');
      }
    }

    if (updates.description !== undefined && updates.description && updates.description.length > 1000) {
      throw new ProjectValidationError('description', 'Project description cannot exceed 1000 characters');
    }
  }

  /**
   * Audit logging
   */
  private static async logAuditEvent(
    projectId: string,
    userId: string,
    action: ProjectAuditAction,
    details?: Record<string, any>
  ): Promise<void> {
    try {
      // For now, we'll use the existing userAuditLog table
      // In the future, we might create a dedicated projectAuditLog table
      await prisma.userAuditLog.create({
        data: {
          userId,
          event: `project_${action.toLowerCase()}`,
          eventType: 'USER_UPDATED', // We'll extend this enum later
          description: `Project ${action}: ${projectId}`,
          metadata: {
            projectId,
            action,
            ...details,
          },
        },
      });
    } catch (error) {
      logger.error('Failed to log project audit event:', error);
      // Don't throw - audit logging failure shouldn't break the operation
    }
  }
}