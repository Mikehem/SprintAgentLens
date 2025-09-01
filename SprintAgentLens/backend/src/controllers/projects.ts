import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import Joi from 'joi';
import { ProjectService } from '@/services/ProjectService';
import { requireAuth, requireUser } from '@/middleware/auth';
import { logger, apiLogger } from '@/utils/logger';
import {
  CreateProjectRequest,
  UpdateProjectRequest,
  ProjectFilters,
  ProjectSortOptions,
  BulkDeleteRequest,
  ProjectNotFoundError,
  ProjectPermissionError,
  ProjectValidationError,
  WorkspaceAccessError,
} from '@/types/projects';

/**
 * Projects Controller with Enterprise Authentication Integration
 * All endpoints require authentication and implement RBAC
 * 
 * Compatible with OPIK Java backend ProjectsResource
 */

// Validation schemas
const createProjectSchema = Joi.object({
  name: Joi.string().trim().min(1).max(100).required(),
  description: Joi.string().trim().max(1000).optional().allow(''),
  workspaceId: Joi.string().max(50).optional(),
});

const updateProjectSchema = Joi.object({
  name: Joi.string().trim().min(1).max(100).optional(),
  description: Joi.string().trim().max(1000).optional().allow(''),
});

const listProjectsSchema = Joi.object({
  // Pagination
  page: Joi.number().integer().min(1).default(1),
  size: Joi.number().integer().min(1).max(100).default(10),
  
  // Filters
  workspaceName: Joi.string().max(50).optional(),
  createdBy: Joi.string().optional(),
  name: Joi.string().max(100).optional(),
  createdAfter: Joi.date().optional(),
  createdBefore: Joi.date().optional(),
  
  // Sorting
  sortField: Joi.string().valid('name', 'createdAt', 'lastUpdatedAt', 'datasetCount', 'experimentCount').optional(),
  sortOrder: Joi.string().valid('asc', 'desc').optional(),
});

const bulkDeleteSchema = Joi.object({
  projectIds: Joi.array().items(Joi.string().uuid()).min(1).max(100).required(),
  force: Joi.boolean().optional().default(false),
});

export default async function projectsController(fastify: FastifyInstance): Promise<void> {
  // Add JSON schema definitions for Swagger documentation
  fastify.addSchema({
    $id: 'CreateProjectRequest',
    type: 'object',
    properties: {
      name: { type: 'string', minLength: 1, maxLength: 100 },
      description: { type: 'string', maxLength: 1000 },
      workspaceId: { type: 'string', maxLength: 50 },
    },
    required: ['name'],
  });

  fastify.addSchema({
    $id: 'ProjectResponse',
    type: 'object',
    properties: {
      id: { type: 'string' },
      name: { type: 'string' },
      description: { type: 'string' },
      workspaceId: { type: 'string' },
      createdAt: { type: 'string', format: 'date-time' },
      createdBy: { type: 'string' },
      lastUpdatedAt: { type: 'string', format: 'date-time' },
      lastUpdatedBy: { type: 'string' },
      datasetCount: { type: 'number' },
      experimentCount: { type: 'number' },
      canEdit: { type: 'boolean' },
      canDelete: { type: 'boolean' },
      canCreateDatasets: { type: 'boolean' },
      canCreateExperiments: { type: 'boolean' },
    },
  });

  /**
   * GET / - List projects with authentication and filtering
   * Compatible with OPIK Java: /v1/private/projects/
   */
  fastify.get('/', {
    preHandler: requireUser,
    schema: {
      description: 'List projects with filtering, sorting, and pagination',
      tags: ['Projects'],
      security: [{ Bearer: [] }],
      querystring: {
        type: 'object',
        properties: {
          page: { type: 'number', minimum: 1, default: 1 },
          size: { type: 'number', minimum: 1, maximum: 100, default: 10 },
          workspaceName: { type: 'string', maxLength: 50 },
          createdBy: { type: 'string' },
          name: { type: 'string', maxLength: 100 },
          createdAfter: { type: 'string', format: 'date-time' },
          createdBefore: { type: 'string', format: 'date-time' },
          sortField: { type: 'string', enum: ['name', 'createdAt', 'lastUpdatedAt', 'datasetCount', 'experimentCount'] },
          sortOrder: { type: 'string', enum: ['asc', 'desc'] },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            projects: {
              type: 'array',
              items: { $ref: 'ProjectResponse' },
            },
            pagination: {
              type: 'object',
              properties: {
                page: { type: 'number' },
                size: { type: 'number' },
                total: { type: 'number' },
                totalPages: { type: 'number' },
                hasNext: { type: 'boolean' },
                hasPrevious: { type: 'boolean' },
              },
            },
          },
        },
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      // Validate query parameters
      const { error: validationError, value: queryParams } = listProjectsSchema.validate(request.query);
      if (validationError) {
        return reply.status(400).send({
          success: false,
          error: 'Invalid query parameters',
          details: validationError.details,
          timestamp: new Date().toISOString(),
        });
      }

      const user = request.user!;
      
      // Build filters
      const filters: ProjectFilters = {};
      if (queryParams.workspaceName) filters.workspaceName = queryParams.workspaceName;
      if (queryParams.createdBy) filters.createdBy = queryParams.createdBy;
      if (queryParams.name) filters.name = queryParams.name;
      if (queryParams.createdAfter) filters.createdAfter = new Date(queryParams.createdAfter);
      if (queryParams.createdBefore) filters.createdBefore = new Date(queryParams.createdBefore);

      // Build sort options
      const sort: ProjectSortOptions | undefined = queryParams.sortField ? {
        field: queryParams.sortField,
        order: queryParams.sortOrder || 'desc',
      } : undefined;

      // Get projects
      const result = await ProjectService.listProjects(
        user,
        filters,
        sort,
        queryParams.page,
        queryParams.size
      );

      apiLogger.info('Projects listed successfully', {
        userId: user.id,
        projectCount: result.projects.length,
        totalCount: result.pagination.total,
        page: queryParams.page,
        size: queryParams.size,
      });

      return reply.status(200).send({
        success: true,
        ...result,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('List projects endpoint error:', error);
      
      return reply.status(500).send({
        success: false,
        error: 'Failed to list projects',
        code: 'SERVER_ERROR',
        timestamp: new Date().toISOString(),
      });
    }
  });

  /**
   * POST / - Create project with authentication and authorization
   * Compatible with OPIK Java: /v1/private/projects/
   */
  fastify.post('/', {
    preHandler: requireUser,
    schema: {
      description: 'Create a new project',
      tags: ['Projects'],
      security: [{ Bearer: [] }],
      body: { $ref: 'CreateProjectRequest' },
      response: {
        201: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            project: { $ref: 'ProjectResponse' },
            timestamp: { type: 'string' },
          },
        },
        400: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            error: { type: 'string' },
            code: { type: 'string' },
            details: { type: 'array' },
          },
        },
        403: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            error: { type: 'string' },
            code: { type: 'string' },
          },
        },
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      // Validate request body
      const { error: validationError, value: projectData } = createProjectSchema.validate(request.body);
      if (validationError) {
        return reply.status(400).send({
          success: false,
          error: 'Invalid project data',
          code: 'VALIDATION_ERROR',
          details: validationError.details,
          timestamp: new Date().toISOString(),
        });
      }

      const user = request.user!;
      const createRequest: CreateProjectRequest = projectData;

      // Create project
      const project = await ProjectService.createProject(createRequest, user);

      apiLogger.info('Project created successfully', {
        projectId: project.id,
        projectName: project.name,
        userId: user.id,
        workspaceId: project.workspaceId,
      });

      return reply.status(201).send({
        success: true,
        project,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('Create project endpoint error:', error);
      
      if (error instanceof ProjectValidationError) {
        return reply.status(400).send({
          success: false,
          error: error.message,
          code: 'VALIDATION_ERROR',
          timestamp: new Date().toISOString(),
        });
      }

      if (error instanceof ProjectPermissionError) {
        return reply.status(403).send({
          success: false,
          error: error.message,
          code: 'PERMISSION_DENIED',
          timestamp: new Date().toISOString(),
        });
      }

      if (error instanceof WorkspaceAccessError) {
        return reply.status(403).send({
          success: false,
          error: error.message,
          code: 'WORKSPACE_ACCESS_DENIED',
          timestamp: new Date().toISOString(),
        });
      }

      return reply.status(500).send({
        success: false,
        error: 'Failed to create project',
        code: 'SERVER_ERROR',
        timestamp: new Date().toISOString(),
      });
    }
  });

  /**
   * GET /:id - Get project by ID with authentication and authorization
   * Compatible with OPIK Java: /v1/private/projects/{id}
   */
  fastify.get('/:id', {
    preHandler: requireUser,
    schema: {
      description: 'Get project by ID',
      tags: ['Projects'],
      security: [{ Bearer: [] }],
      params: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
        },
        required: ['id'],
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            project: { $ref: 'ProjectResponse' },
            timestamp: { type: 'string' },
          },
        },
        404: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            error: { type: 'string' },
            code: { type: 'string' },
          },
        },
        403: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            error: { type: 'string' },
            code: { type: 'string' },
          },
        },
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { id } = request.params as { id: string };
      const user = request.user!;

      const project = await ProjectService.getProject(id, user);

      return reply.status(200).send({
        success: true,
        project,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error(`Get project endpoint error for ${(request.params as any).id}:`, error);
      
      if (error instanceof ProjectNotFoundError) {
        return reply.status(404).send({
          success: false,
          error: error.message,
          code: 'PROJECT_NOT_FOUND',
          timestamp: new Date().toISOString(),
        });
      }

      if (error instanceof ProjectPermissionError) {
        return reply.status(403).send({
          success: false,
          error: error.message,
          code: 'PERMISSION_DENIED',
          timestamp: new Date().toISOString(),
        });
      }

      return reply.status(500).send({
        success: false,
        error: 'Failed to get project',
        code: 'SERVER_ERROR',
        timestamp: new Date().toISOString(),
      });
    }
  });

  /**
   * PATCH /:id - Update project with authentication and authorization
   * Compatible with OPIK Java: /v1/private/projects/{id}
   */
  fastify.patch('/:id', {
    preHandler: requireUser,
    schema: {
      description: 'Update project by ID',
      tags: ['Projects'],
      security: [{ Bearer: [] }],
      params: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
        },
        required: ['id'],
      },
      body: {
        type: 'object',
        properties: {
          name: { type: 'string', minLength: 1, maxLength: 100 },
          description: { type: 'string', maxLength: 1000 },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            project: { $ref: 'ProjectResponse' },
            timestamp: { type: 'string' },
          },
        },
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { id } = request.params as { id: string };
      
      // Validate request body
      const { error: validationError, value: updateData } = updateProjectSchema.validate(request.body);
      if (validationError) {
        return reply.status(400).send({
          success: false,
          error: 'Invalid update data',
          code: 'VALIDATION_ERROR',
          details: validationError.details,
          timestamp: new Date().toISOString(),
        });
      }

      const user = request.user!;
      const updateRequest: UpdateProjectRequest = updateData;

      const project = await ProjectService.updateProject(id, updateRequest, user);

      apiLogger.info('Project updated successfully', {
        projectId: id,
        userId: user.id,
        changes: updateRequest,
      });

      return reply.status(200).send({
        success: true,
        project,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error(`Update project endpoint error for ${(request.params as any).id}:`, error);
      
      if (error instanceof ProjectNotFoundError) {
        return reply.status(404).send({
          success: false,
          error: error.message,
          code: 'PROJECT_NOT_FOUND',
          timestamp: new Date().toISOString(),
        });
      }

      if (error instanceof ProjectPermissionError) {
        return reply.status(403).send({
          success: false,
          error: error.message,
          code: 'PERMISSION_DENIED',
          timestamp: new Date().toISOString(),
        });
      }

      if (error instanceof ProjectValidationError) {
        return reply.status(400).send({
          success: false,
          error: error.message,
          code: 'VALIDATION_ERROR',
          timestamp: new Date().toISOString(),
        });
      }

      return reply.status(500).send({
        success: false,
        error: 'Failed to update project',
        code: 'SERVER_ERROR',
        timestamp: new Date().toISOString(),
      });
    }
  });

  /**
   * DELETE /:id - Delete project with authentication and authorization
   * Compatible with OPIK Java: /v1/private/projects/{id}
   */
  fastify.delete('/:id', {
    preHandler: requireUser,
    schema: {
      description: 'Delete project by ID',
      tags: ['Projects'],
      security: [{ Bearer: [] }],
      params: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
        },
        required: ['id'],
      },
      querystring: {
        type: 'object',
        properties: {
          force: { type: 'boolean', default: false },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
            timestamp: { type: 'string' },
          },
        },
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { id } = request.params as { id: string };
      const { force } = request.query as { force?: boolean };
      const user = request.user!;

      await ProjectService.deleteProject(id, user, force || false);

      apiLogger.info('Project deleted successfully', {
        projectId: id,
        userId: user.id,
        force: force || false,
      });

      return reply.status(200).send({
        success: true,
        message: 'Project deleted successfully',
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error(`Delete project endpoint error for ${(request.params as any).id}:`, error);
      
      if (error instanceof ProjectNotFoundError) {
        return reply.status(404).send({
          success: false,
          error: error.message,
          code: 'PROJECT_NOT_FOUND',
          timestamp: new Date().toISOString(),
        });
      }

      if (error instanceof ProjectPermissionError) {
        return reply.status(403).send({
          success: false,
          error: error.message,
          code: 'PERMISSION_DENIED',
          timestamp: new Date().toISOString(),
        });
      }

      if (error instanceof ProjectValidationError) {
        return reply.status(400).send({
          success: false,
          error: error.message,
          code: 'VALIDATION_ERROR',
          timestamp: new Date().toISOString(),
        });
      }

      return reply.status(500).send({
        success: false,
        error: 'Failed to delete project',
        code: 'SERVER_ERROR',
        timestamp: new Date().toISOString(),
      });
    }
  });

  /**
   * GET /:id/stats-summary - Get project statistics summary
   * Compatible with OPIK Java: /v1/private/projects/{id}/stats-summary
   */
  fastify.get('/:id/stats-summary', {
    preHandler: requireAuth,
    schema: {
      description: 'Get project statistics summary',
      tags: ['Projects'],
      security: [{ Bearer: [] }],
      params: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
        },
        required: ['id'],
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { id } = request.params as { id: string };
      const user = request.user!;

      // Check if project exists and user has access
      const project = await prisma.project.findUnique({
        where: { id },
      });

      if (!project) {
        return reply.status(404).send({
          success: false,
          error: 'Project not found',
          code: 'PROJECT_NOT_FOUND',
          timestamp: new Date().toISOString(),
        });
      }

      // Check permissions (same as getProject)
      if (user.role !== UserRole.ADMIN && project.workspaceId !== user.workspaceId) {
        return reply.status(403).send({
          success: false,
          error: 'Permission denied',
          code: 'PERMISSION_DENIED',
          timestamp: new Date().toISOString(),
        });
      }

      // Get statistics
      const [datasetCount, experimentCount] = await Promise.all([
        prisma.dataset.count({ where: { projectId: id } }),
        prisma.experiment.count({ where: { projectId: id } }),
      ]);

      const statistics = {
        id: project.id,
        name: project.name,
        statistics: {
          datasets: {
            total: datasetCount,
            recentlyCreated: await prisma.dataset.count({
              where: {
                projectId: id,
                createdAt: { gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
              },
            }),
          },
          experiments: {
            total: experimentCount,
            running: 0, // Would need status tracking
            completed: 0,
            failed: 0,
            recentlyCreated: await prisma.experiment.count({
              where: {
                projectId: id,
                createdAt: { gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
              },
            }),
          },
          traces: {
            total: 0, // Would need traces integration
            recentlyCreated: 0,
          },
          feedback: {
            totalScores: 0,
            averageRating: undefined,
          },
        },
        activity: {
          lastDatasetCreated: await prisma.dataset.findFirst({
            where: { projectId: id },
            orderBy: { createdAt: 'desc' },
            select: { createdAt: true },
          }).then(d => d?.createdAt),
          lastExperimentCreated: await prisma.experiment.findFirst({
            where: { projectId: id },
            orderBy: { createdAt: 'desc' },
            select: { createdAt: true },
          }).then(e => e?.createdAt),
          lastTraceCreated: undefined,
          lastActivity: new Date(Math.max(
            project.lastUpdatedAt.getTime(),
            project.createdAt.getTime()
          )),
        },
      };

      return reply.status(200).send({
        success: true,
        statistics,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error(`Get project statistics error for ${(request.params as any).id}:`, error);
      
      return reply.status(500).send({
        success: false,
        error: 'Failed to get project statistics',
        code: 'SERVER_ERROR',
        timestamp: new Date().toISOString(),
      });
    }
  });

  /**
   * GET /:id/feedback-scores/names - Get feedback score names for project
   * Compatible with OPIK Java: /v1/private/projects/{id}/feedback-scores/names
   */
  fastify.get('/:id/feedback-scores/names', {
    preHandler: requireAuth,
    schema: {
      description: 'Get feedback score names for project',
      tags: ['Projects'],
      security: [{ Bearer: [] }],
      params: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
        },
        required: ['id'],
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { id } = request.params as { id: string };
      const user = request.user!;

      // Check if project exists and user has access
      const project = await prisma.project.findUnique({
        where: { id },
      });

      if (!project) {
        return reply.status(404).send({
          success: false,
          error: 'Project not found',
          code: 'PROJECT_NOT_FOUND',
          timestamp: new Date().toISOString(),
        });
      }

      // Check permissions
      if (user.role !== UserRole.ADMIN && project.workspaceId !== user.workspaceId) {
        return reply.status(403).send({
          success: false,
          error: 'Permission denied',
          code: 'PERMISSION_DENIED',
          timestamp: new Date().toISOString(),
        });
      }

      // For now, return empty array - would integrate with feedback system later
      const feedbackScoreNames: string[] = [];

      return reply.status(200).send({
        success: true,
        scoreNames: feedbackScoreNames,
        projectId: id,
        workspaceId: project.workspaceId,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error(`Get feedback score names error for ${(request.params as any).id}:`, error);
      
      return reply.status(500).send({
        success: false,
        error: 'Failed to get feedback score names',
        code: 'SERVER_ERROR',
        timestamp: new Date().toISOString(),
      });
    }
  });

  logger.info('✅ Projects controller registered with full authentication integration');
}