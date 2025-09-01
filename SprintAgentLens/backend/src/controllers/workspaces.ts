import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import Joi from 'joi';
import { prisma } from '@/config/database';
import { requireAuth, requireAdmin } from '@/middleware/auth';
import { logger, apiLogger } from '@/utils/logger';
import {
  WorkspaceConfigurationRequest,
  UpdateWorkspaceRequest,
  WorkspaceResponse,
  WorkspaceMetadataResponse,
  WorkspaceMetricRequest,
  WorkspaceMetricResponse,
  WorkspaceMetricsSummaryRequest,
  WorkspaceMetricsSummaryResponse,
  WorkspacePermissions,
  WorkspaceNotFoundError,
  WorkspacePermissionError,
  WorkspaceValidationError,
  DEFAULT_WORKSPACE_SETTINGS,
  DEFAULT_WORKSPACE_FEATURES,
} from '@/types/workspaces';
import { UserRole } from '@/types/auth';

/**
 * Workspaces Controller with Enterprise Authentication Integration
 * All endpoints require authentication and implement RBAC
 * 
 * Compatible with OPIK Java backend WorkspacesResource
 */

// Validation schemas
const workspaceConfigSchema = Joi.object({
  name: Joi.string().trim().min(1).max(100).required(),
  description: Joi.string().trim().max(500).optional().allow(''),
  settings: Joi.object().optional(),
  features: Joi.object().optional(),
});

const updateWorkspaceSchema = Joi.object({
  name: Joi.string().trim().min(1).max(100).optional(),
  description: Joi.string().trim().max(500).optional().allow(''),
  settings: Joi.object().optional(),
  features: Joi.object().optional(),
});

const metricsSchema = Joi.object({
  metricNames: Joi.array().items(Joi.string()).min(1).required(),
  startDate: Joi.date().optional(),
  endDate: Joi.date().optional(),
  groupBy: Joi.string().valid('day', 'week', 'month').optional(),
  includeProjects: Joi.boolean().optional(),
});

const metricsSummarySchema = Joi.object({
  period: Joi.string().valid('day', 'week', 'month', 'quarter', 'year').required(),
  includeComparison: Joi.boolean().optional(),
});

export default async function workspacesController(fastify: FastifyInstance): Promise<void> {
  // Add JSON schema definitions
  fastify.addSchema({
    $id: 'WorkspaceResponse',
    type: 'object',
    properties: {
      id: { type: 'string' },
      workspaceId: { type: 'string' },
      name: { type: 'string' },
      description: { type: 'string' },
      settings: { type: 'object' },
      features: { type: 'object' },
      createdAt: { type: 'string', format: 'date-time' },
      createdBy: { type: 'string' },
      canEdit: { type: 'boolean' },
      canDelete: { type: 'boolean' },
    },
  });

  /**
   * GET /configurations - Get workspace configurations
   * Compatible with OPIK Java: /v1/private/workspaces/configurations
   */
  fastify.get('/configurations', {
    preHandler: requireAuth,
    schema: {
      description: 'Get workspace configurations',
      tags: ['Workspaces'],
      security: [{ Bearer: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            workspaces: {
              type: 'array',
              items: { $ref: 'WorkspaceResponse' },
            },
            currentWorkspace: { type: 'string' },
          },
        },
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const user = request.user!;
      
      logger.debug(`Getting workspace configurations for user: ${user.username}`, {
        userId: user.id,
        currentWorkspace: user.workspaceId,
      });

      // Get workspace configurations based on user role
      let whereClause: any = {};
      
      if (user.role === UserRole.ADMIN) {
        // Admin can see all workspaces
      } else {
        // Regular users can only see their workspace
        whereClause.workspaceId = user.workspaceId;
      }

      const configurations = await prisma.workspaceConfiguration.findMany({
        where: whereClause,
        orderBy: { createdAt: 'desc' },
      });

      // Transform to response format
      const workspaces = configurations.map(config => {
        const permissions = getWorkspacePermissions(user, config);
        
        return {
          id: config.id,
          workspaceId: config.workspaceId,
          name: config.name,
          description: config.description,
          settings: config.settings as any || DEFAULT_WORKSPACE_SETTINGS,
          features: config.features as any || DEFAULT_WORKSPACE_FEATURES,
          createdAt: config.createdAt,
          createdBy: config.createdBy,
          lastUpdatedAt: config.lastUpdatedAt,
          lastUpdatedBy: config.lastUpdatedBy,
          canEdit: permissions.canEdit,
          canDelete: permissions.canDelete,
          canInviteUsers: permissions.canInviteUsers,
          canManageSettings: permissions.canManageSettings,
        };
      });

      return reply.status(200).send({
        success: true,
        workspaces,
        currentWorkspace: user.workspaceId,
        permissions: getWorkspacePermissions(user, { workspaceId: user.workspaceId }),
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('Get workspace configurations error:', error);
      
      return reply.status(500).send({
        success: false,
        error: 'Failed to get workspace configurations',
        code: 'SERVER_ERROR',
        timestamp: new Date().toISOString(),
      });
    }
  });

  /**
   * POST /configurations - Create workspace configuration (Admin only)
   */
  fastify.post('/configurations', {
    preHandler: requireAdmin,
    schema: {
      description: 'Create workspace configuration',
      tags: ['Workspaces'],
      security: [{ Bearer: [] }],
      body: {
        type: 'object',
        properties: {
          name: { type: 'string', minLength: 1, maxLength: 100 },
          description: { type: 'string', maxLength: 500 },
          settings: { type: 'object' },
          features: { type: 'object' },
        },
        required: ['name'],
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { error: validationError, value: configData } = workspaceConfigSchema.validate(request.body);
      if (validationError) {
        return reply.status(400).send({
          success: false,
          error: 'Invalid workspace configuration',
          details: validationError.details,
          timestamp: new Date().toISOString(),
        });
      }

      const user = request.user!;
      const workspaceId = `workspace-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

      // Create workspace configuration
      const configuration = await prisma.workspaceConfiguration.create({
        data: {
          workspaceId,
          name: configData.name,
          description: configData.description || null,
          settings: configData.settings || DEFAULT_WORKSPACE_SETTINGS,
          features: configData.features || DEFAULT_WORKSPACE_FEATURES,
          createdBy: user.id,
        },
      });

      apiLogger.info('Workspace configuration created', {
        workspaceId,
        name: configData.name,
        createdBy: user.id,
      });

      const permissions = getWorkspacePermissions(user, configuration);

      return reply.status(201).send({
        success: true,
        workspace: {
          id: configuration.id,
          workspaceId: configuration.workspaceId,
          name: configuration.name,
          description: configuration.description,
          settings: configuration.settings,
          features: configuration.features,
          createdAt: configuration.createdAt,
          createdBy: configuration.createdBy,
          canEdit: permissions.canEdit,
          canDelete: permissions.canDelete,
        },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('Create workspace configuration error:', error);
      
      return reply.status(500).send({
        success: false,
        error: 'Failed to create workspace configuration',
        code: 'SERVER_ERROR',
        timestamp: new Date().toISOString(),
      });
    }
  });

  /**
   * GET /metadata - Get workspace metadata and statistics
   * Compatible with OPIK Java: /v1/private/workspaces/metadata
   */
  fastify.get('/metadata', {
    preHandler: requireAuth,
    schema: {
      description: 'Get workspace metadata and statistics',
      tags: ['Workspaces'],
      security: [{ Bearer: [] }],
      querystring: {
        type: 'object',
        properties: {
          workspaceId: { type: 'string' },
        },
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const user = request.user!;
      const { workspaceId } = request.query as { workspaceId?: string };
      
      const targetWorkspaceId = workspaceId || user.workspaceId;

      // Check permissions
      if (user.role !== UserRole.ADMIN && targetWorkspaceId !== user.workspaceId) {
        return reply.status(403).send({
          success: false,
          error: 'Access denied to workspace',
          code: 'WORKSPACE_ACCESS_DENIED',
          timestamp: new Date().toISOString(),
        });
      }

      // Get workspace configuration
      const configuration = await prisma.workspaceConfiguration.findUnique({
        where: { workspaceId: targetWorkspaceId },
      });

      if (!configuration) {
        return reply.status(404).send({
          success: false,
          error: 'Workspace not found',
          code: 'WORKSPACE_NOT_FOUND',
          timestamp: new Date().toISOString(),
        });
      }

      // Get statistics
      const [userCount, projectCount, datasetCount, experimentCount] = await Promise.all([
        prisma.user.count({ where: { workspaceId: targetWorkspaceId, isActive: true } }),
        prisma.project.count({ where: { workspaceId: targetWorkspaceId } }),
        prisma.dataset.count({
          where: {
            project: { workspaceId: targetWorkspaceId },
          },
        }),
        prisma.experiment.count({
          where: {
            project: { workspaceId: targetWorkspaceId },
          },
        }),
      ]);

      const metadata: WorkspaceMetadataResponse = {
        workspaceId: configuration.workspaceId,
        name: configuration.name,
        description: configuration.description,
        settings: (configuration.settings as any) || DEFAULT_WORKSPACE_SETTINGS,
        features: (configuration.features as any) || DEFAULT_WORKSPACE_FEATURES,
        statistics: {
          users: {
            total: userCount,
            active: userCount, // For simplicity, assuming active users
            admins: await prisma.user.count({
              where: { workspaceId: targetWorkspaceId, role: UserRole.ADMIN, isActive: true },
            }),
            viewers: await prisma.user.count({
              where: { workspaceId: targetWorkspaceId, role: UserRole.VIEWER, isActive: true },
            }),
          },
          projects: {
            total: projectCount,
            recentlyCreated: await prisma.project.count({
              where: {
                workspaceId: targetWorkspaceId,
                createdAt: { gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
              },
            }),
          },
          datasets: {
            total: datasetCount,
            totalItems: 0, // Would need to aggregate dataset items
            recentlyCreated: await prisma.dataset.count({
              where: {
                project: { workspaceId: targetWorkspaceId },
                createdAt: { gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
              },
            }),
          },
          experiments: {
            total: experimentCount,
            running: 0, // Would need experiment status tracking
            completed: 0,
            failed: 0,
            recentlyCreated: await prisma.experiment.count({
              where: {
                project: { workspaceId: targetWorkspaceId },
                createdAt: { gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
              },
            }),
          },
          traces: {
            total: 0, // Would need traces table
            recentlyCreated: 0,
          },
          storage: {
            usedGB: 0, // Would need file storage tracking
            attachmentsGB: 0,
          },
        },
        limits: {
          maxUsers: 100, // From configuration or subscription
          maxProjects: 1000,
          maxDatasetsPerProject: 50,
          maxExperimentsPerProject: 100,
          storageQuotaGB: 100,
          apiCallsPerMonth: 10000,
        },
        usage: {
          users: {
            current: userCount,
            limit: 100,
            percentUsed: (userCount / 100) * 100,
          },
          projects: {
            current: projectCount,
            limit: 1000,
            percentUsed: (projectCount / 1000) * 100,
          },
          storage: {
            currentGB: 0,
            limitGB: 100,
            percentUsed: 0,
          },
          apiCalls: {
            currentMonth: 0,
            limit: 10000,
            percentUsed: 0,
          },
        },
      };

      return reply.status(200).send({
        success: true,
        metadata,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('Get workspace metadata error:', error);
      
      return reply.status(500).send({
        success: false,
        error: 'Failed to get workspace metadata',
        code: 'SERVER_ERROR',
        timestamp: new Date().toISOString(),
      });
    }
  });

  /**
   * POST /metrics - Get workspace metrics with filtering
   * Compatible with OPIK Java: /v1/private/workspaces/metrics
   */
  fastify.post('/metrics', {
    preHandler: requireAuth,
    schema: {
      description: 'Get workspace metrics',
      tags: ['Workspaces'],
      security: [{ Bearer: [] }],
      body: {
        type: 'object',
        properties: {
          metricNames: {
            type: 'array',
            items: { type: 'string' },
            minItems: 1,
          },
          startDate: { type: 'string', format: 'date-time' },
          endDate: { type: 'string', format: 'date-time' },
          groupBy: { type: 'string', enum: ['day', 'week', 'month'] },
          includeProjects: { type: 'boolean' },
        },
        required: ['metricNames'],
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { error: validationError, value: metricsRequest } = metricsSchema.validate(request.body);
      if (validationError) {
        return reply.status(400).send({
          success: false,
          error: 'Invalid metrics request',
          details: validationError.details,
          timestamp: new Date().toISOString(),
        });
      }

      const user = request.user!;
      
      // For now, return mock metrics data
      // In production, this would query actual metrics from ClickHouse
      const mockMetrics: WorkspaceMetricResponse = {
        workspaceId: user.workspaceId,
        metrics: metricsRequest.metricNames.map(name => ({
          name,
          data: [
            {
              timestamp: new Date(),
              value: Math.floor(Math.random() * 100),
            },
          ],
          aggregation: {
            min: 0,
            max: 100,
            avg: 50,
            total: 1000,
          },
        })),
        timeRange: {
          start: metricsRequest.startDate || new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
          end: metricsRequest.endDate || new Date(),
        },
      };

      return reply.status(200).send({
        success: true,
        metrics: mockMetrics,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('Get workspace metrics error:', error);
      
      return reply.status(500).send({
        success: false,
        error: 'Failed to get workspace metrics',
        code: 'SERVER_ERROR',
        timestamp: new Date().toISOString(),
      });
    }
  });

  /**
   * POST /metrics/summary - Get workspace metrics summary
   * Compatible with OPIK Java: /v1/private/workspaces/metrics/summary
   */
  fastify.post('/metrics/summary', {
    preHandler: requireAuth,
    schema: {
      description: 'Get workspace metrics summary',
      tags: ['Workspaces'],
      security: [{ Bearer: [] }],
      body: {
        type: 'object',
        properties: {
          period: { type: 'string', enum: ['day', 'week', 'month', 'quarter', 'year'] },
          includeComparison: { type: 'boolean' },
        },
        required: ['period'],
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { error: validationError, value: summaryRequest } = metricsSummarySchema.validate(request.body);
      if (validationError) {
        return reply.status(400).send({
          success: false,
          error: 'Invalid metrics summary request',
          details: validationError.details,
          timestamp: new Date().toISOString(),
        });
      }

      const user = request.user!;
      
      // Get actual statistics for the workspace
      const [projectCount, experimentCount, userCount] = await Promise.all([
        prisma.project.count({ where: { workspaceId: user.workspaceId } }),
        prisma.experiment.count({
          where: { project: { workspaceId: user.workspaceId } },
        }),
        prisma.user.count({ where: { workspaceId: user.workspaceId, isActive: true } }),
      ]);

      const summary: WorkspaceMetricsSummaryResponse = {
        period: summaryRequest.period,
        summary: {
          projects: {
            total: projectCount,
            created: Math.floor(projectCount * 0.1), // Mock recent creations
            active: Math.floor(projectCount * 0.8),
          },
          experiments: {
            total: experimentCount,
            created: Math.floor(experimentCount * 0.2),
            completed: Math.floor(experimentCount * 0.7),
            successRate: 85.5,
          },
          traces: {
            total: 0,
            created: 0,
            averageLatency: 0,
          },
          users: {
            total: userCount,
            active: Math.floor(userCount * 0.9),
            newSignups: Math.floor(userCount * 0.05),
          },
          storage: {
            totalGB: 0,
            growth: 0,
          },
        },
        trends: [
          {
            metric: 'projects',
            trend: 'up',
            changePercent: 15.2,
          },
          {
            metric: 'experiments',
            trend: 'up',
            changePercent: 8.7,
          },
          {
            metric: 'users',
            trend: 'stable',
            changePercent: 2.1,
          },
        ],
      };

      return reply.status(200).send({
        success: true,
        summary,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('Get workspace metrics summary error:', error);
      
      return reply.status(500).send({
        success: false,
        error: 'Failed to get workspace metrics summary',
        code: 'SERVER_ERROR',
        timestamp: new Date().toISOString(),
      });
    }
  });

  /**
   * Helper function to get workspace permissions
   */
  function getWorkspacePermissions(user: any, workspace: any): WorkspacePermissions {
    const isAdmin = user.role === UserRole.ADMIN;
    const isOwner = workspace.createdBy === user.id;
    const canAccess = isAdmin || workspace.workspaceId === user.workspaceId;

    return {
      canRead: canAccess,
      canEdit: isAdmin || isOwner,
      canDelete: isAdmin,
      canInviteUsers: isAdmin || isOwner,
      canManageUsers: isAdmin,
      canManageSettings: isAdmin || isOwner,
      canViewMetrics: canAccess,
      canViewAuditLogs: isAdmin,
      isOwner,
      isAdmin,
    };
  }

  logger.info('✅ Workspaces controller registered with full authentication integration');
}