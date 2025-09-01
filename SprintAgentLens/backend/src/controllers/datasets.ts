/**
 * Dataset Controller - Enterprise dataset management endpoints
 * All endpoints include authentication middleware and workspace isolation
 */

import { FastifyPluginAsync } from 'fastify';
import Joi from 'joi';
import { requireAuth, requireUser, requireAdmin } from '@/middleware/auth';
import { DatasetService } from '@/services/DatasetService';
import { logger } from '@/utils/logger';
import type { AuthenticatedRequest } from '@/types/auth';
import type {
  CreateDatasetRequest,
  UpdateDatasetRequest,
  DatasetListRequest,
  DatasetMetricsRequest,
  BulkDatasetOperationRequest,
} from '@/types/datasets';

const datasetsController: FastifyPluginAsync = async (fastify) => {
  // Validation schemas
  const createDatasetSchema = Joi.object({
    name: Joi.string().min(1).max(255).pattern(/^[a-zA-Z0-9\s\-_\.]+$/).required(),
    description: Joi.string().max(2000).optional(),
    projectId: Joi.string().uuid().required(),
    workspaceId: Joi.string().uuid().required(),
    metadata: Joi.object({
      version: Joi.string().optional(),
      source: Joi.string().optional(),
      format: Joi.string().valid('json', 'csv', 'parquet', 'txt', 'custom').optional(),
      schema: Joi.object().optional(),
      quality: Joi.object({
        completeness: Joi.number().min(0).max(100).optional(),
        consistency: Joi.number().min(0).max(100).optional(),
        validity: Joi.number().min(0).max(100).optional(),
        lastChecked: Joi.date().optional(),
      }).optional(),
      lineage: Joi.object({
        sourceDatasets: Joi.array().items(Joi.string()).optional(),
        derivedFrom: Joi.string().optional(),
        transformations: Joi.array().items(Joi.string()).optional(),
      }).optional(),
      annotations: Joi.object({
        author: Joi.string().optional(),
        reviewedBy: Joi.string().optional(),
        approvedBy: Joi.string().optional(),
        reviewDate: Joi.date().optional(),
        approvalDate: Joi.date().optional(),
      }).optional(),
    }).optional(),
    tags: Joi.array().items(Joi.string().max(50)).max(20).optional(),
  });

  const updateDatasetSchema = Joi.object({
    name: Joi.string().min(1).max(255).pattern(/^[a-zA-Z0-9\s\-_\.]+$/).optional(),
    description: Joi.string().max(2000).allow(null).optional(),
    metadata: Joi.object().optional(),
    tags: Joi.array().items(Joi.string().max(50)).max(20).optional(),
  });

  const listDatasetsSchema = Joi.object({
    projectId: Joi.string().uuid().optional(),
    workspaceId: Joi.string().uuid().optional(),
    status: Joi.array().items(Joi.string().valid(
      'draft', 'ready', 'processing', 'error', 'archived', 'deprecated'
    )).optional(),
    tags: Joi.array().items(Joi.string()).optional(),
    search: Joi.string().max(255).optional(),
    sortBy: Joi.string().valid('name', 'created_at', 'updated_at', 'item_count', 'size').optional(),
    sortOrder: Joi.string().valid('asc', 'desc').optional(),
    page: Joi.number().integer().min(1).optional(),
    limit: Joi.number().integer().min(1).max(100).optional(),
  });

  const bulkOperationSchema = Joi.object({
    datasetIds: Joi.array().items(Joi.string().uuid()).min(1).max(100).required(),
    operation: Joi.string().valid('delete', 'archive', 'restore', 'export', 'duplicate').required(),
    options: Joi.object({
      exportFormat: Joi.string().valid('json', 'csv', 'parquet').optional(),
      targetProjectId: Joi.string().uuid().optional(),
      includeMetadata: Joi.boolean().optional(),
    }).optional(),
  });

  // GET /v1/private/datasets - List datasets with workspace isolation
  fastify.get<{
    Querystring: DatasetListRequest;
    Reply: any;
  }>('/', {
    preHandler: requireUser,
    schema: {
      querystring: listDatasetsSchema,
      response: {
        200: {
          type: 'object',
          properties: {
            datasets: { type: 'array' },
            pagination: { type: 'object' },
            filters: { type: 'object' },
            sorting: { type: 'object' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const user = (request as AuthenticatedRequest).user!;
      
      logger.debug('Listing datasets', { 
        userId: user.id, 
        workspaceId: user.workspaceId,
        filters: request.query 
      });

      const result = await DatasetService.listDatasets(request.query, user);

      logger.debug('Datasets listed successfully', { 
        userId: user.id,
        count: result.datasets.length,
        total: result.pagination.total
      });

      return result;
    } catch (error) {
      logger.error('Failed to list datasets', { 
        userId: (request as AuthenticatedRequest).user?.id, 
        error 
      });
      
      if (error instanceof Error) {
        return reply.status(400).send({
          error: 'BadRequest',
          message: error.message,
        });
      }
      
      return reply.status(500).send({
        error: 'InternalServerError',
        message: 'Failed to list datasets',
      });
    }
  });

  // POST /v1/private/datasets - Create new dataset with authentication
  fastify.post<{
    Body: CreateDatasetRequest;
    Reply: any;
  }>('/', {
    preHandler: requireUser,
    schema: {
      body: createDatasetSchema,
      response: {
        201: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            name: { type: 'string' },
            projectId: { type: 'string' },
            workspaceId: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const user = (request as AuthenticatedRequest).user!;
      
      logger.info('Creating dataset', { 
        name: request.body.name,
        projectId: request.body.projectId,
        userId: user.id 
      });

      // Ensure workspace consistency
      if (request.body.workspaceId !== user.workspaceId) {
        return reply.status(403).send({
          error: 'Forbidden',
          message: 'Workspace mismatch',
        });
      }

      const dataset = await DatasetService.createDataset(request.body, user);

      logger.info('Dataset created successfully', { 
        datasetId: dataset.id,
        name: dataset.name,
        userId: user.id 
      });

      return reply.status(201).send(dataset);
    } catch (error) {
      logger.error('Failed to create dataset', { 
        name: request.body.name,
        userId: (request as AuthenticatedRequest).user?.id, 
        error 
      });

      if (error instanceof Error) {
        const statusCode = error.name === 'DatasetPermissionError' ? 403 :
                          error.name === 'DatasetValidationError' ? 400 :
                          error.name === 'DatasetLimitError' ? 409 : 500;
        
        return reply.status(statusCode).send({
          error: error.name,
          message: error.message,
        });
      }
      
      return reply.status(500).send({
        error: 'InternalServerError',
        message: 'Failed to create dataset',
      });
    }
  });

  // GET /v1/private/datasets/:id - Get dataset by ID with permissions
  fastify.get<{
    Params: { id: string };
    Reply: any;
  }>('/:id', {
    preHandler: requireUser,
    schema: {
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
            id: { type: 'string' },
            name: { type: 'string' },
            description: { type: 'string' },
            projectId: { type: 'string' },
            workspaceId: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const user = (request as AuthenticatedRequest).user!;
      const { id } = request.params;
      
      logger.debug('Getting dataset by ID', { 
        datasetId: id, 
        userId: user.id 
      });

      const dataset = await DatasetService.getDatasetById(id, user);

      logger.debug('Dataset retrieved successfully', { 
        datasetId: id,
        userId: user.id 
      });

      return dataset;
    } catch (error) {
      logger.error('Failed to get dataset', { 
        datasetId: request.params.id,
        userId: (request as AuthenticatedRequest).user?.id, 
        error 
      });

      if (error instanceof Error) {
        const statusCode = error.name === 'DatasetNotFoundError' ? 404 :
                          error.name === 'DatasetPermissionError' ? 403 : 500;
        
        return reply.status(statusCode).send({
          error: error.name,
          message: error.message,
        });
      }
      
      return reply.status(500).send({
        error: 'InternalServerError',
        message: 'Failed to retrieve dataset',
      });
    }
  });

  // PATCH /v1/private/datasets/:id - Update dataset with permissions
  fastify.patch<{
    Params: { id: string };
    Body: UpdateDatasetRequest;
    Reply: any;
  }>('/:id', {
    preHandler: requireUser,
    schema: {
      params: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
        },
        required: ['id'],
      },
      body: updateDatasetSchema,
      response: {
        200: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            name: { type: 'string' },
            lastUpdatedAt: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const user = (request as AuthenticatedRequest).user!;
      const { id } = request.params;
      
      logger.info('Updating dataset', { 
        datasetId: id,
        userId: user.id,
        updates: Object.keys(request.body)
      });

      const dataset = await DatasetService.updateDataset(id, request.body, user);

      logger.info('Dataset updated successfully', { 
        datasetId: id,
        userId: user.id 
      });

      return dataset;
    } catch (error) {
      logger.error('Failed to update dataset', { 
        datasetId: request.params.id,
        userId: (request as AuthenticatedRequest).user?.id, 
        error 
      });

      if (error instanceof Error) {
        const statusCode = error.name === 'DatasetNotFoundError' ? 404 :
                          error.name === 'DatasetPermissionError' ? 403 :
                          error.name === 'DatasetValidationError' ? 400 : 500;
        
        return reply.status(statusCode).send({
          error: error.name,
          message: error.message,
        });
      }
      
      return reply.status(500).send({
        error: 'InternalServerError',
        message: 'Failed to update dataset',
      });
    }
  });

  // DELETE /v1/private/datasets/:id - Delete dataset with permissions
  fastify.delete<{
    Params: { id: string };
    Reply: any;
  }>('/:id', {
    preHandler: requireUser,
    schema: {
      params: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
        },
        required: ['id'],
      },
      response: {
        204: { type: 'null' },
      },
    },
  }, async (request, reply) => {
    try {
      const user = (request as AuthenticatedRequest).user!;
      const { id } = request.params;
      
      logger.info('Deleting dataset', { 
        datasetId: id,
        userId: user.id 
      });

      await DatasetService.deleteDataset(id, user);

      logger.info('Dataset deleted successfully', { 
        datasetId: id,
        userId: user.id 
      });

      return reply.status(204).send();
    } catch (error) {
      logger.error('Failed to delete dataset', { 
        datasetId: request.params.id,
        userId: (request as AuthenticatedRequest).user?.id, 
        error 
      });

      if (error instanceof Error) {
        const statusCode = error.name === 'DatasetNotFoundError' ? 404 :
                          error.name === 'DatasetPermissionError' ? 403 :
                          error.name === 'DatasetStatusError' ? 409 : 500;
        
        return reply.status(statusCode).send({
          error: error.name,
          message: error.message,
        });
      }
      
      return reply.status(500).send({
        error: 'InternalServerError',
        message: 'Failed to delete dataset',
      });
    }
  });

  // GET /v1/private/datasets/:id/statistics - Get dataset statistics
  fastify.get<{
    Params: { id: string };
    Reply: any;
  }>('/:id/statistics', {
    preHandler: requireUser,
    schema: {
      params: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
        },
        required: ['id'],
      },
    },
  }, async (request, reply) => {
    try {
      const user = (request as AuthenticatedRequest).user!;
      const { id } = request.params;
      
      logger.debug('Getting dataset statistics', { 
        datasetId: id, 
        userId: user.id 
      });

      const statistics = await DatasetService.getDatasetStatistics(id, user);
      return statistics;
    } catch (error) {
      logger.error('Failed to get dataset statistics', { 
        datasetId: request.params.id,
        userId: (request as AuthenticatedRequest).user?.id, 
        error 
      });

      if (error instanceof Error && error.message === 'Not implemented yet') {
        return reply.status(501).send({
          error: 'NotImplemented',
          message: 'Dataset statistics not implemented yet',
        });
      }

      return reply.status(500).send({
        error: 'InternalServerError',
        message: 'Failed to get dataset statistics',
      });
    }
  });

  // POST /v1/private/datasets/:id/metrics - Get dataset metrics
  fastify.post<{
    Params: { id: string };
    Body: Omit<DatasetMetricsRequest, 'datasetId'>;
    Reply: any;
  }>('/:id/metrics', {
    preHandler: requireUser,
    schema: {
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
          metrics: { type: 'array', items: { type: 'string' } },
          startDate: { type: 'string', format: 'date-time' },
          endDate: { type: 'string', format: 'date-time' },
          granularity: { type: 'string', enum: ['hour', 'day', 'week', 'month'] },
        },
        required: ['metrics'],
      },
    },
  }, async (request, reply) => {
    try {
      const user = (request as AuthenticatedRequest).user!;
      const { id } = request.params;
      
      logger.debug('Getting dataset metrics', { 
        datasetId: id, 
        userId: user.id,
        metrics: request.body.metrics
      });

      const metricsRequest: DatasetMetricsRequest = {
        ...request.body,
        datasetId: id,
      };

      const metrics = await DatasetService.getDatasetMetrics(metricsRequest, user);
      return metrics;
    } catch (error) {
      logger.error('Failed to get dataset metrics', { 
        datasetId: request.params.id,
        userId: (request as AuthenticatedRequest).user?.id, 
        error 
      });

      if (error instanceof Error && error.message === 'Not implemented yet') {
        return reply.status(501).send({
          error: 'NotImplemented',
          message: 'Dataset metrics not implemented yet',
        });
      }

      return reply.status(500).send({
        error: 'InternalServerError',
        message: 'Failed to get dataset metrics',
      });
    }
  });

  // POST /v1/private/datasets/bulk - Bulk dataset operations (admin only)
  fastify.post<{
    Body: BulkDatasetOperationRequest;
    Reply: any;
  }>('/bulk', {
    preHandler: requireAdmin,
    schema: {
      body: bulkOperationSchema,
      response: {
        202: {
          type: 'object',
          properties: {
            requestId: { type: 'string' },
            operation: { type: 'string' },
            status: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const user = (request as AuthenticatedRequest).user!;
      
      logger.info('Executing bulk dataset operation', { 
        operation: request.body.operation,
        datasetCount: request.body.datasetIds.length,
        userId: user.id 
      });

      const result = await DatasetService.bulkDatasetOperation(request.body, user);

      logger.info('Bulk dataset operation started', { 
        requestId: result.requestId,
        operation: request.body.operation,
        userId: user.id 
      });

      return reply.status(202).send(result);
    } catch (error) {
      logger.error('Failed to execute bulk dataset operation', { 
        operation: request.body.operation,
        userId: (request as AuthenticatedRequest).user?.id, 
        error 
      });

      if (error instanceof Error && error.message === 'Not implemented yet') {
        return reply.status(501).send({
          error: 'NotImplemented',
          message: 'Bulk dataset operations not implemented yet',
        });
      }

      return reply.status(500).send({
        error: 'InternalServerError',
        message: 'Failed to execute bulk operation',
      });
    }
  });

  logger.debug('✅ Dataset routes registered with enterprise authentication');
};

export default datasetsController;