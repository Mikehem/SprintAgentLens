import { FastifyInstance } from 'fastify';
import { logger } from '@/utils/logger';

/**
 * Register all API routes
 */
export async function registerRoutes(server: FastifyInstance): Promise<void> {
  try {
    logger.info('🛣️  Registering API routes...');

    // API root endpoint
    server.get('/', async () => ({
      service: 'SprintAgentLens Backend',
      version: '1.0.0',
      status: 'running',
      timestamp: new Date().toISOString(),
      docs: '/docs',
      health: '/health',
    }));

    // API versioning prefix
    await server.register(async function v1Routes(server) {
      // Authentication routes (highest priority - implemented first)
      await server.register(import('@/controllers/auth'), {
        prefix: '/v1/enterprise/auth',
      });

      // Projects routes - PHASE 2 IMPLEMENTED ✅
      await server.register(import('@/controllers/projects'), {
        prefix: '/v1/private/projects',
      });

      // Workspaces routes - PHASE 2 IMPLEMENTED ✅
      await server.register(import('@/controllers/workspaces'), {
        prefix: '/v1/private/workspaces',
      });

      // Future routes will be added here as features are implemented

      // Experiments routes
      // await server.register(import('@/controllers/experiments'), {
      //   prefix: '/v1/private/experiments',
      // });

      // Datasets routes
      // await server.register(import('@/controllers/datasets'), {
      //   prefix: '/v1/private/datasets',
      // });

      // Traces routes
      // await server.register(import('@/controllers/traces'), {
      //   prefix: '/v1/private/traces',
      // });

      // LLM Chat routes
      // await server.register(import('@/controllers/chat'), {
      //   prefix: '/v1/private/chat',
      // });

      logger.debug('✅ V1 API routes registered');
    });

    logger.info('✅ All routes registered successfully');
  } catch (error) {
    logger.error('❌ Failed to register routes:', error);
    throw error;
  }
}