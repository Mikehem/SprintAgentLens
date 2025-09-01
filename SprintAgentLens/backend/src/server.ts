import fastify from 'fastify';
import { config } from '@/config/environment';
import { logger } from '@/utils/logger';
import { registerPlugins } from '@/plugins';
import { registerRoutes } from '@/routes';
import { connectDatabases } from '@/config/database';
import { gracefulShutdown } from '@/utils/gracefulShutdown';

/**
 * SprintAgentLens Backend Server
 * Enterprise AI observability and evaluation platform
 */

const server = fastify({
  logger: logger,
  trustProxy: true,
  bodyLimit: 10 * 1024 * 1024, // 10MB limit for file uploads
});

/**
 * Application startup sequence
 */
async function start(): Promise<void> {
  try {
    logger.info('🚀 Starting SprintAgentLens Backend Server...');

    // Connect to databases
    logger.info('🔌 Connecting to databases...');
    await connectDatabases();

    // Register plugins (CORS, JWT, Swagger, etc.)
    logger.info('🔧 Registering plugins...');
    await registerPlugins(server);

    // Register API routes
    logger.info('🛣️  Registering routes...');
    await registerRoutes(server);

    // Health check endpoint
    server.get('/health', async () => {
      return {
        status: 'ok',
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version || '1.0.0',
        environment: config.NODE_ENV,
        uptime: process.uptime(),
      };
    });

    // Start server
    const address = await server.listen({
      port: config.PORT,
      host: config.HOST,
    });

    logger.info(`✅ SprintAgentLens Backend Server started successfully`);
    logger.info(`📍 Server listening at: ${address}`);
    logger.info(`📚 API Documentation: ${address}/docs`);
    logger.info(`🩺 Health Check: ${address}/health`);

    // Setup graceful shutdown
    gracefulShutdown(server, logger);
  } catch (error) {
    logger.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Promise Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

// Start the application
if (require.main === module) {
  start();
}

export { server };
export default server;