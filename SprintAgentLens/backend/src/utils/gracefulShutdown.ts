import { FastifyInstance } from 'fastify';
import { Logger } from 'pino';

/**
 * Graceful shutdown handler for the application
 * Ensures clean termination of all resources
 */
export function gracefulShutdown(server: FastifyInstance, logger: Logger): void {
  const shutdown = async (signal: string): Promise<void> => {
    logger.info(`🛑 Received ${signal}, starting graceful shutdown...`);

    try {
      // Close the Fastify server
      await server.close();
      logger.info('✅ Fastify server closed');

      // Close database connections will be handled by Prisma client
      // Redis connections will be closed by fastify-redis plugin

      logger.info('✅ SprintAgentLens Backend shutdown complete');
      process.exit(0);
    } catch (error) {
      logger.error('❌ Error during graceful shutdown:', error);
      process.exit(1);
    }
  };

  // Listen for termination signals
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  // Log startup completion
  logger.info('🔄 Graceful shutdown handler registered');
}