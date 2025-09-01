import { PrismaClient } from '@prisma/client';
import { createClient } from '@clickhouse/client';
import { config } from '@/config/environment';
import { dbLogger, logger } from '@/utils/logger';

/**
 * Database connection management
 * Handles MySQL (Prisma) and ClickHouse connections
 */

// Prisma Client instance with logging and error handling
export const prisma = new PrismaClient({
  log: [
    {
      emit: 'event',
      level: 'query',
    },
    {
      emit: 'event', 
      level: 'error',
    },
    {
      emit: 'event',
      level: 'info',
    },
    {
      emit: 'event',
      level: 'warn',
    },
  ],
  errorFormat: 'pretty',
});

// ClickHouse client for analytics data
export const clickhouse = createClient({
  host: `http://${config.CLICKHOUSE_HOST}:${config.CLICKHOUSE_PORT}`,
  database: config.CLICKHOUSE_DATABASE,
  username: config.CLICKHOUSE_USER,
  password: config.CLICKHOUSE_PASSWORD,
  clickhouse_settings: {
    // Optimize for frequent small queries
    max_execution_time: 30,
    max_memory_usage: 1000000000, // 1GB
  },
});

/**
 * Set up Prisma event listeners for logging
 */
function setupPrismaLogging(): void {
  prisma.$on('query', (e) => {
    dbLogger.debug({
      query: e.query,
      params: e.params,
      duration: `${e.duration}ms`,
    }, 'Prisma query executed');
  });

  prisma.$on('error', (e) => {
    dbLogger.error({
      target: e.target,
      message: e.message,
    }, 'Prisma error occurred');
  });

  prisma.$on('info', (e) => {
    dbLogger.info({
      target: e.target,
      message: e.message,
    }, 'Prisma info');
  });

  prisma.$on('warn', (e) => {
    dbLogger.warn({
      target: e.target,
      message: e.message,
    }, 'Prisma warning');
  });
}

/**
 * Test database connections
 */
async function testConnections(): Promise<void> {
  // Test MySQL connection
  try {
    await prisma.$queryRaw`SELECT 1 as test`;
    dbLogger.info('✅ MySQL connection successful');
  } catch (error) {
    dbLogger.error('❌ MySQL connection failed:', error);
    throw error;
  }

  // Test ClickHouse connection (if enabled)
  if (config.ANALYTICS_ENABLED) {
    try {
      await clickhouse.query({
        query: 'SELECT 1 as test',
      });
      dbLogger.info('✅ ClickHouse connection successful');
    } catch (error) {
      dbLogger.warn('⚠️  ClickHouse connection failed (analytics will be disabled):', error);
    }
  }
}

/**
 * Connect to all databases and set up logging
 */
export async function connectDatabases(): Promise<void> {
  try {
    logger.info('🔌 Connecting to databases...');
    
    // Set up Prisma logging
    setupPrismaLogging();
    
    // Test connections
    await testConnections();
    
    logger.info('✅ Database connections established');
  } catch (error) {
    logger.error('❌ Failed to connect to databases:', error);
    throw error;
  }
}

/**
 * Disconnect from all databases
 */
export async function disconnectDatabases(): Promise<void> {
  try {
    logger.info('🔌 Disconnecting from databases...');
    
    await prisma.$disconnect();
    await clickhouse.close();
    
    logger.info('✅ Database connections closed');
  } catch (error) {
    logger.error('❌ Error disconnecting from databases:', error);
    throw error;
  }
}

/**
 * Database health check
 */
export async function checkDatabaseHealth(): Promise<{
  mysql: boolean;
  clickhouse: boolean;
}> {
  const health = {
    mysql: false,
    clickhouse: false,
  };

  // Check MySQL
  try {
    await prisma.$queryRaw`SELECT 1 as test`;
    health.mysql = true;
  } catch (error) {
    dbLogger.error('MySQL health check failed:', error);
  }

  // Check ClickHouse
  if (config.ANALYTICS_ENABLED) {
    try {
      await clickhouse.query({
        query: 'SELECT 1 as test',
      });
      health.clickhouse = true;
    } catch (error) {
      dbLogger.error('ClickHouse health check failed:', error);
    }
  } else {
    health.clickhouse = true; // Not enabled, so consider healthy
  }

  return health;
}

/**
 * Execute raw MySQL query with error handling
 */
export async function executeRawQuery<T = any>(
  query: string,
  params: any[] = []
): Promise<T[]> {
  try {
    const startTime = Date.now();
    const result = await prisma.$queryRawUnsafe<T[]>(query, ...params);
    const duration = Date.now() - startTime;
    
    dbLogger.debug({
      query,
      params,
      duration: `${duration}ms`,
      resultCount: result.length,
    }, 'Raw query executed');
    
    return result;
  } catch (error) {
    dbLogger.error({
      query,
      params,
      error,
    }, 'Raw query failed');
    throw error;
  }
}

/**
 * Execute ClickHouse query with error handling
 */
export async function executeClickHouseQuery<T = any>(
  query: string,
  params: Record<string, any> = {}
): Promise<T[]> {
  try {
    const startTime = Date.now();
    const result = await clickhouse.query({
      query,
      query_params: params,
    });
    
    const data = await result.json<T[]>();
    const duration = Date.now() - startTime;
    
    dbLogger.debug({
      query,
      params,
      duration: `${duration}ms`,
      resultCount: data.length,
    }, 'ClickHouse query executed');
    
    return data;
  } catch (error) {
    dbLogger.error({
      query,
      params,
      error,
    }, 'ClickHouse query failed');
    throw error;
  }
}

// Export default Prisma client
export default prisma;