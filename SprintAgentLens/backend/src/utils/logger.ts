import pino from 'pino';
import { config } from '@/config/environment';

/**
 * Structured logging configuration using Pino
 * Provides production-grade logging with performance optimization
 */

const logLevel = config.LOG_LEVEL || 'info';
const logFormat = config.LOG_FORMAT || 'pretty';

// Base logger configuration
const baseConfig: pino.LoggerOptions = {
  level: logLevel,
  serializers: {
    req: pino.stdSerializers.req,
    res: pino.stdSerializers.res,
    err: pino.stdSerializers.err,
  },
  // Custom serializers for security
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'req.body.password',
      'req.body.token',
      'res.headers["set-cookie"]',
      'password',
      'token',
      'jwt',
      'secret',
      'apiKey',
      'api_key',
    ],
    censor: '[REDACTED]',
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  formatters: {
    level: (label) => ({ level: label }),
  },
};

// Development pretty printing
const prettyConfig = {
  ...baseConfig,
  transport: {
    target: 'pino-pretty',
    options: {
      colorize: true,
      translateTime: 'SYS:standard',
      ignore: 'pid,hostname',
      messageFormat: '[SprintAgentLens] {msg}',
    },
  },
};

// Production structured logging
const productionConfig = {
  ...baseConfig,
};

// Create logger based on environment
export const logger = pino(
  config.NODE_ENV === 'development' && logFormat === 'pretty'
    ? prettyConfig
    : productionConfig
);

/**
 * Authentication-specific logger with additional context
 */
export const authLogger = logger.child({ module: 'authentication' });

/**
 * Database operation logger
 */
export const dbLogger = logger.child({ module: 'database' });

/**
 * API request logger
 */
export const apiLogger = logger.child({ module: 'api' });

/**
 * Security event logger for audit trails
 */
export const securityLogger = logger.child({ 
  module: 'security',
  audit: true 
});

/**
 * Background job logger
 */
export const jobLogger = logger.child({ module: 'jobs' });

/**
 * Utility function to create contextual loggers
 */
export function createLogger(context: string): pino.Logger {
  return logger.child({ context });
}

/**
 * Log authentication events for security audit
 */
export function logAuthEvent(
  event: 'login' | 'logout' | 'failed_login' | 'account_locked' | 'password_changed',
  userId: string | null,
  metadata: Record<string, any> = {}
): void {
  securityLogger.info({
    event: `auth_${event}`,
    userId,
    timestamp: new Date().toISOString(),
    ...metadata,
  }, `Authentication event: ${event}`);
}

/**
 * Log API request/response for debugging
 */
export function logApiRequest(
  method: string,
  url: string,
  statusCode: number,
  responseTime: number,
  userId?: string
): void {
  apiLogger.info({
    method,
    url,
    statusCode,
    responseTime,
    userId,
  }, `${method} ${url} - ${statusCode} (${responseTime}ms)`);
}

/**
 * Log database operations
 */
export function logDatabaseOperation(
  operation: string,
  table: string,
  executionTime: number,
  recordCount?: number
): void {
  dbLogger.debug({
    operation,
    table,
    executionTime,
    recordCount,
  }, `Database ${operation} on ${table} (${executionTime}ms)`);
}

/**
 * Log security violations
 */
export function logSecurityViolation(
  violation: string,
  source: string,
  metadata: Record<string, any> = {}
): void {
  securityLogger.warn({
    violation,
    source,
    timestamp: new Date().toISOString(),
    ...metadata,
  }, `Security violation: ${violation} from ${source}`);
}

/**
 * Emergency shutdown logger
 */
export function logEmergencyShutdown(reason: string, error?: Error): void {
  logger.fatal({
    reason,
    error,
    timestamp: new Date().toISOString(),
  }, `Emergency shutdown: ${reason}`);
}

// Export default logger
export default logger;