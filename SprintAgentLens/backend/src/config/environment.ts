import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

/**
 * Environment configuration with validation and type safety
 */
export interface Config {
  // Application
  NODE_ENV: 'development' | 'production' | 'test';
  PORT: number;
  HOST: string;

  // Database
  MYSQL_HOST: string;
  MYSQL_PORT: number;
  MYSQL_DATABASE: string;
  MYSQL_USER: string;
  MYSQL_PASSWORD: string;
  DATABASE_URL: string;

  // ClickHouse
  CLICKHOUSE_HOST: string;
  CLICKHOUSE_PORT: number;
  CLICKHOUSE_DATABASE: string;
  CLICKHOUSE_USER: string;
  CLICKHOUSE_PASSWORD: string;

  // Redis
  REDIS_HOST: string;
  REDIS_PORT: number;
  REDIS_PASSWORD: string;
  REDIS_DB: number;
  REDIS_URL: string;

  // Authentication & Security
  JWT_SECRET: string;
  JWT_EXPIRE_TIME: string;
  BCRYPT_ROUNDS: number;
  SESSION_EXPIRE_TIME: number;
  ACCOUNT_LOCKOUT_ATTEMPTS: number;
  ACCOUNT_LOCKOUT_DURATION: number;

  // CORS
  CORS_ORIGIN: string[];
  CORS_CREDENTIALS: boolean;

  // Rate Limiting
  RATE_LIMIT_MAX: number;
  RATE_LIMIT_WINDOW: number;

  // Logging
  LOG_LEVEL: string;
  LOG_FORMAT: 'json' | 'pretty';
  LOG_FILE_ENABLED: boolean;
  LOG_FILE_PATH?: string;

  // Feature Toggles
  AUTH_ENABLED: boolean;
  AUTH_MODE: 'database' | 'external';
  ANALYTICS_ENABLED: boolean;
  EXTERNAL_TELEMETRY: boolean;
  DEBUG_ENABLED: boolean;
  DEVELOPMENT_SEED_DATA: boolean;

  // AWS S3 (optional)
  AWS_REGION?: string;
  AWS_ACCESS_KEY_ID?: string;
  AWS_SECRET_ACCESS_KEY?: string;
  AWS_S3_BUCKET?: string;

  // LLM API Keys (optional)
  OPENAI_API_KEY?: string;
  ANTHROPIC_API_KEY?: string;
  GOOGLE_GEMINI_API_KEY?: string;
}

function getEnvVar(name: string, defaultValue?: string): string {
  const value = process.env[name] || defaultValue;
  if (!value) {
    throw new Error(`Environment variable ${name} is required`);
  }
  return value;
}

function getEnvNumber(name: string, defaultValue?: number): number {
  const value = process.env[name];
  if (!value && defaultValue === undefined) {
    throw new Error(`Environment variable ${name} is required`);
  }
  return value ? parseInt(value, 10) : defaultValue!;
}

function getEnvBoolean(name: string, defaultValue = false): boolean {
  const value = process.env[name];
  if (!value) return defaultValue;
  return ['true', '1', 'yes', 'on'].includes(value.toLowerCase());
}

function getEnvArray(name: string, defaultValue: string[] = []): string[] {
  const value = process.env[name];
  if (!value) return defaultValue;
  return value.split(',').map(item => item.trim());
}

// Create and validate configuration
export const config: Config = {
  // Application
  NODE_ENV: (process.env.NODE_ENV as Config['NODE_ENV']) || 'development',
  PORT: getEnvNumber('PORT', 3000),
  HOST: getEnvVar('HOST', '0.0.0.0'),

  // Database
  MYSQL_HOST: getEnvVar('MYSQL_HOST', 'localhost'),
  MYSQL_PORT: getEnvNumber('MYSQL_PORT', 3306),
  MYSQL_DATABASE: getEnvVar('MYSQL_DATABASE', 'sprintagentlens_dev'),
  MYSQL_USER: getEnvVar('MYSQL_USER', 'root'),
  MYSQL_PASSWORD: getEnvVar('MYSQL_PASSWORD', ''),
  DATABASE_URL: getEnvVar('DATABASE_URL', 
    `mysql://${process.env.MYSQL_USER || 'root'}:${process.env.MYSQL_PASSWORD || ''}@${process.env.MYSQL_HOST || 'localhost'}:${process.env.MYSQL_PORT || 3306}/${process.env.MYSQL_DATABASE || 'sprintagentlens_dev'}`
  ),

  // ClickHouse
  CLICKHOUSE_HOST: getEnvVar('CLICKHOUSE_HOST', 'localhost'),
  CLICKHOUSE_PORT: getEnvNumber('CLICKHOUSE_PORT', 8123),
  CLICKHOUSE_DATABASE: getEnvVar('CLICKHOUSE_DATABASE', 'sprintagentlens_analytics'),
  CLICKHOUSE_USER: getEnvVar('CLICKHOUSE_USER', 'default'),
  CLICKHOUSE_PASSWORD: getEnvVar('CLICKHOUSE_PASSWORD', ''),

  // Redis
  REDIS_HOST: getEnvVar('REDIS_HOST', 'localhost'),
  REDIS_PORT: getEnvNumber('REDIS_PORT', 6379),
  REDIS_PASSWORD: getEnvVar('REDIS_PASSWORD', ''),
  REDIS_DB: getEnvNumber('REDIS_DB', 0),
  REDIS_URL: getEnvVar('REDIS_URL', 'redis://localhost:6379'),

  // Authentication & Security
  JWT_SECRET: getEnvVar('JWT_SECRET'),
  JWT_EXPIRE_TIME: getEnvVar('JWT_EXPIRE_TIME', '24h'),
  BCRYPT_ROUNDS: getEnvNumber('BCRYPT_ROUNDS', 12),
  SESSION_EXPIRE_TIME: getEnvNumber('SESSION_EXPIRE_TIME', 86400), // 24 hours
  ACCOUNT_LOCKOUT_ATTEMPTS: getEnvNumber('ACCOUNT_LOCKOUT_ATTEMPTS', 5),
  ACCOUNT_LOCKOUT_DURATION: getEnvNumber('ACCOUNT_LOCKOUT_DURATION', 900), // 15 minutes

  // CORS
  CORS_ORIGIN: getEnvArray('CORS_ORIGIN', ['http://localhost:3000']),
  CORS_CREDENTIALS: getEnvBoolean('CORS_CREDENTIALS', true),

  // Rate Limiting
  RATE_LIMIT_MAX: getEnvNumber('RATE_LIMIT_MAX', 100),
  RATE_LIMIT_WINDOW: getEnvNumber('RATE_LIMIT_WINDOW', 15), // minutes

  // Logging
  LOG_LEVEL: getEnvVar('LOG_LEVEL', 'debug'),
  LOG_FORMAT: (process.env.LOG_FORMAT as Config['LOG_FORMAT']) || 'pretty',
  LOG_FILE_ENABLED: getEnvBoolean('LOG_FILE_ENABLED', false),
  LOG_FILE_PATH: process.env.LOG_FILE_PATH,

  // Feature Toggles
  AUTH_ENABLED: getEnvBoolean('AUTH_ENABLED', true),
  AUTH_MODE: (process.env.AUTH_MODE as Config['AUTH_MODE']) || 'database',
  ANALYTICS_ENABLED: getEnvBoolean('ANALYTICS_ENABLED', true),
  EXTERNAL_TELEMETRY: getEnvBoolean('EXTERNAL_TELEMETRY', false),
  DEBUG_ENABLED: getEnvBoolean('DEBUG_ENABLED', true),
  DEVELOPMENT_SEED_DATA: getEnvBoolean('DEVELOPMENT_SEED_DATA', true),

  // Optional AWS S3
  AWS_REGION: process.env.AWS_REGION,
  AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
  AWS_S3_BUCKET: process.env.AWS_S3_BUCKET,

  // Optional LLM API Keys
  OPENAI_API_KEY: process.env.OPENAI_API_KEY,
  ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY,
  GOOGLE_GEMINI_API_KEY: process.env.GOOGLE_GEMINI_API_KEY,
};

// Validate critical configuration
if (config.NODE_ENV === 'production' && config.JWT_SECRET.includes('dev-')) {
  throw new Error('Production environment requires secure JWT_SECRET');
}

if (config.NODE_ENV === 'production' && config.BCRYPT_ROUNDS < 12) {
  throw new Error('Production environment requires BCRYPT_ROUNDS >= 12');
}

// Log configuration (excluding sensitive data)
console.log('📋 Configuration loaded:', {
  NODE_ENV: config.NODE_ENV,
  PORT: config.PORT,
  HOST: config.HOST,
  MYSQL_HOST: config.MYSQL_HOST,
  MYSQL_DATABASE: config.MYSQL_DATABASE,
  REDIS_HOST: config.REDIS_HOST,
  AUTH_ENABLED: config.AUTH_ENABLED,
  DEBUG_ENABLED: config.DEBUG_ENABLED,
});