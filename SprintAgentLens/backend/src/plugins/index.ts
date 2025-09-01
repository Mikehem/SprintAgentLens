import { FastifyInstance } from 'fastify';
import { config } from '@/config/environment';
import { logger } from '@/utils/logger';

/**
 * Register all Fastify plugins
 * Order matters - some plugins depend on others
 */
export async function registerPlugins(server: FastifyInstance): Promise<void> {
  try {
    // CORS - Must be registered early
    await server.register(import('@fastify/cors'), {
      origin: config.CORS_ORIGIN,
      credentials: config.CORS_CREDENTIALS,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'Accept',
        'Origin',
      ],
    });
    logger.debug('✅ CORS plugin registered');

    // Security headers
    await server.register(import('@fastify/helmet'), {
      global: true,
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", 'data:', 'https:'],
        },
      },
    });
    logger.debug('✅ Helmet security plugin registered');

    // Rate limiting
    await server.register(import('@fastify/rate-limit'), {
      max: config.RATE_LIMIT_MAX,
      timeWindow: `${config.RATE_LIMIT_WINDOW} minutes`,
      skipOnError: true,
      errorResponseBuilder: (req, context) => ({
        error: 'Rate limit exceeded',
        message: `Too many requests, try again in ${config.RATE_LIMIT_WINDOW} minutes`,
        expiresIn: Math.round(context.ttl / 1000),
      }),
    });
    logger.debug('✅ Rate limiting plugin registered');

    // JWT Authentication
    await server.register(import('@fastify/jwt'), {
      secret: config.JWT_SECRET,
      sign: {
        expiresIn: config.JWT_EXPIRE_TIME,
      },
      verify: {
        extractToken: (request) => {
          // Try Authorization header first
          const authHeader = request.headers.authorization;
          if (authHeader && authHeader.startsWith('Bearer ')) {
            return authHeader.substring(7);
          }
          
          // Fallback to cookie
          return request.cookies?.['auth-token'] || null;
        },
      },
    });
    logger.debug('✅ JWT authentication plugin registered');

    // Redis connection
    await server.register(import('@fastify/redis'), {
      host: config.REDIS_HOST,
      port: config.REDIS_PORT,
      password: config.REDIS_PASSWORD || undefined,
      db: config.REDIS_DB,
      connectTimeout: 10000,
      lazyConnect: true,
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3,
    });
    logger.debug('✅ Redis plugin registered');

    // Multipart support for file uploads
    await server.register(import('@fastify/multipart'), {
      limits: {
        fieldNameSize: 100,
        fieldSize: 100,
        fields: 10,
        fileSize: 10 * 1024 * 1024, // 10MB
        files: 5,
      },
    });
    logger.debug('✅ Multipart plugin registered');

    // Swagger documentation (only in development)
    if (config.NODE_ENV === 'development' || config.DEBUG_ENABLED) {
      await server.register(import('@fastify/swagger'), {
        swagger: {
          info: {
            title: 'SprintAgentLens API',
            description: 'Enterprise AI observability and evaluation platform API',
            version: '1.0.0',
          },
          externalDocs: {
            url: 'https://github.com/Mikehem/SprintAgentLens',
            description: 'Find more info here',
          },
          host: `${config.HOST}:${config.PORT}`,
          schemes: ['http', 'https'],
          consumes: ['application/json'],
          produces: ['application/json'],
          securityDefinitions: {
            Bearer: {
              type: 'apiKey',
              name: 'Authorization',
              in: 'header',
              description: 'Enter JWT token as: Bearer <token>',
            },
          },
          security: [{ Bearer: [] }],
        },
      });

      await server.register(import('@fastify/swagger-ui'), {
        routePrefix: '/docs',
        uiConfig: {
          docExpansion: 'list',
          deepLinking: false,
        },
        staticCSP: true,
        transformStaticCSP: (header) => header,
      });
      logger.debug('✅ Swagger documentation registered at /docs');
    }

    logger.info('🔧 All plugins registered successfully');
  } catch (error) {
    logger.error('❌ Failed to register plugins:', error);
    throw error;
  }
}