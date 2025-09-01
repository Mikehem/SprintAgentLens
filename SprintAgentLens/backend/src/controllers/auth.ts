import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import Joi from 'joi';
import { AuthService } from '@/services/AuthService';
import { requireAuth, requireAdmin } from '@/middleware/auth';
import { authLogger, logAuthEvent, logSecurityViolation } from '@/utils/logger';
import { config } from '@/config/environment';
import {
  LoginRequest,
  LoginResponse,
  CreateUserRequest,
  PublicUserInfo,
  AuthContext,
  ApiResponse,
} from '@/types/auth';

/**
 * Authentication Controller
 * Enterprise-grade authentication endpoints compatible with OPIK Java backend
 * 
 * Endpoints:
 * - POST /login - User authentication
 * - POST /logout - User logout
 * - GET /status - Check authentication status
 * - POST /generate-hash - Generate password hash (development only)
 */

// Validation schemas
const loginSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(50).required(),
  password: Joi.string().min(8).max(100).required(),
  workspaceId: Joi.string().max(50).optional(),
});

const createUserSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(50).required(),
  email: Joi.string().email().max(255).required(),
  fullName: Joi.string().max(100).optional(),
  password: Joi.string().min(8).max(100).required(),
  role: Joi.string().valid('ADMIN', 'USER', 'VIEWER').optional(),
  workspaceId: Joi.string().max(50).optional(),
});

const generateHashSchema = Joi.object({
  password: Joi.string().min(1).max(100).required(),
  salt: Joi.string().optional(),
});

export default async function authController(fastify: FastifyInstance): Promise<void> {
  // Add JSON schema definitions for Swagger documentation
  fastify.addSchema({
    $id: 'LoginRequest',
    type: 'object',
    properties: {
      username: { type: 'string', minLength: 3, maxLength: 50 },
      password: { type: 'string', minLength: 8, maxLength: 100 },
      workspaceId: { type: 'string', maxLength: 50 },
    },
    required: ['username', 'password'],
  });

  fastify.addSchema({
    $id: 'LoginResponse',
    type: 'object',
    properties: {
      success: { type: 'boolean' },
      token: { type: 'string' },
      user: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          username: { type: 'string' },
          email: { type: 'string' },
          fullName: { type: 'string' },
          role: { type: 'string' },
          workspaceId: { type: 'string' },
          isActive: { type: 'boolean' },
          lastLoginAt: { type: 'string', format: 'date-time' },
        },
      },
      expiresIn: { type: 'number' },
      workspaceId: { type: 'string' },
    },
  });

  /**
   * POST /login - User authentication
   * Compatible with OPIK Java EnterpriseAuthResource.login()
   */
  fastify.post('/login', {
    schema: {
      description: 'Authenticate user with username and password',
      tags: ['Authentication'],
      body: { $ref: 'LoginRequest' },
      response: {
        200: { $ref: 'LoginResponse' },
        401: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            error: { type: 'string' },
            code: { type: 'string' },
            timestamp: { type: 'string' },
          },
        },
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      // Validate request body
      const { error: validationError, value: loginData } = loginSchema.validate(request.body);
      if (validationError) {
        authLogger.warn('Login validation failed:', validationError.details);
        return reply.status(400).send({
          success: false,
          error: 'Invalid request data',
          code: 'VALIDATION_ERROR',
          details: validationError.details,
          timestamp: new Date().toISOString(),
        });
      }

      const loginRequest: LoginRequest = {
        username: loginData.username,
        password: loginData.password,
        workspaceId: loginData.workspaceId || 'default',
      };

      // Extract authentication context
      const authContext: AuthContext = {
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] || null,
        requestId: request.id,
        timestamp: new Date(),
      };

      authLogger.info(`Login attempt for user: ${loginRequest.username}`, {
        ip: authContext.ipAddress,
        userAgent: authContext.userAgent,
      });

      // Authenticate user
      const authResult = await AuthService.authenticate(loginRequest, authContext);

      if (!authResult.success) {
        const statusCode = authResult.reason === 'account_locked' ? 423 : 401;
        
        logSecurityViolation(
          'failed_login_attempt',
          authContext.ipAddress || 'unknown',
          {
            username: loginRequest.username,
            reason: authResult.reason,
          }
        );

        return reply.status(statusCode).send({
          success: false,
          error: authResult.error,
          code: authResult.reason?.toUpperCase() || 'AUTH_FAILED',
          timestamp: new Date().toISOString(),
        });
      }

      // Prepare successful response
      const loginResponse: LoginResponse = {
        success: true,
        token: authResult.token!,
        user: authResult.user!,
        expiresIn: config.SESSION_EXPIRE_TIME,
        workspaceId: authResult.user!.workspaceId,
      };

      // Set HTTP-only cookie for additional security
      reply.setCookie('auth-token', authResult.token!, {
        httpOnly: true,
        secure: config.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: config.SESSION_EXPIRE_TIME,
        path: '/',
      });

      authLogger.info(`Login successful for user: ${authResult.user!.username}`, {
        userId: authResult.user!.id,
        sessionId: authResult.sessionId,
      });

      return reply.status(200).send(loginResponse);
    } catch (error) {
      authLogger.error('Login endpoint error:', error);
      return reply.status(500).send({
        success: false,
        error: 'Internal server error',
        code: 'SERVER_ERROR',
        timestamp: new Date().toISOString(),
      });
    }
  });

  /**
   * POST /logout - User logout
   * Compatible with OPIK Java EnterpriseAuthResource.logout()
   */
  fastify.post('/logout', {
    preHandler: requireAuth,
    schema: {
      description: 'Logout user and invalidate session',
      tags: ['Authentication'],
      security: [{ Bearer: [] }],
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
      const user = request.user!;
      const authContext = request.authContext!;

      authLogger.info(`Logout request for user: ${user.username}`, {
        userId: user.id,
        sessionId: user.sessionId,
      });

      // Invalidate session
      const success = await AuthService.logout(user.sessionId, authContext);

      if (success) {
        // Clear authentication cookie
        reply.clearCookie('auth-token', { path: '/' });

        authLogger.info(`Logout successful for user: ${user.username}`);

        return reply.status(200).send({
          success: true,
          message: 'Successfully logged out',
          timestamp: new Date().toISOString(),
        });
      } else {
        return reply.status(500).send({
          success: false,
          error: 'Logout failed',
          code: 'LOGOUT_ERROR',
          timestamp: new Date().toISOString(),
        });
      }
    } catch (error) {
      authLogger.error('Logout endpoint error:', error);
      return reply.status(500).send({
        success: false,
        error: 'Internal server error',
        code: 'SERVER_ERROR',
        timestamp: new Date().toISOString(),
      });
    }
  });

  /**
   * GET /status - Check authentication status
   * Compatible with OPIK Java EnterpriseAuthResource.status()
   */
  fastify.get('/status', {
    preHandler: requireAuth,
    schema: {
      description: 'Get current authentication status and user information',
      tags: ['Authentication'],
      security: [{ Bearer: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            authenticated: { type: 'boolean' },
            user: {
              type: 'object',
              properties: {
                id: { type: 'string' },
                username: { type: 'string' },
                email: { type: 'string' },
                fullName: { type: 'string' },
                role: { type: 'string' },
                workspaceId: { type: 'string' },
                isActive: { type: 'boolean' },
                lastLoginAt: { type: 'string', format: 'date-time' },
              },
            },
            sessionId: { type: 'string' },
            permissions: {
              type: 'array',
              items: { type: 'string' },
            },
            timestamp: { type: 'string' },
          },
        },
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const user = request.user!;

      authLogger.debug(`Status check for user: ${user.username}`, {
        userId: user.id,
        sessionId: user.sessionId,
      });

      return reply.status(200).send({
        success: true,
        authenticated: true,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          fullName: user.fullName,
          role: user.role,
          workspaceId: user.workspaceId,
          isActive: user.isActive,
          lastLoginAt: user.lastLoginAt,
        },
        sessionId: user.sessionId,
        permissions: user.permissions,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      authLogger.error('Status endpoint error:', error);
      return reply.status(500).send({
        success: false,
        error: 'Internal server error',
        code: 'SERVER_ERROR',
        timestamp: new Date().toISOString(),
      });
    }
  });

  /**
   * POST /generate-hash - Generate password hash (development/testing only)
   * Compatible with OPIK Java EnterpriseAuthResource.generateHash()
   */
  if (config.NODE_ENV === 'development' || config.DEBUG_ENABLED) {
    fastify.post('/generate-hash', {
      schema: {
        description: 'Generate BCrypt hash for password (development only)',
        tags: ['Authentication', 'Development'],
        body: {
          type: 'object',
          properties: {
            password: { type: 'string' },
            salt: { type: 'string' },
          },
          required: ['password'],
        },
        response: {
          200: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              hash: { type: 'string' },
              salt: { type: 'string' },
              timestamp: { type: 'string' },
            },
          },
        },
      },
    }, async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const { error: validationError, value: hashData } = generateHashSchema.validate(request.body);
        if (validationError) {
          return reply.status(400).send({
            success: false,
            error: 'Invalid request data',
            details: validationError.details,
          });
        }

        authLogger.info('Password hash generation request (development mode)');

        const result = await AuthService.hashPassword(hashData.password, hashData.salt);

        return reply.status(200).send({
          success: true,
          hash: result.hash,
          salt: result.salt,
          timestamp: new Date().toISOString(),
        });
      } catch (error) {
        authLogger.error('Generate hash endpoint error:', error);
        return reply.status(500).send({
          success: false,
          error: 'Hash generation failed',
          timestamp: new Date().toISOString(),
        });
      }
    });
  }

  /**
   * POST /create-user - Create new user (admin only)
   */
  fastify.post('/create-user', {
    preHandler: requireAdmin,
    schema: {
      description: 'Create new user account (admin only)',
      tags: ['Authentication', 'Admin'],
      security: [{ Bearer: [] }],
      body: {
        type: 'object',
        properties: {
          username: { type: 'string', minLength: 3, maxLength: 50 },
          email: { type: 'string', format: 'email', maxLength: 255 },
          fullName: { type: 'string', maxLength: 100 },
          password: { type: 'string', minLength: 8, maxLength: 100 },
          role: { type: 'string', enum: ['ADMIN', 'USER', 'VIEWER'] },
          workspaceId: { type: 'string', maxLength: 50 },
        },
        required: ['username', 'email', 'password'],
      },
      response: {
        201: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            user: {
              type: 'object',
              properties: {
                id: { type: 'string' },
                username: { type: 'string' },
                email: { type: 'string' },
                fullName: { type: 'string' },
                role: { type: 'string' },
                workspaceId: { type: 'string' },
                isActive: { type: 'boolean' },
              },
            },
            timestamp: { type: 'string' },
          },
        },
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { error: validationError, value: userData } = createUserSchema.validate(request.body);
      if (validationError) {
        return reply.status(400).send({
          success: false,
          error: 'Invalid request data',
          details: validationError.details,
          timestamp: new Date().toISOString(),
        });
      }

      const creator = request.user!;
      const authContext = request.authContext!;

      authLogger.info(`User creation request by admin: ${creator.username}`, {
        creatorId: creator.id,
        newUsername: userData.username,
      });

      const newUser = await AuthService.createUser(userData, creator.id, authContext);

      return reply.status(201).send({
        success: true,
        user: newUser,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      authLogger.error('Create user endpoint error:', error);
      
      if (error instanceof Error && error.message.includes('already exists')) {
        return reply.status(409).send({
          success: false,
          error: error.message,
          code: 'USER_EXISTS',
          timestamp: new Date().toISOString(),
        });
      }

      return reply.status(500).send({
        success: false,
        error: 'User creation failed',
        code: 'SERVER_ERROR',
        timestamp: new Date().toISOString(),
      });
    }
  });

  authLogger.info('✅ Authentication controller registered with endpoints: /login, /logout, /status');
}