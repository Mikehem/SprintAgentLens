import { FastifyRequest, FastifyReply } from 'fastify';
import { AuthService } from '@/services/AuthService';
import { authLogger, logSecurityViolation } from '@/utils/logger';
import { UserRole, AuthenticatedUser, AuthMiddlewareOptions, AuthContext } from '@/types/auth';

/**
 * Authentication middleware for Fastify
 * Provides JWT token verification and role-based access control
 */

declare module 'fastify' {
  interface FastifyRequest {
    user?: AuthenticatedUser;
    authContext?: AuthContext;
  }
}

/**
 * Extract authentication context from request
 */
function extractAuthContext(request: FastifyRequest): AuthContext {
  return {
    ipAddress: request.ip || null,
    userAgent: request.headers['user-agent'] || null,
    requestId: request.id || `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    timestamp: new Date(),
  };
}

/**
 * Main authentication middleware
 */
export async function authenticate(
  request: FastifyRequest,
  reply: FastifyReply,
  options: AuthMiddlewareOptions = {}
): Promise<void> {
  try {
    const authContext = extractAuthContext(request);
    request.authContext = authContext;

    // Extract token from Authorization header or cookies
    let token: string | null = null;
    
    const authHeader = request.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    } else if (request.cookies?.['auth-token']) {
      token = request.cookies['auth-token'];
    }

    // If no token and authentication is optional, continue
    if (!token && !options.required) {
      return;
    }

    // If no token and authentication is required, return unauthorized
    if (!token) {
      authLogger.warn('Authentication required but no token provided', {
        path: request.url,
        method: request.method,
        ip: authContext.ipAddress,
      });

      logSecurityViolation(
        'missing_authentication_token',
        authContext.ipAddress || 'unknown',
        { path: request.url, method: request.method }
      );

      return reply.status(401).send({
        success: false,
        error: 'Authentication token required',
        code: 'MISSING_TOKEN',
        timestamp: new Date().toISOString(),
      });
    }

    // Verify token
    const authResult = await AuthService.verifyToken(token);
    
    if (!authResult.success || !authResult.user) {
      authLogger.warn('Invalid authentication token', {
        reason: authResult.reason,
        path: request.url,
        method: request.method,
        ip: authContext.ipAddress,
      });

      logSecurityViolation(
        'invalid_authentication_token',
        authContext.ipAddress || 'unknown',
        { 
          reason: authResult.reason,
          path: request.url,
          method: request.method,
        }
      );

      return reply.status(401).send({
        success: false,
        error: authResult.error || 'Invalid or expired token',
        code: authResult.reason?.toUpperCase() || 'INVALID_TOKEN',
        timestamp: new Date().toISOString(),
      });
    }

    // Create authenticated user object with session info
    const authenticatedUser: AuthenticatedUser = {
      ...authResult.user,
      sessionId: authResult.sessionId!,
      permissions: getRolePermissions(authResult.user.role),
    };

    request.user = authenticatedUser;

    // Check role requirements
    if (options.roles && options.roles.length > 0) {
      if (!options.roles.includes(authenticatedUser.role)) {
        authLogger.warn('Insufficient role permissions', {
          userId: authenticatedUser.id,
          userRole: authenticatedUser.role,
          requiredRoles: options.roles,
          path: request.url,
          method: request.method,
        });

        logSecurityViolation(
          'insufficient_role_permissions',
          authContext.ipAddress || 'unknown',
          {
            userId: authenticatedUser.id,
            userRole: authenticatedUser.role,
            requiredRoles: options.roles,
            path: request.url,
            method: request.method,
          }
        );

        return reply.status(403).send({
          success: false,
          error: 'Insufficient permissions',
          code: 'INSUFFICIENT_PERMISSIONS',
          timestamp: new Date().toISOString(),
        });
      }
    }

    // Check specific permissions
    if (options.permissions && options.permissions.length > 0) {
      const hasPermission = options.permissions.some(permission => 
        authenticatedUser.permissions.includes(permission)
      );

      if (!hasPermission) {
        authLogger.warn('Insufficient permissions', {
          userId: authenticatedUser.id,
          userPermissions: authenticatedUser.permissions,
          requiredPermissions: options.permissions,
          path: request.url,
          method: request.method,
        });

        logSecurityViolation(
          'insufficient_permissions',
          authContext.ipAddress || 'unknown',
          {
            userId: authenticatedUser.id,
            requiredPermissions: options.permissions,
            path: request.url,
            method: request.method,
          }
        );

        return reply.status(403).send({
          success: false,
          error: 'Insufficient permissions',
          code: 'INSUFFICIENT_PERMISSIONS',
          timestamp: new Date().toISOString(),
        });
      }
    }

    authLogger.debug('Authentication successful', {
      userId: authenticatedUser.id,
      username: authenticatedUser.username,
      role: authenticatedUser.role,
      path: request.url,
      method: request.method,
    });
  } catch (error) {
    authLogger.error('Authentication middleware error:', error);
    
    return reply.status(500).send({
      success: false,
      error: 'Authentication service error',
      code: 'AUTH_SERVICE_ERROR',
      timestamp: new Date().toISOString(),
    });
  }
}

/**
 * Require authentication middleware
 */
export async function requireAuth(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  return authenticate(request, reply, { required: true });
}

/**
 * Require admin role middleware
 */
export async function requireAdmin(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  return authenticate(request, reply, { 
    required: true, 
    roles: [UserRole.ADMIN] 
  });
}

/**
 * Require user role or higher middleware
 */
export async function requireUser(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  return authenticate(request, reply, { 
    required: true, 
    roles: [UserRole.ADMIN, UserRole.USER] 
  });
}

/**
 * Optional authentication middleware
 */
export async function optionalAuth(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  return authenticate(request, reply, { required: false });
}

/**
 * Get role permissions
 */
function getRolePermissions(role: UserRole): string[] {
  const permissions: Record<UserRole, string[]> = {
    [UserRole.ADMIN]: [
      'users:create',
      'users:read',
      'users:update',
      'users:delete',
      'projects:create',
      'projects:read',
      'projects:update',
      'projects:delete',
      'experiments:create',
      'experiments:read',
      'experiments:update',
      'experiments:delete',
      'datasets:create',
      'datasets:read',
      'datasets:update',
      'datasets:delete',
      'traces:create',
      'traces:read',
      'traces:update',
      'traces:delete',
      'workspace:configure',
      'system:admin',
    ],
    [UserRole.USER]: [
      'projects:create',
      'projects:read',
      'projects:update',
      'experiments:create',
      'experiments:read',
      'experiments:update',
      'datasets:create',
      'datasets:read',
      'datasets:update',
      'traces:create',
      'traces:read',
      'traces:update',
      'profile:update',
    ],
    [UserRole.VIEWER]: [
      'projects:read',
      'experiments:read',
      'datasets:read',
      'traces:read',
      'profile:read',
    ],
  };

  return permissions[role] || [];
}

/**
 * Check if user has specific permission
 */
export function hasPermission(user: AuthenticatedUser, permission: string): boolean {
  return user.permissions.includes(permission);
}

/**
 * Check if user has any of the specified roles
 */
export function hasRole(user: AuthenticatedUser, roles: UserRole[]): boolean {
  return roles.includes(user.role);
}

/**
 * Workspace authorization - check if user can access workspace
 */
export function canAccessWorkspace(user: AuthenticatedUser, workspaceId: string): boolean {
  // Admin can access any workspace
  if (user.role === UserRole.ADMIN) {
    return true;
  }
  
  // Regular users can only access their own workspace
  return user.workspaceId === workspaceId;
}

/**
 * Resource authorization - check if user can access specific resource
 */
export function canAccessResource(
  user: AuthenticatedUser, 
  resourceOwnerId: string, 
  resourceWorkspaceId?: string
): boolean {
  // Admin can access any resource
  if (user.role === UserRole.ADMIN) {
    return true;
  }
  
  // Users can access resources they own
  if (user.id === resourceOwnerId) {
    return true;
  }
  
  // Users can access resources in their workspace (if workspace matches)
  if (resourceWorkspaceId && user.workspaceId === resourceWorkspaceId) {
    return true;
  }
  
  return false;
}

/**
 * Error handler for authentication failures
 */
export function handleAuthError(error: any, reply: FastifyReply): void {
  authLogger.error('Authentication error:', error);
  
  reply.status(401).send({
    success: false,
    error: 'Authentication failed',
    code: 'AUTH_FAILED',
    timestamp: new Date().toISOString(),
  });
}