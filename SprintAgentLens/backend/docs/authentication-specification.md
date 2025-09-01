# Authentication Specification for SprintAgentLens

## Overview
This document provides detailed specifications for implementing the authentication system in SprintAgentLens, maintaining full compatibility with the existing OPIK Java backend.

## Authentication Architecture

### Core Components
1. **User Management**: User accounts and profiles
2. **Session Management**: JWT tokens with Redis storage
3. **Password Security**: BCrypt hashing with custom salt logic
4. **Authorization**: Role-based access control (RBAC)
5. **Audit Logging**: Comprehensive authentication tracking
6. **Security Features**: Rate limiting, account lockout, IP tracking

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id CHAR(36) PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255),
    role ENUM('admin', 'user', 'viewer') DEFAULT 'user',
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    workspace_id VARCHAR(255) DEFAULT 'default',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255),
    last_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_updated_by VARCHAR(255),
    last_login_at TIMESTAMP NULL,
    failed_login_attempts INT DEFAULT 0,
    account_locked_until TIMESTAMP NULL,
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_workspace_id (workspace_id)
);
```

### User Sessions Table
```sql
CREATE TABLE user_sessions (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    session_token VARCHAR(512) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_session_token (session_token),
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at)
);
```

### User Audit Log Table
```sql
CREATE TABLE user_audit_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id CHAR(36),
    username VARCHAR(255),
    action ENUM('login_success', 'login_failed', 'logout', 'password_change', 'account_locked', 'account_unlocked', 'created', 'updated', 'deleted') NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    additional_info JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_id (user_id),
    INDEX idx_username (username),
    INDEX idx_action (action),
    INDEX idx_created_at (created_at)
);
```

## TypeScript Interfaces

### Core Types
```typescript
interface User {
  id: string;
  username: string;
  email: string;
  fullName: string | null;
  role: 'admin' | 'user' | 'viewer';
  passwordHash: string;
  salt: string;
  isActive: boolean;
  workspaceId: string;
  createdAt: Date;
  createdBy: string | null;
  lastUpdatedAt: Date;
  lastUpdatedBy: string | null;
  lastLoginAt: Date | null;
  failedLoginAttempts: number;
  accountLockedUntil: Date | null;
}

interface UserSession {
  id: string;
  userId: string;
  sessionToken: string;
  expiresAt: Date;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: Date;
  lastAccessedAt: Date;
}

interface AuditLogEntry {
  id: number;
  userId: string | null;
  username: string | null;
  action: AuditAction;
  ipAddress: string | null;
  userAgent: string | null;
  additionalInfo: Record<string, any> | null;
  createdAt: Date;
}

type AuditAction = 
  | 'login_success' 
  | 'login_failed' 
  | 'logout' 
  | 'password_change' 
  | 'account_locked' 
  | 'account_unlocked' 
  | 'created' 
  | 'updated' 
  | 'deleted';
```

### Request/Response Types
```typescript
interface LoginRequest {
  username: string;
  password: string;
  workspaceId?: string;
}

interface LoginResponse {
  success: boolean;
  user: PublicUser;
  sessionToken: string;
  expiresAt: Date;
}

interface PublicUser {
  id: string;
  username: string;
  email: string;
  fullName: string | null;
  role: string;
  workspaceId: string;
  isActive: boolean;
  lastLoginAt: Date | null;
  createdAt: Date;
  createdBy: string | null;
  lastUpdatedAt: Date;
  lastUpdatedBy: string | null;
}

interface CreateUserRequest {
  username: string;
  email: string;
  fullName?: string;
  password: string;
  role: 'admin' | 'user' | 'viewer';
  workspaceId?: string;
}

interface UpdateUserRequest {
  email?: string;
  fullName?: string;
  role?: 'admin' | 'user' | 'viewer';
  isActive?: boolean;
}

interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
}
```

## Authentication Service Implementation

### Password Hashing Service
```typescript
import bcrypt from 'bcryptjs';
import crypto from 'crypto';

export class PasswordService {
  private static readonly SALT_ROUNDS = 12;
  private static readonly SALT_LENGTH = 32;

  /**
   * Generate a random salt for password hashing
   */
  static generateSalt(): string {
    return crypto.randomBytes(this.SALT_LENGTH).toString('hex');
  }

  /**
   * Hash password with salt using BCrypt
   * Maintains compatibility with Java implementation: BCrypt.hashpw(password + salt, BCrypt.gensalt(12))
   */
  static async hashPassword(password: string, salt: string): Promise<string> {
    const combined = password + salt;
    return bcrypt.hash(combined, this.SALT_ROUNDS);
  }

  /**
   * Verify password against hash
   * Maintains compatibility with Java implementation
   */
  static async verifyPassword(
    password: string, 
    salt: string, 
    hash: string
  ): Promise<boolean> {
    const combined = password + salt;
    return bcrypt.compare(combined, hash);
  }

  /**
   * Generate secure random password for admin-created users
   */
  static generateSecurePassword(length: number = 16): string {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let password = '';
    for (let i = 0; i < length; i++) {
      password += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    return password;
  }
}
```

### JWT Service
```typescript
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

interface JWTPayload {
  userId: string;
  username: string;
  role: string;
  workspaceId: string;
  sessionId: string;
  iat: number;
  exp: number;
}

export class JWTService {
  private static readonly JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
  private static readonly JWT_EXPIRY = '24h'; // 24 hours
  
  /**
   * Generate JWT token for user session
   */
  static generateToken(user: User): { token: string; expiresAt: Date } {
    const sessionId = uuidv4();
    const expiresIn = 24 * 60 * 60; // 24 hours in seconds
    const expiresAt = new Date(Date.now() + expiresIn * 1000);
    
    const payload: JWTPayload = {
      userId: user.id,
      username: user.username,
      role: user.role,
      workspaceId: user.workspaceId,
      sessionId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(expiresAt.getTime() / 1000),
    };
    
    const token = jwt.sign(payload, this.JWT_SECRET);
    
    return { token, expiresAt };
  }
  
  /**
   * Verify and decode JWT token
   */
  static verifyToken(token: string): JWTPayload | null {
    try {
      const decoded = jwt.verify(token, this.JWT_SECRET) as JWTPayload;
      return decoded;
    } catch (error) {
      return null;
    }
  }
  
  /**
   * Extract token from Authorization header
   */
  static extractTokenFromHeader(authHeader: string | undefined): string | null {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }
    return authHeader.substring(7);
  }
}
```

### Authentication Service
```typescript
export class AuthService {
  private userDAO: UserDAO;
  private sessionDAO: UserSessionDAO;
  private auditDAO: UserAuditDAO;
  private redisClient: Redis;

  constructor(
    userDAO: UserDAO,
    sessionDAO: UserSessionDAO,
    auditDAO: UserAuditDAO,
    redisClient: Redis
  ) {
    this.userDAO = userDAO;
    this.sessionDAO = sessionDAO;
    this.auditDAO = auditDAO;
    this.redisClient = redisClient;
  }

  /**
   * Authenticate user with username/password
   */
  async login(
    username: string, 
    password: string, 
    workspaceId: string = 'default',
    ipAddress?: string,
    userAgent?: string
  ): Promise<LoginResponse> {
    try {
      // Find user by username
      const user = await this.userDAO.findByUsername(username);
      if (!user) {
        await this.auditDAO.logAction({
          username,
          action: 'login_failed',
          ipAddress,
          userAgent,
          additionalInfo: { reason: 'user_not_found' }
        });
        throw new Error('Invalid credentials');
      }

      // Check if account is locked
      if (user.accountLockedUntil && user.accountLockedUntil > new Date()) {
        await this.auditDAO.logAction({
          userId: user.id,
          username,
          action: 'login_failed',
          ipAddress,
          userAgent,
          additionalInfo: { reason: 'account_locked' }
        });
        throw new Error('Account is locked');
      }

      // Check if account is active
      if (!user.isActive) {
        await this.auditDAO.logAction({
          userId: user.id,
          username,
          action: 'login_failed',
          ipAddress,
          userAgent,
          additionalInfo: { reason: 'account_disabled' }
        });
        throw new Error('Account is disabled');
      }

      // Verify password
      const isValidPassword = await PasswordService.verifyPassword(
        password, 
        user.salt, 
        user.passwordHash
      );

      if (!isValidPassword) {
        // Increment failed login attempts
        await this.handleFailedLogin(user, ipAddress, userAgent);
        throw new Error('Invalid credentials');
      }

      // Reset failed login attempts on successful login
      if (user.failedLoginAttempts > 0) {
        await this.userDAO.update(user.id, {
          failedLoginAttempts: 0,
          accountLockedUntil: null
        });
      }

      // Generate JWT token
      const { token, expiresAt } = JWTService.generateToken(user);

      // Create session record
      const session: Omit<UserSession, 'id' | 'createdAt' | 'lastAccessedAt'> = {
        userId: user.id,
        sessionToken: token,
        expiresAt,
        ipAddress: ipAddress || null,
        userAgent: userAgent || null,
      };

      await this.sessionDAO.create(session);

      // Store session in Redis for fast lookup
      await this.redisClient.setex(
        `session:${token}`,
        24 * 60 * 60, // 24 hours
        JSON.stringify({ userId: user.id, username: user.username })
      );

      // Update last login time
      await this.userDAO.update(user.id, {
        lastLoginAt: new Date()
      });

      // Log successful login
      await this.auditDAO.logAction({
        userId: user.id,
        username,
        action: 'login_success',
        ipAddress,
        userAgent,
      });

      return {
        success: true,
        user: this.toPublicUser(user),
        sessionToken: token,
        expiresAt,
      };

    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error('Login failed');
    }
  }

  /**
   * Handle failed login attempt
   */
  private async handleFailedLogin(
    user: User, 
    ipAddress?: string, 
    userAgent?: string
  ): Promise<void> {
    const newFailedAttempts = user.failedLoginAttempts + 1;
    const maxAttempts = 5;
    const lockoutDuration = 30 * 60 * 1000; // 30 minutes

    let accountLockedUntil = null;
    if (newFailedAttempts >= maxAttempts) {
      accountLockedUntil = new Date(Date.now() + lockoutDuration);
    }

    await this.userDAO.update(user.id, {
      failedLoginAttempts: newFailedAttempts,
      accountLockedUntil,
    });

    await this.auditDAO.logAction({
      userId: user.id,
      username: user.username,
      action: newFailedAttempts >= maxAttempts ? 'account_locked' : 'login_failed',
      ipAddress,
      userAgent,
      additionalInfo: { 
        failedAttempts: newFailedAttempts,
        lockedUntil: accountLockedUntil?.toISOString() 
      }
    });
  }

  /**
   * Logout user and invalidate session
   */
  async logout(sessionToken: string): Promise<void> {
    // Remove from Redis
    await this.redisClient.del(`session:${sessionToken}`);

    // Remove from database
    await this.sessionDAO.deleteByToken(sessionToken);

    // Log logout action
    const payload = JWTService.verifyToken(sessionToken);
    if (payload) {
      await this.auditDAO.logAction({
        userId: payload.userId,
        username: payload.username,
        action: 'logout',
      });
    }
  }

  /**
   * Validate session token
   */
  async validateSession(sessionToken: string): Promise<User | null> {
    // Check Redis first for performance
    const cachedSession = await this.redisClient.get(`session:${sessionToken}`);
    if (!cachedSession) {
      return null;
    }

    // Verify JWT token
    const payload = JWTService.verifyToken(sessionToken);
    if (!payload) {
      // Remove invalid token from Redis
      await this.redisClient.del(`session:${sessionToken}`);
      return null;
    }

    // Get current user data
    const user = await this.userDAO.findById(payload.userId);
    if (!user || !user.isActive) {
      // Remove session for inactive user
      await this.logout(sessionToken);
      return null;
    }

    return user;
  }

  /**
   * Convert User to PublicUser (remove sensitive data)
   */
  private toPublicUser(user: User): PublicUser {
    return {
      id: user.id,
      username: user.username,
      email: user.email,
      fullName: user.fullName,
      role: user.role,
      workspaceId: user.workspaceId,
      isActive: user.isActive,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.createdAt,
      createdBy: user.createdBy,
      lastUpdatedAt: user.lastUpdatedAt,
      lastUpdatedBy: user.lastUpdatedBy,
    };
  }
}
```

## API Endpoints

### Authentication Routes
```typescript
// POST /v1/enterprise/auth/login
export async function loginHandler(request: FastifyRequest, reply: FastifyReply) {
  const { username, password, workspaceId } = request.body as LoginRequest;
  const ipAddress = request.ip;
  const userAgent = request.headers['user-agent'];

  try {
    const result = await authService.login(
      username, 
      password, 
      workspaceId || 'default',
      ipAddress,
      userAgent
    );

    return reply.code(200).send(result);
  } catch (error) {
    return reply.code(401).send({
      success: false,
      error: error.message,
    });
  }
}

// POST /v1/enterprise/auth/logout
export async function logoutHandler(request: FastifyRequest, reply: FastifyReply) {
  const authHeader = request.headers.authorization;
  const token = JWTService.extractTokenFromHeader(authHeader);

  if (!token) {
    return reply.code(400).send({
      success: false,
      error: 'No token provided',
    });
  }

  try {
    await authService.logout(token);
    return reply.code(200).send({
      success: true,
      message: 'Logged out successfully',
    });
  } catch (error) {
    return reply.code(500).send({
      success: false,
      error: 'Logout failed',
    });
  }
}

// GET /v1/enterprise/auth/status
export async function statusHandler(request: FastifyRequest, reply: FastifyReply) {
  const authHeader = request.headers.authorization;
  const token = JWTService.extractTokenFromHeader(authHeader);

  if (!token) {
    return reply.code(401).send({
      success: false,
      error: 'No token provided',
    });
  }

  try {
    const user = await authService.validateSession(token);
    if (!user) {
      return reply.code(401).send({
        success: false,
        error: 'Invalid or expired token',
      });
    }

    return reply.code(200).send({
      success: true,
      user: authService.toPublicUser(user),
    });
  } catch (error) {
    return reply.code(500).send({
      success: false,
      error: 'Status check failed',
    });
  }
}
```

## Security Configuration

### Rate Limiting
```typescript
import rateLimit from '@fastify/rate-limit';

// Configure rate limiting for auth endpoints
const authRateLimit = {
  max: 5, // 5 attempts
  timeWindow: '15 minutes',
  errorResponseBuilder: () => ({
    error: 'Too many authentication attempts, please try again later',
    statusCode: 429,
  }),
};

fastify.register(rateLimit, {
  global: false, // Don't apply to all routes
});

// Apply to auth routes
fastify.register(async function (fastify) {
  await fastify.register(rateLimit, authRateLimit);
  
  fastify.post('/v1/enterprise/auth/login', loginHandler);
});
```

### Security Headers
```typescript
import helmet from '@fastify/helmet';

fastify.register(helmet, {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
});
```

## Testing Strategy

### Unit Tests
```typescript
describe('AuthService', () => {
  describe('login', () => {
    it('should successfully authenticate valid user', async () => {
      const result = await authService.login('admin', 'password');
      expect(result.success).toBe(true);
      expect(result.user.username).toBe('admin');
      expect(result.sessionToken).toBeDefined();
    });

    it('should reject invalid credentials', async () => {
      await expect(
        authService.login('admin', 'wrongpassword')
      ).rejects.toThrow('Invalid credentials');
    });

    it('should lock account after failed attempts', async () => {
      // Attempt login 5 times with wrong password
      for (let i = 0; i < 5; i++) {
        try {
          await authService.login('admin', 'wrongpassword');
        } catch (error) {
          // Expected to fail
        }
      }

      // 6th attempt should show account locked
      await expect(
        authService.login('admin', 'wrongpassword')
      ).rejects.toThrow('Account is locked');
    });
  });
});
```

This authentication specification provides a comprehensive guide for implementing secure, compatible authentication in SprintAgentLens while maintaining full compatibility with the existing OPIK Java backend.