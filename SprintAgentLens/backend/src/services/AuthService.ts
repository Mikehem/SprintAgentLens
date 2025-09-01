import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { prisma } from '@/config/database';
import { config } from '@/config/environment';
import { authLogger, logAuthEvent, logSecurityViolation } from '@/utils/logger';
import {
  AuthenticationResult,
  AuthContext,
  JwtPayload,
  LoginRequest,
  PasswordHashResult,
  PasswordValidationResult,
  PublicUserInfo,
  SessionInfo,
  UserRole,
  AuditEventType,
  CreateUserRequest,
  UpdateUserRequest,
  ChangePasswordRequest,
} from '@/types/auth';

/**
 * Enterprise Authentication Service
 * Maintains 100% compatibility with OPIK Java backend authentication logic
 * 
 * CRITICAL: Password verification uses concatenation (password + salt) before BCrypt
 * This matches the Java DatabaseAuthService.verifyPassword() method exactly
 */
export class AuthService {
  private static readonly SALT_ROUNDS = config.BCRYPT_ROUNDS;
  private static readonly JWT_SECRET = config.JWT_SECRET;
  private static readonly SESSION_EXPIRE_TIME = config.SESSION_EXPIRE_TIME;
  private static readonly LOCKOUT_ATTEMPTS = config.ACCOUNT_LOCKOUT_ATTEMPTS;
  private static readonly LOCKOUT_DURATION = config.ACCOUNT_LOCKOUT_DURATION * 1000; // Convert to ms

  /**
   * Hash password with salt - MAINTAINS JAVA COMPATIBILITY
   * Java logic: BCrypt.hashpw(password + salt, BCrypt.gensalt(12))
   */
  static async hashPassword(password: string, salt?: string): Promise<PasswordHashResult> {
    try {
      const passwordSalt = salt || this.generateSalt();
      
      // CRITICAL: Match Java logic - concatenate password + salt before hashing
      const combined = password + passwordSalt;
      const hash = await bcrypt.hash(combined, this.SALT_ROUNDS);
      
      authLogger.debug('Password hashed successfully with salt');
      
      return {
        hash,
        salt: passwordSalt,
      };
    } catch (error) {
      authLogger.error('Password hashing failed:', error);
      throw new Error('Password hashing failed');
    }
  }

  /**
   * Verify password - MAINTAINS JAVA COMPATIBILITY  
   * Java logic: BCrypt.checkpw(password + user.salt(), user.passwordHash())
   */
  static async verifyPassword(
    password: string,
    storedHash: string,
    salt: string,
    userId: string,
    context: AuthContext
  ): Promise<PasswordValidationResult> {
    try {
      // Get current user for failed attempt tracking
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
          failedLoginAttempts: true,
          accountLockedUntil: true,
          isActive: true,
        },
      });

      if (!user) {
        return { isValid: false };
      }

      // Check if account is currently locked
      const now = new Date();
      if (user.accountLockedUntil && user.accountLockedUntil > now) {
        logSecurityViolation(
          'login_attempt_on_locked_account',
          context.ipAddress || 'unknown',
          { userId, lockUntil: user.accountLockedUntil }
        );
        return { isValid: false };
      }

      // CRITICAL: Match Java logic - concatenate password + salt before verification
      const combined = password + salt;
      const isValid = await bcrypt.compare(combined, storedHash);

      if (isValid) {
        // Reset failed attempts on successful login
        if (user.failedLoginAttempts > 0 || user.accountLockedUntil) {
          await prisma.user.update({
            where: { id: userId },
            data: {
              failedLoginAttempts: 0,
              accountLockedUntil: null,
              lastLoginAt: now,
            },
          });

          if (user.accountLockedUntil) {
            await this.logAuditEvent(
              'account_unlocked',
              AuditEventType.ACCOUNT_UNLOCKED,
              userId,
              context,
              'Account automatically unlocked after successful login'
            );
          }
        } else {
          await prisma.user.update({
            where: { id: userId },
            data: { lastLoginAt: now },
          });
        }

        authLogger.info(`Password verification successful for user ${userId}`);
        return { isValid: true };
      } else {
        // Handle failed login attempt
        const newFailedAttempts = user.failedLoginAttempts + 1;
        const shouldLock = newFailedAttempts >= this.LOCKOUT_ATTEMPTS;
        
        const updateData: any = {
          failedLoginAttempts: newFailedAttempts,
        };

        if (shouldLock) {
          updateData.accountLockedUntil = new Date(now.getTime() + this.LOCKOUT_DURATION);
          
          authLogger.warn(`Account locked for user ${userId} after ${newFailedAttempts} failed attempts`);
          logSecurityViolation(
            'account_locked_failed_attempts',
            context.ipAddress || 'unknown',
            { userId, attempts: newFailedAttempts }
          );

          await this.logAuditEvent(
            'account_locked',
            AuditEventType.ACCOUNT_LOCKED,
            userId,
            context,
            `Account locked after ${newFailedAttempts} failed login attempts`
          );
        } else {
          authLogger.debug(`Failed login attempt ${newFailedAttempts}/${this.LOCKOUT_ATTEMPTS} for user ${userId}`);
        }

        await prisma.user.update({
          where: { id: userId },
          data: updateData,
        });

        await this.logAuditEvent(
          'login_failed',
          AuditEventType.LOGIN_FAILED,
          userId,
          context,
          `Login failed - invalid password (attempt ${newFailedAttempts})`
        );

        return {
          isValid: false,
          shouldLockAccount: shouldLock,
          attemptsRemaining: Math.max(0, this.LOCKOUT_ATTEMPTS - newFailedAttempts),
        };
      }
    } catch (error) {
      authLogger.error('Password verification error:', error);
      return { isValid: false };
    }
  }

  /**
   * Authenticate user with username/password
   */
  static async authenticate(
    loginRequest: LoginRequest,
    context: AuthContext
  ): Promise<AuthenticationResult> {
    try {
      authLogger.info(`Authentication attempt for user: ${loginRequest.username}`);

      // Find user by username
      const user = await prisma.user.findUnique({
        where: { username: loginRequest.username },
      });

      if (!user) {
        authLogger.warn(`Authentication failed - user not found: ${loginRequest.username}`);
        await this.logAuditEvent(
          'login_failed',
          AuditEventType.LOGIN_FAILED,
          null,
          context,
          `Login failed - user not found: ${loginRequest.username}`
        );
        return {
          success: false,
          reason: 'invalid_credentials',
          error: 'Invalid username or password',
        };
      }

      // Check if user is active
      if (!user.isActive) {
        authLogger.warn(`Authentication failed - account disabled: ${user.username}`);
        await this.logAuditEvent(
          'login_failed',
          AuditEventType.LOGIN_FAILED,
          user.id,
          context,
          'Login failed - account disabled'
        );
        return {
          success: false,
          reason: 'account_disabled',
          error: 'Account is disabled',
        };
      }

      // Verify password
      const passwordResult = await this.verifyPassword(
        loginRequest.password,
        user.passwordHash,
        user.salt,
        user.id,
        context
      );

      if (!passwordResult.isValid) {
        return {
          success: false,
          reason: passwordResult.shouldLockAccount ? 'account_locked' : 'invalid_credentials',
          error: passwordResult.shouldLockAccount 
            ? 'Account has been locked due to too many failed attempts'
            : 'Invalid username or password',
        };
      }

      // Create session
      const session = await this.createSession(user.id, context);
      
      // Generate JWT token
      const token = await this.generateJwtToken(user, session.id);

      // Convert to public user info
      const publicUser: PublicUserInfo = {
        id: user.id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        role: user.role as UserRole,
        workspaceId: user.workspaceId,
        isActive: user.isActive,
        lastLoginAt: user.lastLoginAt,
      };

      // Log successful authentication
      await this.logAuditEvent(
        'login_successful',
        AuditEventType.LOGIN,
        user.id,
        context,
        'User successfully authenticated'
      );

      logAuthEvent('login', user.id, {
        username: user.username,
        workspaceId: user.workspaceId,
        sessionId: session.id,
      });

      authLogger.info(`Authentication successful for user: ${user.username}`);

      return {
        success: true,
        user: publicUser,
        token,
        sessionId: session.id,
      };
    } catch (error) {
      authLogger.error('Authentication error:', error);
      return {
        success: false,
        reason: 'server_error',
        error: 'Authentication service error',
      };
    }
  }

  /**
   * Create user session
   */
  static async createSession(userId: string, context: AuthContext): Promise<SessionInfo> {
    try {
      const sessionId = uuidv4();
      const sessionToken = this.generateSessionToken();
      const expiresAt = new Date(Date.now() + (this.SESSION_EXPIRE_TIME * 1000));

      const session = await prisma.userSession.create({
        data: {
          id: sessionId,
          userId,
          sessionToken,
          ipAddress: context.ipAddress,
          userAgent: context.userAgent,
          expiresAt,
        },
      });

      authLogger.debug(`Session created for user ${userId}: ${sessionId}`);

      return {
        id: session.id,
        userId: session.userId,
        sessionToken: session.sessionToken,
        ipAddress: session.ipAddress,
        userAgent: session.userAgent,
        createdAt: session.createdAt,
        expiresAt: session.expiresAt,
        lastUsedAt: session.lastUsedAt,
      };
    } catch (error) {
      authLogger.error('Session creation failed:', error);
      throw new Error('Failed to create session');
    }
  }

  /**
   * Generate JWT token
   */
  static async generateJwtToken(user: any, sessionId: string): Promise<string> {
    try {
      const payload: JwtPayload = {
        userId: user.id,
        username: user.username,
        role: user.role as UserRole,
        workspaceId: user.workspaceId,
        sessionId,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor((Date.now() + (this.SESSION_EXPIRE_TIME * 1000)) / 1000),
      };

      const token = jwt.sign(payload, this.JWT_SECRET, {
        expiresIn: config.JWT_EXPIRE_TIME,
      });

      authLogger.debug(`JWT token generated for user ${user.id}`);
      return token;
    } catch (error) {
      authLogger.error('JWT generation failed:', error);
      throw new Error('Failed to generate token');
    }
  }

  /**
   * Verify JWT token and get user info
   */
  static async verifyToken(token: string): Promise<AuthenticationResult> {
    try {
      const decoded = jwt.verify(token, this.JWT_SECRET) as JwtPayload;
      
      // Verify session is still valid
      const session = await prisma.userSession.findUnique({
        where: { id: decoded.sessionId },
        include: { user: true },
      });

      if (!session || session.expiresAt < new Date()) {
        return {
          success: false,
          reason: 'invalid_credentials',
          error: 'Session expired or invalid',
        };
      }

      if (!session.user.isActive) {
        return {
          success: false,
          reason: 'account_disabled', 
          error: 'Account is disabled',
        };
      }

      // Update session last used time
      await prisma.userSession.update({
        where: { id: session.id },
        data: { lastUsedAt: new Date() },
      });

      const publicUser: PublicUserInfo = {
        id: session.user.id,
        username: session.user.username,
        email: session.user.email,
        fullName: session.user.fullName,
        role: session.user.role as UserRole,
        workspaceId: session.user.workspaceId,
        isActive: session.user.isActive,
        lastLoginAt: session.user.lastLoginAt,
      };

      return {
        success: true,
        user: publicUser,
        token,
        sessionId: session.id,
      };
    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        return {
          success: false,
          reason: 'invalid_credentials',
          error: 'Invalid token',
        };
      }
      
      authLogger.error('Token verification error:', error);
      return {
        success: false,
        reason: 'server_error',
        error: 'Token verification failed',
      };
    }
  }

  /**
   * Logout user and invalidate session
   */
  static async logout(sessionId: string, context: AuthContext): Promise<boolean> {
    try {
      const session = await prisma.userSession.findUnique({
        where: { id: sessionId },
        include: { user: true },
      });

      if (session) {
        await prisma.userSession.delete({
          where: { id: sessionId },
        });

        await this.logAuditEvent(
          'logout',
          AuditEventType.LOGOUT,
          session.userId,
          context,
          'User logged out'
        );

        logAuthEvent('logout', session.userId, {
          username: session.user.username,
          sessionId,
        });

        authLogger.info(`User ${session.user.username} logged out`);
      }

      return true;
    } catch (error) {
      authLogger.error('Logout error:', error);
      return false;
    }
  }

  /**
   * Create new user (admin only)
   */
  static async createUser(
    request: CreateUserRequest,
    creatorId: string,
    context: AuthContext
  ): Promise<PublicUserInfo> {
    try {
      // Check if username or email already exists
      const existing = await prisma.user.findFirst({
        where: {
          OR: [
            { username: request.username },
            { email: request.email },
          ],
        },
      });

      if (existing) {
        throw new Error('Username or email already exists');
      }

      // Hash password
      const { hash, salt } = await this.hashPassword(request.password);

      // Create user
      const user = await prisma.user.create({
        data: {
          username: request.username,
          email: request.email,
          fullName: request.fullName || null,
          passwordHash: hash,
          salt,
          role: request.role || UserRole.USER,
          workspaceId: request.workspaceId || 'default',
          createdBy: creatorId,
        },
      });

      await this.logAuditEvent(
        'user_created',
        AuditEventType.USER_CREATED,
        user.id,
        context,
        `User created by ${creatorId}`
      );

      authLogger.info(`User created: ${user.username} by ${creatorId}`);

      return {
        id: user.id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        role: user.role as UserRole,
        workspaceId: user.workspaceId,
        isActive: user.isActive,
        lastLoginAt: user.lastLoginAt,
      };
    } catch (error) {
      authLogger.error('User creation failed:', error);
      throw error;
    }
  }

  /**
   * Generate secure salt
   */
  private static generateSalt(): string {
    return randomBytes(32).toString('hex');
  }

  /**
   * Generate session token
   */
  private static generateSessionToken(): string {
    return randomBytes(64).toString('hex');
  }

  /**
   * Log audit events
   */
  private static async logAuditEvent(
    event: string,
    eventType: AuditEventType,
    userId: string | null,
    context: AuthContext,
    description?: string,
    metadata?: Record<string, any>
  ): Promise<void> {
    try {
      await prisma.userAuditLog.create({
        data: {
          event,
          eventType,
          userId,
          ipAddress: context.ipAddress,
          userAgent: context.userAgent,
          requestId: context.requestId,
          description,
          metadata: metadata || {},
        },
      });
    } catch (error) {
      authLogger.error('Audit logging failed:', error);
    }
  }

  /**
   * Clean up expired sessions
   */
  static async cleanupExpiredSessions(): Promise<number> {
    try {
      const result = await prisma.userSession.deleteMany({
        where: {
          expiresAt: {
            lt: new Date(),
          },
        },
      });

      if (result.count > 0) {
        authLogger.info(`Cleaned up ${result.count} expired sessions`);
      }

      return result.count;
    } catch (error) {
      authLogger.error('Session cleanup failed:', error);
      return 0;
    }
  }
}