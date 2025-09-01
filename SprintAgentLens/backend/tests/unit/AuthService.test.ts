/**
 * AuthService Unit Tests
 * Tests the core authentication service functionality
 */

import { PrismaClient } from '@prisma/client';
import { AuthService } from '@/services/AuthService';
import { UserRole, AuthContext } from '@/types/auth';
import bcrypt from 'bcryptjs';

// Test database client
const prisma = new PrismaClient({
  datasources: {
    db: {
      url: 'mysql://root:@localhost:3306/sprintagentlens_test',
    },
  },
});

describe('AuthService', () => {
  beforeAll(async () => {
    // Clean test database before running tests
    await prisma.userAuditLog.deleteMany();
    await prisma.userSession.deleteMany();
    await prisma.user.deleteMany();
  });

  afterAll(async () => {
    // Clean up after tests
    await prisma.userAuditLog.deleteMany();
    await prisma.userSession.deleteMany();
    await prisma.user.deleteMany();
    await prisma.$disconnect();
  });

  beforeEach(async () => {
    // Clean test data before each test
    await prisma.userAuditLog.deleteMany();
    await prisma.userSession.deleteMany();
    await prisma.user.deleteMany();
  });

  describe('Password Hashing', () => {
    it('should hash password with salt correctly', async () => {
      const password = 'TestPassword123!';
      const result = await AuthService.hashPassword(password);

      expect(result).toHaveProperty('hash');
      expect(result).toHaveProperty('salt');
      expect(result.hash).toBeDefined();
      expect(result.salt).toBeDefined();
      expect(result.hash).not.toBe(password);
      expect(result.salt).toHaveLength(64); // 32 bytes = 64 hex chars
    });

    it('should use provided salt when given', async () => {
      const password = 'TestPassword123!';
      const customSalt = 'custom-test-salt';
      
      const result = await AuthService.hashPassword(password, customSalt);
      
      expect(result.salt).toBe(customSalt);
    });

    it('should create compatible BCrypt hash (password + salt)', async () => {
      const password = 'TestPassword123!';
      const salt = 'test-salt';
      
      const result = await AuthService.hashPassword(password, salt);
      
      // Verify the hash was created using password + salt combination
      const combined = password + salt;
      const isValid = await bcrypt.compare(combined, result.hash);
      expect(isValid).toBe(true);
    });
  });

  describe('User Authentication', () => {
    let testUser: any;
    const testPassword = 'TestPassword123!';

    beforeEach(async () => {
      // Create test user for authentication tests
      const { hash, salt } = await AuthService.hashPassword(testPassword);
      
      testUser = await prisma.user.create({
        data: {
          username: 'testuser',
          email: 'test@example.com',
          fullName: 'Test User',
          passwordHash: hash,
          salt: salt,
          role: UserRole.USER,
          workspaceId: 'default',
          isActive: true,
          createdBy: 'system',
        },
      });
    });

    it('should authenticate user with correct credentials', async () => {
      const loginRequest = {
        username: 'testuser',
        password: testPassword,
        workspaceId: 'default',
      };

      const authContext: AuthContext = {
        ipAddress: '127.0.0.1',
        userAgent: 'Jest Test',
        requestId: 'test-request',
        timestamp: new Date(),
      };

      const result = await AuthService.authenticate(loginRequest, authContext);

      expect(result.success).toBe(true);
      expect(result.user).toBeDefined();
      expect(result.token).toBeDefined();
      expect(result.sessionId).toBeDefined();
      expect(result.user?.username).toBe('testuser');
      expect(result.user?.email).toBe('test@example.com');
      expect(result.token).toBeValidJWT();
      expect(result.sessionId).toBeValidUUID();
    });

    it('should fail authentication with incorrect password', async () => {
      const loginRequest = {
        username: 'testuser',
        password: 'WrongPassword123!',
        workspaceId: 'default',
      };

      const authContext: AuthContext = {
        ipAddress: '127.0.0.1',
        userAgent: 'Jest Test',
        requestId: 'test-request',
        timestamp: new Date(),
      };

      const result = await AuthService.authenticate(loginRequest, authContext);

      expect(result.success).toBe(false);
      expect(result.reason).toBe('invalid_credentials');
      expect(result.error).toBe('Invalid username or password');
      expect(result.user).toBeUndefined();
      expect(result.token).toBeUndefined();
    });

    it('should fail authentication with non-existent user', async () => {
      const loginRequest = {
        username: 'nonexistentuser',
        password: testPassword,
        workspaceId: 'default',
      };

      const authContext: AuthContext = {
        ipAddress: '127.0.0.1',
        userAgent: 'Jest Test', 
        requestId: 'test-request',
        timestamp: new Date(),
      };

      const result = await AuthService.authenticate(loginRequest, authContext);

      expect(result.success).toBe(false);
      expect(result.reason).toBe('invalid_credentials');
      expect(result.error).toBe('Invalid username or password');
    });

    it('should fail authentication for inactive user', async () => {
      // Deactivate user
      await prisma.user.update({
        where: { id: testUser.id },
        data: { isActive: false },
      });

      const loginRequest = {
        username: 'testuser',
        password: testPassword,
        workspaceId: 'default',
      };

      const authContext: AuthContext = {
        ipAddress: '127.0.0.1',
        userAgent: 'Jest Test',
        requestId: 'test-request',
        timestamp: new Date(),
      };

      const result = await AuthService.authenticate(loginRequest, authContext);

      expect(result.success).toBe(false);
      expect(result.reason).toBe('account_disabled');
      expect(result.error).toBe('Account is disabled');
    });

    it('should track failed login attempts', async () => {
      const loginRequest = {
        username: 'testuser',
        password: 'WrongPassword123!',
        workspaceId: 'default',
      };

      const authContext: AuthContext = {
        ipAddress: '127.0.0.1',
        userAgent: 'Jest Test',
        requestId: 'test-request',
        timestamp: new Date(),
      };

      // First failed attempt
      await AuthService.authenticate(loginRequest, authContext);
      
      let user = await prisma.user.findUnique({
        where: { id: testUser.id },
      });
      
      expect(user?.failedLoginAttempts).toBe(1);

      // Second failed attempt
      await AuthService.authenticate(loginRequest, authContext);
      
      user = await prisma.user.findUnique({
        where: { id: testUser.id },
      });
      
      expect(user?.failedLoginAttempts).toBe(2);
    });

    it('should lock account after max failed attempts', async () => {
      const loginRequest = {
        username: 'testuser',
        password: 'WrongPassword123!',
        workspaceId: 'default',
      };

      const authContext: AuthContext = {
        ipAddress: '127.0.0.1',
        userAgent: 'Jest Test',
        requestId: 'test-request',
        timestamp: new Date(),
      };

      // Simulate 5 failed attempts (default lockout threshold)
      for (let i = 0; i < 5; i++) {
        await AuthService.authenticate(loginRequest, authContext);
      }

      const user = await prisma.user.findUnique({
        where: { id: testUser.id },
      });

      expect(user?.failedLoginAttempts).toBe(5);
      expect(user?.accountLockedUntil).toBeDefined();
      expect(user?.accountLockedUntil!.getTime()).toBeGreaterThan(Date.now());
    });

    it('should reset failed attempts on successful login', async () => {
      // Set some failed attempts
      await prisma.user.update({
        where: { id: testUser.id },
        data: { failedLoginAttempts: 3 },
      });

      const loginRequest = {
        username: 'testuser',
        password: testPassword,
        workspaceId: 'default',
      };

      const authContext: AuthContext = {
        ipAddress: '127.0.0.1',
        userAgent: 'Jest Test',
        requestId: 'test-request',
        timestamp: new Date(),
      };

      const result = await AuthService.authenticate(loginRequest, authContext);

      expect(result.success).toBe(true);

      const user = await prisma.user.findUnique({
        where: { id: testUser.id },
      });

      expect(user?.failedLoginAttempts).toBe(0);
      expect(user?.lastLoginAt).toBeDefined();
    });
  });

  describe('Token Management', () => {
    let testUser: any;
    let sessionId: string;

    beforeEach(async () => {
      const { hash, salt } = await AuthService.hashPassword('TestPassword123!');
      
      testUser = await prisma.user.create({
        data: {
          username: 'tokenuser',
          email: 'token@example.com',
          fullName: 'Token Test User',
          passwordHash: hash,
          salt: salt,
          role: UserRole.USER,
          workspaceId: 'default',
          isActive: true,
          createdBy: 'system',
        },
      });

      // Create a session
      const authContext: AuthContext = {
        ipAddress: '127.0.0.1',
        userAgent: 'Jest Test',
        requestId: 'test-request',
        timestamp: new Date(),
      };

      const session = await AuthService.createSession(testUser.id, authContext);
      sessionId = session.id;
    });

    it('should generate valid JWT token', async () => {
      const token = await AuthService.generateJwtToken(testUser, sessionId);
      
      expect(token).toBeValidJWT();
      expect(token.split('.')).toHaveLength(3); // JWT has 3 parts
    });

    it('should verify valid token', async () => {
      const token = await AuthService.generateJwtToken(testUser, sessionId);
      
      const result = await AuthService.verifyToken(token);
      
      expect(result.success).toBe(true);
      expect(result.user).toBeDefined();
      expect(result.user?.id).toBe(testUser.id);
      expect(result.user?.username).toBe('tokenuser');
      expect(result.sessionId).toBe(sessionId);
    });

    it('should reject invalid token', async () => {
      const invalidToken = 'invalid.jwt.token';
      
      const result = await AuthService.verifyToken(invalidToken);
      
      expect(result.success).toBe(false);
      expect(result.reason).toBe('invalid_credentials');
      expect(result.error).toBe('Invalid token');
    });

    it('should reject token for expired session', async () => {
      // Expire the session
      await prisma.userSession.update({
        where: { id: sessionId },
        data: { expiresAt: new Date(Date.now() - 1000) }, // 1 second ago
      });

      const token = await AuthService.generateJwtToken(testUser, sessionId);
      
      const result = await AuthService.verifyToken(token);
      
      expect(result.success).toBe(false);
      expect(result.reason).toBe('invalid_credentials');
      expect(result.error).toBe('Session expired or invalid');
    });
  });

  describe('Session Management', () => {
    let testUser: any;

    beforeEach(async () => {
      const { hash, salt } = await AuthService.hashPassword('TestPassword123!');
      
      testUser = await prisma.user.create({
        data: {
          username: 'sessionuser',
          email: 'session@example.com',
          fullName: 'Session Test User',
          passwordHash: hash,
          salt: salt,
          role: UserRole.USER,
          workspaceId: 'default',
          isActive: true,
          createdBy: 'system',
        },
      });
    });

    it('should create session successfully', async () => {
      const authContext: AuthContext = {
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0 Test Browser',
        requestId: 'test-session-request',
        timestamp: new Date(),
      };

      const session = await AuthService.createSession(testUser.id, authContext);

      expect(session.id).toBeValidUUID();
      expect(session.userId).toBe(testUser.id);
      expect(session.sessionToken).toBeDefined();
      expect(session.sessionToken).toHaveLength(128); // 64 bytes = 128 hex chars
      expect(session.ipAddress).toBe('192.168.1.1');
      expect(session.userAgent).toBe('Mozilla/5.0 Test Browser');
      expect(session.expiresAt.getTime()).toBeGreaterThan(Date.now());
    });

    it('should logout and invalidate session', async () => {
      const authContext: AuthContext = {
        ipAddress: '127.0.0.1',
        userAgent: 'Jest Test',
        requestId: 'test-request',
        timestamp: new Date(),
      };

      const session = await AuthService.createSession(testUser.id, authContext);
      
      const result = await AuthService.logout(session.id, authContext);
      
      expect(result).toBe(true);

      // Verify session is deleted
      const deletedSession = await prisma.userSession.findUnique({
        where: { id: session.id },
      });
      
      expect(deletedSession).toBeNull();
    });

    it('should handle logout of non-existent session gracefully', async () => {
      const authContext: AuthContext = {
        ipAddress: '127.0.0.1',
        userAgent: 'Jest Test',
        requestId: 'test-request',
        timestamp: new Date(),
      };

      const result = await AuthService.logout('non-existent-session-id', authContext);
      
      expect(result).toBe(true); // Should not throw error
    });

    it('should clean up expired sessions', async () => {
      const authContext: AuthContext = {
        ipAddress: '127.0.0.1',
        userAgent: 'Jest Test',
        requestId: 'test-request',
        timestamp: new Date(),
      };

      // Create expired session
      const expiredSession = await AuthService.createSession(testUser.id, authContext);
      await prisma.userSession.update({
        where: { id: expiredSession.id },
        data: { expiresAt: new Date(Date.now() - 1000) }, // 1 second ago
      });

      // Create valid session
      const validSession = await AuthService.createSession(testUser.id, authContext);

      const cleanedCount = await AuthService.cleanupExpiredSessions();

      expect(cleanedCount).toBe(1);

      // Verify expired session is gone, valid session remains
      const expiredCheck = await prisma.userSession.findUnique({
        where: { id: expiredSession.id },
      });
      const validCheck = await prisma.userSession.findUnique({
        where: { id: validSession.id },
      });

      expect(expiredCheck).toBeNull();
      expect(validCheck).not.toBeNull();
    });
  });

  describe('User Creation', () => {
    let adminUser: any;

    beforeEach(async () => {
      const { hash, salt } = await AuthService.hashPassword('AdminPassword123!');
      
      adminUser = await prisma.user.create({
        data: {
          username: 'admin',
          email: 'admin@example.com',
          fullName: 'Admin User',
          passwordHash: hash,
          salt: salt,
          role: UserRole.ADMIN,
          workspaceId: 'default',
          isActive: true,
          createdBy: 'system',
        },
      });
    });

    it('should create user successfully', async () => {
      const createRequest = {
        username: 'newuser',
        email: 'newuser@example.com',
        fullName: 'New User',
        password: 'NewUserPassword123!',
        role: UserRole.USER,
        workspaceId: 'default',
      };

      const authContext: AuthContext = {
        ipAddress: '127.0.0.1',
        userAgent: 'Jest Test',
        requestId: 'test-request',
        timestamp: new Date(),
      };

      const newUser = await AuthService.createUser(
        createRequest,
        adminUser.id,
        authContext
      );

      expect(newUser.id).toBeValidUUID();
      expect(newUser.username).toBe('newuser');
      expect(newUser.email).toBeValidEmail();
      expect(newUser.email).toBe('newuser@example.com');
      expect(newUser.fullName).toBe('New User');
      expect(newUser.role).toBe(UserRole.USER);
      expect(newUser.workspaceId).toBe('default');
      expect(newUser.isActive).toBe(true);

      // Verify user can authenticate
      const loginResult = await AuthService.authenticate({
        username: 'newuser',
        password: 'NewUserPassword123!',
        workspaceId: 'default',
      }, authContext);

      expect(loginResult.success).toBe(true);
    });

    it('should reject user creation with duplicate username', async () => {
      const createRequest = {
        username: 'admin', // Already exists
        email: 'different@example.com',
        password: 'Password123!',
      };

      const authContext: AuthContext = {
        ipAddress: '127.0.0.1',
        userAgent: 'Jest Test',
        requestId: 'test-request',
        timestamp: new Date(),
      };

      await expect(
        AuthService.createUser(createRequest, adminUser.id, authContext)
      ).rejects.toThrow('Username or email already exists');
    });

    it('should reject user creation with duplicate email', async () => {
      const createRequest = {
        username: 'differentuser',
        email: 'admin@example.com', // Already exists
        password: 'Password123!',
      };

      const authContext: AuthContext = {
        ipAddress: '127.0.0.1',
        userAgent: 'Jest Test',
        requestId: 'test-request',
        timestamp: new Date(),
      };

      await expect(
        AuthService.createUser(createRequest, adminUser.id, authContext)
      ).rejects.toThrow('Username or email already exists');
    });
  });
});