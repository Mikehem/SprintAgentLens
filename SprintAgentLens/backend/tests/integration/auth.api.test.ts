/**
 * Authentication API Integration Tests
 * Tests the authentication endpoints with full HTTP requests
 */

import { FastifyInstance } from 'fastify';
import { PrismaClient } from '@prisma/client';
import supertest from 'supertest';
import { server } from '@/server';
import { AuthService } from '@/services/AuthService';
import { UserRole } from '@/types/auth';

// Test database client
const prisma = new PrismaClient({
  datasources: {
    db: {
      url: 'mysql://root:@localhost:3306/sprintagentlens_test',
    },
  },
});

describe('Authentication API Integration Tests', () => {
  let app: FastifyInstance;
  let request: supertest.SuperTest<supertest.Test>;

  beforeAll(async () => {
    // Start test server
    app = server;
    await app.ready();
    request = supertest(app.server);

    // Clean test database
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
    await app.close();
  });

  beforeEach(async () => {
    // Clean test data before each test
    await prisma.userAuditLog.deleteMany();
    await prisma.userSession.deleteMany();
    await prisma.user.deleteMany();
  });

  describe('POST /v1/enterprise/auth/login', () => {
    let testUser: any;
    const testPassword = 'TestPassword123!';

    beforeEach(async () => {
      // Create test user for each test
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

    it('should login successfully with valid credentials', async () => {
      const response = await request
        .post('/v1/enterprise/auth/login')
        .send({
          username: 'testuser',
          password: testPassword,
          workspaceId: 'default',
        })
        .expect(200);

      expect(response.body).toMatchObject({
        success: true,
        token: expect.any(String),
        user: {
          id: testUser.id,
          username: 'testuser',
          email: 'test@example.com',
          fullName: 'Test User',
          role: 'USER',
          workspaceId: 'default',
          isActive: true,
        },
        expiresIn: expect.any(Number),
        workspaceId: 'default',
      });

      expect(response.body.token).toBeValidJWT();
      expect(response.headers['set-cookie']).toBeDefined();
    });

    it('should fail login with invalid credentials', async () => {
      const response = await request
        .post('/v1/enterprise/auth/login')
        .send({
          username: 'testuser',
          password: 'WrongPassword123!',
        })
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        error: 'Invalid username or password',
        code: 'INVALID_CREDENTIALS',
        timestamp: expect.any(String),
      });
    });

    it('should fail login with non-existent user', async () => {
      const response = await request
        .post('/v1/enterprise/auth/login')
        .send({
          username: 'nonexistentuser',
          password: testPassword,
        })
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        error: 'Invalid username or password',
        code: 'INVALID_CREDENTIALS',
      });
    });

    it('should fail login with invalid request data', async () => {
      const response = await request
        .post('/v1/enterprise/auth/login')
        .send({
          username: 'ab', // Too short
          password: '123', // Too short
        })
        .expect(400);

      expect(response.body).toMatchObject({
        success: false,
        error: 'Invalid request data',
        code: 'VALIDATION_ERROR',
        details: expect.any(Array),
      });
    });

    it('should fail login for inactive user', async () => {
      // Deactivate user
      await prisma.user.update({
        where: { id: testUser.id },
        data: { isActive: false },
      });

      const response = await request
        .post('/v1/enterprise/auth/login')
        .send({
          username: 'testuser',
          password: testPassword,
        })
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        error: 'Account is disabled',
        code: 'ACCOUNT_DISABLED',
      });
    });

    it('should lock account after multiple failed attempts', async () => {
      // Attempt login 5 times with wrong password
      for (let i = 0; i < 5; i++) {
        await request
          .post('/v1/enterprise/auth/login')
          .send({
            username: 'testuser',
            password: 'WrongPassword123!',
          })
          .expect(401);
      }

      // 6th attempt should return account locked
      const response = await request
        .post('/v1/enterprise/auth/login')
        .send({
          username: 'testuser',
          password: 'WrongPassword123!',
        })
        .expect(401);

      expect(response.body.code).toBe('ACCOUNT_LOCKED');

      // Even correct password should fail on locked account
      const lockedResponse = await request
        .post('/v1/enterprise/auth/login')
        .send({
          username: 'testuser',
          password: testPassword,
        })
        .expect(401);

      expect(lockedResponse.body.code).toBe('INVALID_CREDENTIALS');
    });
  });

  describe('GET /v1/enterprise/auth/status', () => {
    let testUser: any;
    let authToken: string;

    beforeEach(async () => {
      // Create and authenticate test user
      const { hash, salt } = await AuthService.hashPassword('TestPassword123!');
      
      testUser = await prisma.user.create({
        data: {
          username: 'statususer',
          email: 'status@example.com',
          fullName: 'Status Test User',
          passwordHash: hash,
          salt: salt,
          role: UserRole.USER,
          workspaceId: 'default',
          isActive: true,
          createdBy: 'system',
        },
      });

      // Get auth token
      const loginResponse = await request
        .post('/v1/enterprise/auth/login')
        .send({
          username: 'statususer',
          password: 'TestPassword123!',
        });

      authToken = loginResponse.body.token;
    });

    it('should return user status with valid token', async () => {
      const response = await request
        .get('/v1/enterprise/auth/status')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body).toMatchObject({
        success: true,
        authenticated: true,
        user: {
          id: testUser.id,
          username: 'statususer',
          email: 'status@example.com',
          fullName: 'Status Test User',
          role: 'USER',
          workspaceId: 'default',
          isActive: true,
        },
        sessionId: expect.any(String),
        permissions: expect.any(Array),
        timestamp: expect.any(String),
      });

      expect(response.body.sessionId).toBeValidUUID();
      expect(response.body.permissions).toContain('projects:read');
    });

    it('should fail status check without token', async () => {
      const response = await request
        .get('/v1/enterprise/auth/status')
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        error: 'Authentication token required',
        code: 'MISSING_TOKEN',
      });
    });

    it('should fail status check with invalid token', async () => {
      const response = await request
        .get('/v1/enterprise/auth/status')
        .set('Authorization', 'Bearer invalid.jwt.token')
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        error: 'Invalid token',
        code: 'INVALID_TOKEN',
      });
    });
  });

  describe('POST /v1/enterprise/auth/logout', () => {
    let testUser: any;
    let authToken: string;

    beforeEach(async () => {
      // Create and authenticate test user
      const { hash, salt } = await AuthService.hashPassword('TestPassword123!');
      
      testUser = await prisma.user.create({
        data: {
          username: 'logoutuser',
          email: 'logout@example.com',
          fullName: 'Logout Test User',
          passwordHash: hash,
          salt: salt,
          role: UserRole.USER,
          workspaceId: 'default',
          isActive: true,
          createdBy: 'system',
        },
      });

      // Get auth token
      const loginResponse = await request
        .post('/v1/enterprise/auth/login')
        .send({
          username: 'logoutuser',
          password: 'TestPassword123!',
        });

      authToken = loginResponse.body.token;
    });

    it('should logout successfully with valid token', async () => {
      const response = await request
        .post('/v1/enterprise/auth/logout')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body).toMatchObject({
        success: true,
        message: 'Successfully logged out',
        timestamp: expect.any(String),
      });

      // Verify session is invalidated - status check should fail
      const statusResponse = await request
        .get('/v1/enterprise/auth/status')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(401);

      expect(statusResponse.body.error).toBe('Session expired or invalid');
    });

    it('should fail logout without token', async () => {
      const response = await request
        .post('/v1/enterprise/auth/logout')
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        error: 'Authentication token required',
        code: 'MISSING_TOKEN',
      });
    });
  });

  describe('POST /v1/enterprise/auth/create-user', () => {
    let adminUser: any;
    let adminToken: string;

    beforeEach(async () => {
      // Create admin user
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

      // Get admin token
      const loginResponse = await request
        .post('/v1/enterprise/auth/login')
        .send({
          username: 'admin',
          password: 'AdminPassword123!',
        });

      adminToken = loginResponse.body.token;
    });

    it('should create user successfully with admin privileges', async () => {
      const response = await request
        .post('/v1/enterprise/auth/create-user')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          username: 'newuser',
          email: 'newuser@example.com',
          fullName: 'New User',
          password: 'NewUserPassword123!',
          role: 'USER',
        })
        .expect(201);

      expect(response.body).toMatchObject({
        success: true,
        user: {
          id: expect.any(String),
          username: 'newuser',
          email: 'newuser@example.com',
          fullName: 'New User',
          role: 'USER',
          workspaceId: 'default',
          isActive: true,
        },
        timestamp: expect.any(String),
      });

      expect(response.body.user.id).toBeValidUUID();

      // Verify new user can login
      const loginResponse = await request
        .post('/v1/enterprise/auth/login')
        .send({
          username: 'newuser',
          password: 'NewUserPassword123!',
        })
        .expect(200);

      expect(loginResponse.body.success).toBe(true);
    });

    it('should fail user creation without admin privileges', async () => {
      // Create regular user
      const { hash, salt } = await AuthService.hashPassword('UserPassword123!');
      
      const regularUser = await prisma.user.create({
        data: {
          username: 'regularuser',
          email: 'regular@example.com',
          fullName: 'Regular User',
          passwordHash: hash,
          salt: salt,
          role: UserRole.USER,
          workspaceId: 'default',
          isActive: true,
          createdBy: adminUser.id,
        },
      });

      const userLoginResponse = await request
        .post('/v1/enterprise/auth/login')
        .send({
          username: 'regularuser',
          password: 'UserPassword123!',
        });

      const userToken = userLoginResponse.body.token;

      const response = await request
        .post('/v1/enterprise/auth/create-user')
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          username: 'unauthorizeduser',
          email: 'unauthorized@example.com',
          password: 'Password123!',
        })
        .expect(403);

      expect(response.body).toMatchObject({
        success: false,
        error: 'Insufficient permissions',
        code: 'INSUFFICIENT_PERMISSIONS',
      });
    });

    it('should fail user creation with duplicate username', async () => {
      const response = await request
        .post('/v1/enterprise/auth/create-user')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          username: 'admin', // Already exists
          email: 'different@example.com',
          password: 'Password123!',
        })
        .expect(409);

      expect(response.body).toMatchObject({
        success: false,
        error: 'Username or email already exists',
        code: 'USER_EXISTS',
      });
    });
  });

  describe('Rate Limiting', () => {
    it('should enforce rate limiting on login attempts', async () => {
      // Create user for testing rate limiting
      const { hash, salt } = await AuthService.hashPassword('TestPassword123!');
      
      await prisma.user.create({
        data: {
          username: 'rateuser',
          email: 'rate@example.com',
          fullName: 'Rate Test User',
          passwordHash: hash,
          salt: salt,
          role: UserRole.USER,
          workspaceId: 'default',
          isActive: true,
          createdBy: 'system',
        },
      });

      // Make multiple rapid requests to trigger rate limiting
      const requests = [];
      for (let i = 0; i < 110; i++) { // Exceed default rate limit of 100
        requests.push(
          request
            .post('/v1/enterprise/auth/login')
            .send({
              username: 'rateuser',
              password: 'WrongPassword123!',
            })
        );
      }

      const responses = await Promise.all(requests);
      
      // Some responses should be rate limited (429)
      const rateLimited = responses.filter(res => res.status === 429);
      expect(rateLimited.length).toBeGreaterThan(0);

      if (rateLimited.length > 0) {
        expect(rateLimited[0].body).toMatchObject({
          error: 'Rate limit exceeded',
          expiresIn: expect.any(Number),
        });
      }
    });
  });

  describe('CORS Headers', () => {
    it('should include proper CORS headers', async () => {
      const response = await request
        .options('/v1/enterprise/auth/login')
        .set('Origin', 'http://localhost:3000')
        .expect(204);

      expect(response.headers['access-control-allow-origin']).toBeDefined();
      expect(response.headers['access-control-allow-methods']).toContain('POST');
      expect(response.headers['access-control-allow-headers']).toContain('Authorization');
    });
  });

  describe('Security Headers', () => {
    it('should include security headers in responses', async () => {
      const response = await request
        .get('/health')
        .expect(200);

      expect(response.headers['x-frame-options']).toBeDefined();
      expect(response.headers['x-content-type-options']).toBeDefined();
      expect(response.headers['x-xss-protection']).toBeDefined();
    });
  });
});