/**
 * ProjectService Unit Tests
 * Tests project service functionality with authentication integration
 */

import { PrismaClient } from '@prisma/client';
import { ProjectService } from '@/services/ProjectService';
import { AuthService } from '@/services/AuthService';
import { UserRole, AuthenticatedUser } from '@/types/auth';
import {
  CreateProjectRequest,
  UpdateProjectRequest,
  ProjectNotFoundError,
  ProjectPermissionError,
  ProjectValidationError,
  WorkspaceAccessError,
} from '@/types/projects';

// Test database client
const prisma = new PrismaClient({
  datasources: {
    db: {
      url: 'mysql://root:@localhost:3306/sprintagentlens_test',
    },
  },
});

describe('ProjectService', () => {
  let adminUser: AuthenticatedUser;
  let regularUser: AuthenticatedUser;
  let viewerUser: AuthenticatedUser;
  let otherWorkspaceUser: AuthenticatedUser;

  beforeAll(async () => {
    // Clean test database
    await prisma.userAuditLog.deleteMany();
    await prisma.userSession.deleteMany();
    await prisma.project.deleteMany();
    await prisma.user.deleteMany();

    // Create test users
    const { hash, salt } = await AuthService.hashPassword('TestPassword123!');

    // Admin user
    const admin = await prisma.user.create({
      data: {
        id: 'admin-test-id',
        username: 'admin',
        email: 'admin@test.com',
        fullName: 'Admin User',
        passwordHash: hash,
        salt: salt,
        role: UserRole.ADMIN,
        workspaceId: 'default',
        isActive: true,
        createdBy: 'system',
      },
    });

    adminUser = {
      id: admin.id,
      username: admin.username,
      email: admin.email,
      fullName: admin.fullName,
      role: admin.role as UserRole,
      workspaceId: admin.workspaceId,
      isActive: admin.isActive,
      lastLoginAt: admin.lastLoginAt,
      sessionId: 'admin-session',
      permissions: [
        'projects:create', 'projects:read', 'projects:update', 'projects:delete',
        'datasets:create', 'experiments:create', 'system:admin'
      ],
    };

    // Regular user
    const regular = await prisma.user.create({
      data: {
        id: 'user-test-id',
        username: 'regularuser',
        email: 'user@test.com',
        fullName: 'Regular User',
        passwordHash: hash,
        salt: salt,
        role: UserRole.USER,
        workspaceId: 'default',
        isActive: true,
        createdBy: admin.id,
      },
    });

    regularUser = {
      id: regular.id,
      username: regular.username,
      email: regular.email,
      fullName: regular.fullName,
      role: regular.role as UserRole,
      workspaceId: regular.workspaceId,
      isActive: regular.isActive,
      lastLoginAt: regular.lastLoginAt,
      sessionId: 'user-session',
      permissions: [
        'projects:create', 'projects:read', 'projects:update',
        'datasets:create', 'experiments:create'
      ],
    };

    // Viewer user
    const viewer = await prisma.user.create({
      data: {
        id: 'viewer-test-id',
        username: 'vieweruser',
        email: 'viewer@test.com',
        fullName: 'Viewer User',
        passwordHash: hash,
        salt: salt,
        role: UserRole.VIEWER,
        workspaceId: 'default',
        isActive: true,
        createdBy: admin.id,
      },
    });

    viewerUser = {
      id: viewer.id,
      username: viewer.username,
      email: viewer.email,
      fullName: viewer.fullName,
      role: viewer.role as UserRole,
      workspaceId: viewer.workspaceId,
      isActive: viewer.isActive,
      lastLoginAt: viewer.lastLoginAt,
      sessionId: 'viewer-session',
      permissions: ['projects:read'],
    };

    // Other workspace user
    const otherWorkspace = await prisma.user.create({
      data: {
        id: 'other-workspace-test-id',
        username: 'otherworkspaceuser',
        email: 'other@test.com',
        fullName: 'Other Workspace User',
        passwordHash: hash,
        salt: salt,
        role: UserRole.USER,
        workspaceId: 'other-workspace',
        isActive: true,
        createdBy: 'system',
      },
    });

    otherWorkspaceUser = {
      id: otherWorkspace.id,
      username: otherWorkspace.username,
      email: otherWorkspace.email,
      fullName: otherWorkspace.fullName,
      role: otherWorkspace.role as UserRole,
      workspaceId: otherWorkspace.workspaceId,
      isActive: otherWorkspace.isActive,
      lastLoginAt: otherWorkspace.lastLoginAt,
      sessionId: 'other-session',
      permissions: ['projects:create', 'projects:read', 'projects:update'],
    };
  });

  afterAll(async () => {
    // Clean up after tests
    await prisma.userAuditLog.deleteMany();
    await prisma.userSession.deleteMany();
    await prisma.project.deleteMany();
    await prisma.user.deleteMany();
    await prisma.$disconnect();
  });

  beforeEach(async () => {
    // Clean projects before each test
    await prisma.project.deleteMany();
  });

  describe('Create Project', () => {
    it('should create project successfully with valid data', async () => {
      const createRequest: CreateProjectRequest = {
        name: 'Test Project',
        description: 'A test project',
      };

      const project = await ProjectService.createProject(createRequest, regularUser);

      expect(project.id).toBeValidUUID();
      expect(project.name).toBe('Test Project');
      expect(project.description).toBe('A test project');
      expect(project.workspaceId).toBe(regularUser.workspaceId);
      expect(project.createdBy).toBe(regularUser.id);
      expect(project.canEdit).toBe(true);
      expect(project.canDelete).toBe(true); // Owner can delete
      expect(project.canCreateDatasets).toBe(true);
      expect(project.canCreateExperiments).toBe(true);
    });

    it('should create project in specified workspace for admin', async () => {
      const createRequest: CreateProjectRequest = {
        name: 'Admin Cross-Workspace Project',
        description: 'Admin creating in other workspace',
        workspaceId: 'other-workspace',
      };

      const project = await ProjectService.createProject(createRequest, adminUser);

      expect(project.workspaceId).toBe('other-workspace');
      expect(project.createdBy).toBe(adminUser.id);
    });

    it('should reject workspace access for regular user', async () => {
      const createRequest: CreateProjectRequest = {
        name: 'Unauthorized Project',
        workspaceId: 'other-workspace',
      };

      await expect(
        ProjectService.createProject(createRequest, regularUser)
      ).rejects.toThrow(WorkspaceAccessError);
    });

    it('should reject creation for viewer user', async () => {
      const createRequest: CreateProjectRequest = {
        name: 'Viewer Project',
        description: 'Viewer should not be able to create',
      };

      await expect(
        ProjectService.createProject(createRequest, viewerUser)
      ).rejects.toThrow(ProjectPermissionError);
    });

    it('should reject duplicate project names in same workspace', async () => {
      const createRequest: CreateProjectRequest = {
        name: 'Duplicate Project',
        description: 'First project',
      };

      await ProjectService.createProject(createRequest, regularUser);

      // Try to create another with same name
      await expect(
        ProjectService.createProject(createRequest, regularUser)
      ).rejects.toThrow(ProjectValidationError);
    });

    it('should allow same project name in different workspaces', async () => {
      const createRequest1: CreateProjectRequest = {
        name: 'Same Name Project',
        workspaceId: 'default',
      };

      const createRequest2: CreateProjectRequest = {
        name: 'Same Name Project',
        workspaceId: 'other-workspace',
      };

      const project1 = await ProjectService.createProject(createRequest1, adminUser);
      const project2 = await ProjectService.createProject(createRequest2, adminUser);

      expect(project1.name).toBe('Same Name Project');
      expect(project2.name).toBe('Same Name Project');
      expect(project1.workspaceId).toBe('default');
      expect(project2.workspaceId).toBe('other-workspace');
    });

    it('should validate required fields', async () => {
      const createRequest: CreateProjectRequest = {
        name: '',
      };

      await expect(
        ProjectService.createProject(createRequest, regularUser)
      ).rejects.toThrow(ProjectValidationError);
    });

    it('should validate field lengths', async () => {
      const longName = 'a'.repeat(101); // Max 100 characters
      const createRequest: CreateProjectRequest = {
        name: longName,
      };

      await expect(
        ProjectService.createProject(createRequest, regularUser)
      ).rejects.toThrow(ProjectValidationError);
    });
  });

  describe('List Projects', () => {
    let testProjects: any[] = [];

    beforeEach(async () => {
      // Create test projects
      testProjects = await Promise.all([
        prisma.project.create({
          data: {
            name: 'Project 1',
            description: 'First project',
            workspaceId: 'default',
            createdBy: regularUser.id,
          },
        }),
        prisma.project.create({
          data: {
            name: 'Project 2',
            description: 'Second project',
            workspaceId: 'default',
            createdBy: adminUser.id,
          },
        }),
        prisma.project.create({
          data: {
            name: 'Other Workspace Project',
            description: 'Project in other workspace',
            workspaceId: 'other-workspace',
            createdBy: otherWorkspaceUser.id,
          },
        }),
      ]);
    });

    it('should list projects for regular user with workspace isolation', async () => {
      const result = await ProjectService.listProjects(regularUser);

      expect(result.projects).toHaveLength(2);
      expect(result.projects.every(p => p.workspaceId === 'default')).toBe(true);
      expect(result.pagination.total).toBe(2);
    });

    it('should list all projects for admin user', async () => {
      const result = await ProjectService.listProjects(adminUser);

      expect(result.projects.length).toBeGreaterThanOrEqual(3);
      expect(result.pagination.total).toBeGreaterThanOrEqual(3);
    });

    it('should apply name filter', async () => {
      const result = await ProjectService.listProjects(
        regularUser,
        { name: 'Project 1' }
      );

      expect(result.projects).toHaveLength(1);
      expect(result.projects[0].name).toBe('Project 1');
    });

    it('should apply createdBy filter', async () => {
      const result = await ProjectService.listProjects(
        regularUser,
        { createdBy: regularUser.id }
      );

      expect(result.projects).toHaveLength(1);
      expect(result.projects[0].createdBy).toBe(regularUser.id);
    });

    it('should handle pagination correctly', async () => {
      const result = await ProjectService.listProjects(
        regularUser,
        undefined,
        undefined,
        1,
        1
      );

      expect(result.projects).toHaveLength(1);
      expect(result.pagination.page).toBe(1);
      expect(result.pagination.size).toBe(1);
      expect(result.pagination.hasNext).toBe(true);
      expect(result.pagination.hasPrevious).toBe(false);
    });

    it('should handle sorting correctly', async () => {
      const result = await ProjectService.listProjects(
        regularUser,
        undefined,
        { field: 'name', order: 'asc' }
      );

      expect(result.projects[0].name).toBeLessThanOrEqual(result.projects[1].name);
    });
  });

  describe('Get Project', () => {
    let testProject: any;

    beforeEach(async () => {
      testProject = await prisma.project.create({
        data: {
          name: 'Get Test Project',
          description: 'Project for get testing',
          workspaceId: 'default',
          createdBy: regularUser.id,
        },
      });
    });

    it('should get project successfully for owner', async () => {
      const project = await ProjectService.getProject(testProject.id, regularUser);

      expect(project.id).toBe(testProject.id);
      expect(project.name).toBe('Get Test Project');
      expect(project.canEdit).toBe(true);
      expect(project.canDelete).toBe(true);
    });

    it('should get project successfully for admin', async () => {
      const project = await ProjectService.getProject(testProject.id, adminUser);

      expect(project.id).toBe(testProject.id);
      expect(project.canEdit).toBe(true);
      expect(project.canDelete).toBe(true);
    });

    it('should get project with limited permissions for viewer', async () => {
      const project = await ProjectService.getProject(testProject.id, viewerUser);

      expect(project.id).toBe(testProject.id);
      expect(project.canEdit).toBe(false);
      expect(project.canDelete).toBe(false);
      expect(project.canCreateDatasets).toBe(false);
    });

    it('should reject access for user in different workspace', async () => {
      await expect(
        ProjectService.getProject(testProject.id, otherWorkspaceUser)
      ).rejects.toThrow(ProjectPermissionError);
    });

    it('should throw error for non-existent project', async () => {
      await expect(
        ProjectService.getProject('non-existent-id', regularUser)
      ).rejects.toThrow(ProjectNotFoundError);
    });
  });

  describe('Update Project', () => {
    let testProject: any;

    beforeEach(async () => {
      testProject = await prisma.project.create({
        data: {
          name: 'Update Test Project',
          description: 'Project for update testing',
          workspaceId: 'default',
          createdBy: regularUser.id,
        },
      });
    });

    it('should update project successfully for owner', async () => {
      const updateRequest: UpdateProjectRequest = {
        name: 'Updated Project Name',
        description: 'Updated description',
      };

      const project = await ProjectService.updateProject(testProject.id, updateRequest, regularUser);

      expect(project.name).toBe('Updated Project Name');
      expect(project.description).toBe('Updated description');
      expect(project.lastUpdatedBy).toBe(regularUser.id);
    });

    it('should update project successfully for admin', async () => {
      const updateRequest: UpdateProjectRequest = {
        name: 'Admin Updated Project',
      };

      const project = await ProjectService.updateProject(testProject.id, updateRequest, adminUser);

      expect(project.name).toBe('Admin Updated Project');
      expect(project.lastUpdatedBy).toBe(adminUser.id);
    });

    it('should reject update for viewer', async () => {
      const updateRequest: UpdateProjectRequest = {
        name: 'Viewer Update Attempt',
      };

      await expect(
        ProjectService.updateProject(testProject.id, updateRequest, viewerUser)
      ).rejects.toThrow(ProjectPermissionError);
    });

    it('should reject update for user in different workspace', async () => {
      const updateRequest: UpdateProjectRequest = {
        name: 'Cross-workspace Update',
      };

      await expect(
        ProjectService.updateProject(testProject.id, updateRequest, otherWorkspaceUser)
      ).rejects.toThrow(ProjectPermissionError);
    });

    it('should reject duplicate name in same workspace', async () => {
      // Create another project
      await prisma.project.create({
        data: {
          name: 'Existing Project',
          workspaceId: 'default',
          createdBy: regularUser.id,
        },
      });

      const updateRequest: UpdateProjectRequest = {
        name: 'Existing Project',
      };

      await expect(
        ProjectService.updateProject(testProject.id, updateRequest, regularUser)
      ).rejects.toThrow(ProjectValidationError);
    });

    it('should validate update data', async () => {
      const updateRequest: UpdateProjectRequest = {
        name: '', // Empty name should fail
      };

      await expect(
        ProjectService.updateProject(testProject.id, updateRequest, regularUser)
      ).rejects.toThrow(ProjectValidationError);
    });
  });

  describe('Delete Project', () => {
    let testProject: any;

    beforeEach(async () => {
      testProject = await prisma.project.create({
        data: {
          name: 'Delete Test Project',
          description: 'Project for delete testing',
          workspaceId: 'default',
          createdBy: regularUser.id,
        },
      });
    });

    it('should delete project successfully for owner', async () => {
      await ProjectService.deleteProject(testProject.id, regularUser);

      const deletedProject = await prisma.project.findUnique({
        where: { id: testProject.id },
      });
      
      expect(deletedProject).toBeNull();
    });

    it('should delete project successfully for admin', async () => {
      await ProjectService.deleteProject(testProject.id, adminUser);

      const deletedProject = await prisma.project.findUnique({
        where: { id: testProject.id },
      });
      
      expect(deletedProject).toBeNull();
    });

    it('should reject delete for viewer', async () => {
      await expect(
        ProjectService.deleteProject(testProject.id, viewerUser)
      ).rejects.toThrow(ProjectPermissionError);
    });

    it('should reject delete for user in different workspace', async () => {
      await expect(
        ProjectService.deleteProject(testProject.id, otherWorkspaceUser)
      ).rejects.toThrow(ProjectPermissionError);
    });

    it('should throw error for non-existent project', async () => {
      await expect(
        ProjectService.deleteProject('non-existent-id', regularUser)
      ).rejects.toThrow(ProjectNotFoundError);
    });

    it('should require force flag for projects with dependencies', async () => {
      // Create a dataset for the project
      await prisma.dataset.create({
        data: {
          name: 'Test Dataset',
          projectId: testProject.id,
          createdBy: regularUser.id,
        },
      });

      // Should fail without force
      await expect(
        ProjectService.deleteProject(testProject.id, regularUser, false)
      ).rejects.toThrow(ProjectValidationError);

      // Should succeed with force for admin
      await ProjectService.deleteProject(testProject.id, adminUser, true);

      const deletedProject = await prisma.project.findUnique({
        where: { id: testProject.id },
      });
      
      expect(deletedProject).toBeNull();
    });

    it('should reject force delete for regular user', async () => {
      // Create a dataset for the project
      await prisma.dataset.create({
        data: {
          name: 'Test Dataset',
          projectId: testProject.id,
          createdBy: regularUser.id,
        },
      });

      await expect(
        ProjectService.deleteProject(testProject.id, regularUser, true)
      ).rejects.toThrow(ProjectPermissionError);
    });
  });

  describe('Permission System', () => {
    let ownedProject: any;
    let otherProject: any;

    beforeEach(async () => {
      ownedProject = await prisma.project.create({
        data: {
          name: 'Owned Project',
          workspaceId: 'default',
          createdBy: regularUser.id,
        },
      });

      otherProject = await prisma.project.create({
        data: {
          name: 'Other Project',
          workspaceId: 'default',
          createdBy: adminUser.id,
        },
      });
    });

    it('should provide correct permissions for project owner', async () => {
      const project = await ProjectService.getProject(ownedProject.id, regularUser);

      expect(project.canEdit).toBe(true);
      expect(project.canDelete).toBe(true);
      expect(project.canCreateDatasets).toBe(true);
      expect(project.canCreateExperiments).toBe(true);
    });

    it('should provide correct permissions for admin', async () => {
      const project = await ProjectService.getProject(ownedProject.id, adminUser);

      expect(project.canEdit).toBe(true);
      expect(project.canDelete).toBe(true);
      expect(project.canCreateDatasets).toBe(true);
      expect(project.canCreateExperiments).toBe(true);
    });

    it('should provide correct permissions for viewer', async () => {
      const project = await ProjectService.getProject(ownedProject.id, viewerUser);

      expect(project.canEdit).toBe(false);
      expect(project.canDelete).toBe(false);
      expect(project.canCreateDatasets).toBe(false);
      expect(project.canCreateExperiments).toBe(false);
    });

    it('should provide limited permissions for non-owner regular user', async () => {
      const project = await ProjectService.getProject(otherProject.id, regularUser);

      expect(project.canEdit).toBe(true); // Has projects:update permission
      expect(project.canDelete).toBe(false); // Not owner, no projects:delete permission
      expect(project.canCreateDatasets).toBe(true);
      expect(project.canCreateExperiments).toBe(true);
    });
  });
});