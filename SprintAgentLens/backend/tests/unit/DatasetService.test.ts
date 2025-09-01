/**
 * Dataset Service Unit Tests
 * Comprehensive testing of dataset operations with authentication and workspace isolation
 */

// Mock modules before imports
jest.mock('@prisma/client');
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    debug: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
  }
}));
jest.mock('@/config/environment', () => ({
  env: {
    MYSQL_HOST: 'localhost',
    MYSQL_USER: 'test',
    MYSQL_PASSWORD: 'test',
    NODE_ENV: 'test'
  }
}));
jest.mock('@/config/database', () => ({}));
jest.mock('@/services/ProjectService');

import { PrismaClient } from '@prisma/client';
import { DatasetService } from '@/services/DatasetService';
import { logger } from '@/utils/logger';
import type { AuthenticatedUser } from '@/types/auth';
import type { CreateDatasetRequest, UpdateDatasetRequest } from '@/types/datasets';

const mockPrisma = {
  dataset: {
    create: jest.fn(),
    findUnique: jest.fn(),
    findMany: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    count: jest.fn(),
  },
  project: {
    findUnique: jest.fn(),
  },
  experiment: {
    count: jest.fn(),
  },
} as any;

// Mock ProjectService
import { ProjectService } from '@/services/ProjectService';
const mockProjectService = {
  getProjectById: jest.fn(),
} as jest.Mocked<Partial<typeof ProjectService>>;

describe('DatasetService', () => {
  beforeAll(() => {
    // Mock Prisma Client constructor
    (PrismaClient as jest.Mock).mockImplementation(() => mockPrisma);
    
    // Access private static prisma property
    (DatasetService as any).prisma = mockPrisma;
    
    // Mock ProjectService static methods
    (ProjectService as any).getProjectById = mockProjectService.getProjectById;
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  // Test users with different roles and workspaces
  const adminUser: AuthenticatedUser = {
    id: 'user-admin-1',
    username: 'admin',
    email: 'admin@company.com',
    fullName: 'Admin User',
    role: 'admin',
    workspaceId: 'workspace-1',
    permissions: ['admin:all'],
  };

  const regularUser: AuthenticatedUser = {
    id: 'user-regular-1',
    username: 'user',
    email: 'user@company.com',
    fullName: 'Regular User',
    role: 'user',
    workspaceId: 'workspace-1',
    permissions: ['user:read', 'user:write'],
  };

  const viewerUser: AuthenticatedUser = {
    id: 'user-viewer-1',
    username: 'viewer',
    email: 'viewer@company.com',
    fullName: 'Viewer User',
    role: 'viewer',
    workspaceId: 'workspace-1',
    permissions: ['user:read'],
  };

  const otherWorkspaceUser: AuthenticatedUser = {
    id: 'user-other-1',
    username: 'other',
    email: 'other@company.com',
    fullName: 'Other Workspace User',
    role: 'user',
    workspaceId: 'workspace-2',
    permissions: ['user:read', 'user:write'],
  };

  describe('Permission Checking', () => {
    const mockDataset = {
      id: 'dataset-1',
      name: 'Test Dataset',
      workspaceId: 'workspace-1',
      createdBy: 'user-regular-1',
    };

    const otherWorkspaceDataset = {
      id: 'dataset-2',
      name: 'Other Dataset',
      workspaceId: 'workspace-2',
      createdBy: 'user-other-1',
    };

    test('canCreateDataset - admin can create', () => {
      expect(DatasetService.canCreateDataset(adminUser, 'project-1')).toBe(true);
    });

    test('canCreateDataset - user can create', () => {
      expect(DatasetService.canCreateDataset(regularUser, 'project-1')).toBe(true);
    });

    test('canCreateDataset - viewer cannot create', () => {
      expect(DatasetService.canCreateDataset(viewerUser, 'project-1')).toBe(false);
    });

    test('canReadDataset - admin can read any workspace', () => {
      expect(DatasetService.canReadDataset(adminUser, mockDataset)).toBe(true);
      expect(DatasetService.canReadDataset(adminUser, otherWorkspaceDataset)).toBe(true);
    });

    test('canReadDataset - user can read same workspace', () => {
      expect(DatasetService.canReadDataset(regularUser, mockDataset)).toBe(true);
      expect(DatasetService.canReadDataset(regularUser, otherWorkspaceDataset)).toBe(false);
    });

    test('canReadDataset - viewer can read same workspace', () => {
      expect(DatasetService.canReadDataset(viewerUser, mockDataset)).toBe(true);
      expect(DatasetService.canReadDataset(viewerUser, otherWorkspaceDataset)).toBe(false);
    });

    test('canEditDataset - admin can edit any', () => {
      expect(DatasetService.canEditDataset(adminUser, mockDataset)).toBe(true);
      expect(DatasetService.canEditDataset(adminUser, otherWorkspaceDataset)).toBe(true);
    });

    test('canEditDataset - user can edit same workspace', () => {
      expect(DatasetService.canEditDataset(regularUser, mockDataset)).toBe(true);
      expect(DatasetService.canEditDataset(regularUser, otherWorkspaceDataset)).toBe(false);
    });

    test('canEditDataset - viewer cannot edit', () => {
      expect(DatasetService.canEditDataset(viewerUser, mockDataset)).toBe(false);
      expect(DatasetService.canEditDataset(viewerUser, otherWorkspaceDataset)).toBe(false);
    });

    test('canDeleteDataset - admin can delete any', () => {
      expect(DatasetService.canDeleteDataset(adminUser, mockDataset)).toBe(true);
      expect(DatasetService.canDeleteDataset(adminUser, otherWorkspaceDataset)).toBe(true);
    });

    test('canDeleteDataset - user can delete same workspace', () => {
      expect(DatasetService.canDeleteDataset(regularUser, mockDataset)).toBe(true);
      expect(DatasetService.canDeleteDataset(regularUser, otherWorkspaceDataset)).toBe(false);
    });

    test('canDeleteDataset - viewer cannot delete', () => {
      expect(DatasetService.canDeleteDataset(viewerUser, mockDataset)).toBe(false);
    });
  });

  describe('createDataset', () => {
    const createRequest: CreateDatasetRequest = {
      name: 'Test Dataset',
      description: 'Test description',
      projectId: 'project-1',
      workspaceId: 'workspace-1',
      metadata: {
        version: '1.0.0',
        source: 'manual',
        format: 'json' as const,
        quality: { completeness: 100, consistency: 100, validity: 100 },
        lineage: {},
        annotations: { author: 'Test User' },
      },
      tags: ['test', 'example'],
    };

    const mockProject = {
      id: 'project-1',
      name: 'Test Project',
      workspaceId: 'workspace-1',
      canCreateDatasets: true,
    };

    const mockCreatedDataset = {
      id: 'dataset-1',
      name: 'Test Dataset',
      description: 'Test description',
      projectId: 'project-1',
      workspaceId: 'workspace-1',
      metadata: JSON.stringify(createRequest.metadata),
      tags: createRequest.tags,
      status: 'draft',
      itemCount: 0,
      createdAt: new Date(),
      createdBy: 'user-regular-1',
      lastUpdatedAt: new Date(),
      lastUpdatedBy: 'user-regular-1',
      project: { name: 'Test Project', workspaceName: 'Test Workspace' },
      creator: { fullName: 'Regular User', username: 'user' },
      updater: { fullName: 'Regular User', username: 'user' },
      _count: { items: 0 },
    };

    beforeEach(() => {
      mockProjectService.getProjectById.mockResolvedValue(mockProject as any);
      mockPrisma.dataset.count.mockResolvedValue(0);
      mockPrisma.dataset.create.mockResolvedValue(mockCreatedDataset);
      
      // Mock getWorkspaceSettings
      (DatasetService as any).getWorkspaceSettings = jest.fn().mockResolvedValue({
        limits: { maxDatasetsPerProject: 50 },
      });
    });

    test('should create dataset successfully for regular user', async () => {
      const result = await DatasetService.createDataset(createRequest, regularUser);

      expect(result).toBeDefined();
      expect(result.name).toBe('Test Dataset');
      expect(result.canEdit).toBe(true);
      expect(result.canRead).toBe(true);
      expect(mockPrisma.dataset.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            name: 'Test Dataset',
            workspaceId: 'workspace-1',
            createdBy: 'user-regular-1',
          }),
        })
      );
    });

    test('should create dataset successfully for admin', async () => {
      const result = await DatasetService.createDataset(createRequest, adminUser);

      expect(result).toBeDefined();
      expect(result.canEdit).toBe(true);
      expect(result.canDelete).toBe(true);
    });

    test('should reject creation for viewer user', async () => {
      await expect(DatasetService.createDataset(createRequest, viewerUser))
        .rejects.toThrow('Permission denied: create');
    });

    test('should reject creation for workspace mismatch', async () => {
      const mismatchProject = { ...mockProject, workspaceId: 'other-workspace' };
      mockProjectService.getProjectById.mockResolvedValue(mismatchProject as any);

      await expect(DatasetService.createDataset(createRequest, regularUser))
        .rejects.toThrow('Permission denied: create');
    });

    test('should reject creation when dataset limit exceeded', async () => {
      mockPrisma.dataset.count.mockResolvedValue(50); // At limit

      await expect(DatasetService.createDataset(createRequest, regularUser))
        .rejects.toThrow('Dataset limit exceeded');
    });

    test('should validate dataset name', async () => {
      const invalidRequest = { ...createRequest, name: '' };

      await expect(DatasetService.createDataset(invalidRequest, regularUser))
        .rejects.toThrow('Name must be at least 1 characters');
    });

    test('should validate description length', async () => {
      const longDescription = 'x'.repeat(2001);
      const invalidRequest = { ...createRequest, description: longDescription };

      await expect(DatasetService.createDataset(invalidRequest, regularUser))
        .rejects.toThrow('Description cannot exceed 2000 characters');
    });

    test('should validate tags', async () => {
      const tooManyTags = Array.from({ length: 21 }, (_, i) => `tag${i}`);
      const invalidRequest = { ...createRequest, tags: tooManyTags };

      await expect(DatasetService.createDataset(invalidRequest, regularUser))
        .rejects.toThrow('Cannot have more than 20 tags');
    });
  });

  describe('getDatasetById', () => {
    const mockDataset = {
      id: 'dataset-1',
      name: 'Test Dataset',
      description: 'Test description',
      projectId: 'project-1',
      workspaceId: 'workspace-1',
      metadata: JSON.stringify({ version: '1.0.0' }),
      tags: ['test'],
      status: 'ready',
      itemCount: 5,
      createdAt: new Date(),
      createdBy: 'user-regular-1',
      lastUpdatedAt: new Date(),
      lastUpdatedBy: 'user-regular-1',
      project: { name: 'Test Project', workspaceName: 'Test Workspace' },
      creator: { fullName: 'Regular User', username: 'user' },
      updater: { fullName: 'Regular User', username: 'user' },
      _count: { items: 5 },
    };

    test('should get dataset successfully for authorized user', async () => {
      mockPrisma.dataset.findUnique.mockResolvedValue(mockDataset);

      const result = await DatasetService.getDatasetById('dataset-1', regularUser);

      expect(result).toBeDefined();
      expect(result.name).toBe('Test Dataset');
      expect(result.canRead).toBe(true);
      expect(result.itemCount).toBe(5);
    });

    test('should reject access for unauthorized workspace', async () => {
      mockPrisma.dataset.findUnique.mockResolvedValue(mockDataset);

      await expect(DatasetService.getDatasetById('dataset-1', otherWorkspaceUser))
        .rejects.toThrow('Permission denied: read on dataset dataset-1');
    });

    test('should throw error for non-existent dataset', async () => {
      mockPrisma.dataset.findUnique.mockResolvedValue(null);

      await expect(DatasetService.getDatasetById('non-existent', regularUser))
        .rejects.toThrow('Dataset not found: non-existent');
    });

    test('should allow admin to access any workspace dataset', async () => {
      const otherWorkspaceDataset = { ...mockDataset, workspaceId: 'workspace-2' };
      mockPrisma.dataset.findUnique.mockResolvedValue(otherWorkspaceDataset);

      const result = await DatasetService.getDatasetById('dataset-1', adminUser);

      expect(result).toBeDefined();
      expect(result.canEdit).toBe(true);
      expect(result.canDelete).toBe(true);
    });
  });

  describe('updateDataset', () => {
    const mockDataset = {
      id: 'dataset-1',
      name: 'Original Name',
      description: 'Original description',
      workspaceId: 'workspace-1',
      metadata: JSON.stringify({ version: '1.0.0' }),
      tags: ['original'],
      createdBy: 'user-regular-1',
    };

    const updateRequest: UpdateDatasetRequest = {
      name: 'Updated Name',
      description: 'Updated description',
      tags: ['updated'],
      metadata: { version: '1.1.0' },
    };

    const mockUpdatedDataset = {
      ...mockDataset,
      ...updateRequest,
      metadata: JSON.stringify({ version: '1.0.0', ...updateRequest.metadata }),
      lastUpdatedAt: new Date(),
      project: { name: 'Test Project', workspaceName: 'Test Workspace' },
      creator: { fullName: 'Regular User', username: 'user' },
      updater: { fullName: 'Regular User', username: 'user' },
      _count: { items: 0 },
    };

    test('should update dataset successfully for authorized user', async () => {
      mockPrisma.dataset.findUnique.mockResolvedValue(mockDataset);
      mockPrisma.dataset.update.mockResolvedValue(mockUpdatedDataset);

      const result = await DatasetService.updateDataset('dataset-1', updateRequest, regularUser);

      expect(result).toBeDefined();
      expect(result.name).toBe('Updated Name');
      expect(mockPrisma.dataset.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'dataset-1' },
          data: expect.objectContaining({
            name: 'Updated Name',
            description: 'Updated description',
            lastUpdatedBy: 'user-regular-1',
          }),
        })
      );
    });

    test('should reject update for unauthorized user', async () => {
      mockPrisma.dataset.findUnique.mockResolvedValue(mockDataset);

      await expect(DatasetService.updateDataset('dataset-1', updateRequest, viewerUser))
        .rejects.toThrow('Permission denied: update on dataset dataset-1');
    });

    test('should reject update for wrong workspace', async () => {
      mockPrisma.dataset.findUnique.mockResolvedValue(mockDataset);

      await expect(DatasetService.updateDataset('dataset-1', updateRequest, otherWorkspaceUser))
        .rejects.toThrow('Permission denied: update on dataset dataset-1');
    });

    test('should validate updated name', async () => {
      mockPrisma.dataset.findUnique.mockResolvedValue(mockDataset);
      const invalidUpdate = { name: '' };

      await expect(DatasetService.updateDataset('dataset-1', invalidUpdate, regularUser))
        .rejects.toThrow('Name must be at least 1 characters');
    });
  });

  describe('deleteDataset', () => {
    const mockDataset = {
      id: 'dataset-1',
      name: 'Test Dataset',
      workspaceId: 'workspace-1',
      createdBy: 'user-regular-1',
    };

    test('should delete dataset successfully for authorized user', async () => {
      mockPrisma.dataset.findUnique.mockResolvedValue(mockDataset);
      mockPrisma.experiment.count.mockResolvedValue(0); // No experiments using dataset
      mockPrisma.dataset.delete.mockResolvedValue(mockDataset);

      await DatasetService.deleteDataset('dataset-1', regularUser);

      expect(mockPrisma.dataset.delete).toHaveBeenCalledWith({
        where: { id: 'dataset-1' },
      });
    });

    test('should reject deletion for unauthorized user', async () => {
      mockPrisma.dataset.findUnique.mockResolvedValue(mockDataset);

      await expect(DatasetService.deleteDataset('dataset-1', viewerUser))
        .rejects.toThrow('Permission denied: delete on dataset dataset-1');
    });

    test('should reject deletion when dataset is used by experiments', async () => {
      mockPrisma.dataset.findUnique.mockResolvedValue(mockDataset);
      mockPrisma.experiment.count.mockResolvedValue(3); // 3 experiments using dataset

      await expect(DatasetService.deleteDataset('dataset-1', regularUser))
        .rejects.toThrow('Invalid dataset status');
    });

    test('should allow admin to delete any dataset', async () => {
      const otherWorkspaceDataset = { ...mockDataset, workspaceId: 'workspace-2' };
      mockPrisma.dataset.findUnique.mockResolvedValue(otherWorkspaceDataset);
      mockPrisma.experiment.count.mockResolvedValue(0);
      mockPrisma.dataset.delete.mockResolvedValue(otherWorkspaceDataset);

      await DatasetService.deleteDataset('dataset-1', adminUser);

      expect(mockPrisma.dataset.delete).toHaveBeenCalled();
    });
  });

  describe('listDatasets', () => {
    const mockDatasets = [
      {
        id: 'dataset-1',
        name: 'Dataset 1',
        workspaceId: 'workspace-1',
        projectId: 'project-1',
        status: 'ready',
        tags: ['tag1'],
        createdAt: new Date('2024-01-01'),
        project: { name: 'Project 1', workspaceName: 'Workspace 1' },
        creator: { fullName: 'User 1', username: 'user1' },
        updater: { fullName: 'User 1', username: 'user1' },
        _count: { items: 10 },
      },
      {
        id: 'dataset-2',
        name: 'Dataset 2',
        workspaceId: 'workspace-1',
        projectId: 'project-2',
        status: 'draft',
        tags: ['tag2'],
        createdAt: new Date('2024-01-02'),
        project: { name: 'Project 2', workspaceName: 'Workspace 1' },
        creator: { fullName: 'User 2', username: 'user2' },
        updater: null,
        _count: { items: 5 },
      },
    ];

    beforeEach(() => {
      mockProjectService.getProjectById.mockResolvedValue({
        id: 'project-1',
        name: 'Test Project',
        workspaceId: 'workspace-1',
      } as any);
    });

    test('should list datasets with workspace isolation', async () => {
      mockPrisma.dataset.findMany.mockResolvedValue(mockDatasets);
      mockPrisma.dataset.count.mockResolvedValue(2);

      const result = await DatasetService.listDatasets({}, regularUser);

      expect(result.datasets).toHaveLength(2);
      expect(result.pagination.total).toBe(2);
      expect(mockPrisma.dataset.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            workspaceId: 'workspace-1', // Workspace isolation enforced
          }),
        })
      );
    });

    test('should filter by project with access check', async () => {
      mockPrisma.dataset.findMany.mockResolvedValue([mockDatasets[0]]);
      mockPrisma.dataset.count.mockResolvedValue(1);

      const result = await DatasetService.listDatasets(
        { projectId: 'project-1' },
        regularUser
      );

      expect(result.datasets).toHaveLength(1);
      expect(mockProjectService.getProjectById).toHaveBeenCalledWith('project-1', regularUser);
    });

    test('should return empty list for unauthorized project', async () => {
      mockProjectService.getProjectById.mockResolvedValue(null);

      const result = await DatasetService.listDatasets(
        { projectId: 'unauthorized-project' },
        regularUser
      );

      expect(result.datasets).toHaveLength(0);
      expect(result.pagination.total).toBe(0);
    });

    test('should apply search filter', async () => {
      mockPrisma.dataset.findMany.mockResolvedValue([mockDatasets[0]]);
      mockPrisma.dataset.count.mockResolvedValue(1);

      await DatasetService.listDatasets({ search: 'Dataset 1' }, regularUser);

      expect(mockPrisma.dataset.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            OR: [
              { name: { contains: 'Dataset 1', mode: 'insensitive' } },
              { description: { contains: 'Dataset 1', mode: 'insensitive' } },
            ],
          }),
        })
      );
    });

    test('should apply status filter', async () => {
      mockPrisma.dataset.findMany.mockResolvedValue([mockDatasets[0]]);
      mockPrisma.dataset.count.mockResolvedValue(1);

      await DatasetService.listDatasets({ status: ['ready', 'archived'] }, regularUser);

      expect(mockPrisma.dataset.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            status: { in: ['ready', 'archived'] },
          }),
        })
      );
    });

    test('should apply tag filter', async () => {
      mockPrisma.dataset.findMany.mockResolvedValue([mockDatasets[0]]);
      mockPrisma.dataset.count.mockResolvedValue(1);

      await DatasetService.listDatasets({ tags: ['tag1', 'tag2'] }, regularUser);

      expect(mockPrisma.dataset.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            tags: { hasSome: ['tag1', 'tag2'] },
          }),
        })
      );
    });

    test('should handle pagination correctly', async () => {
      mockPrisma.dataset.findMany.mockResolvedValue([mockDatasets[0]]);
      mockPrisma.dataset.count.mockResolvedValue(25);

      const result = await DatasetService.listDatasets(
        { page: 2, limit: 10 },
        regularUser
      );

      expect(result.pagination).toEqual({
        page: 2,
        limit: 10,
        total: 25,
        totalPages: 3,
      });
      expect(mockPrisma.dataset.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          skip: 10, // (page - 1) * limit
          take: 10,
        })
      );
    });

    test('should enforce pagination limits', async () => {
      mockPrisma.dataset.findMany.mockResolvedValue([]);
      mockPrisma.dataset.count.mockResolvedValue(0);

      await DatasetService.listDatasets({ page: 0, limit: 200 }, regularUser);

      expect(mockPrisma.dataset.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          skip: 0, // Min page is 1
          take: 100, // Max limit is 100
        })
      );
    });
  });
});