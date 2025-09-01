/**
 * Database seed script for SprintAgentLens
 * Creates initial admin user and workspace configuration
 */

import { PrismaClient } from '@prisma/client';
import { AuthService } from '@/services/AuthService';
import { UserRole } from '@/types/auth';
import { logger } from '@/utils/logger';
import { config } from '@/config/environment';

const prisma = new PrismaClient();

async function main(): Promise<void> {
  try {
    logger.info('🌱 Starting database seeding...');

    // Check if admin user already exists
    const existingAdmin = await prisma.user.findFirst({
      where: { role: UserRole.ADMIN },
    });

    if (existingAdmin) {
      logger.info('Admin user already exists, skipping seed');
      return;
    }

    // Create default admin user
    const adminPassword = 'OpikAdmin2024!';
    const { hash, salt } = await AuthService.hashPassword(adminPassword);

    const admin = await prisma.user.create({
      data: {
        id: 'admin-seed-id',
        username: 'admin',
        email: 'admin@sprintagentlens.com',
        fullName: 'System Administrator',
        passwordHash: hash,
        salt: salt,
        role: UserRole.ADMIN,
        workspaceId: 'default',
        isActive: true,
        createdBy: 'system',
      },
    });

    logger.info(`✅ Admin user created: ${admin.username}`);

    // Create test user for development
    if (config.NODE_ENV === 'development') {
      const testUser = await prisma.user.create({
        data: {
          id: 'test-user-id',
          username: 'testuser',
          email: 'user@sprintagentlens.com',
          fullName: 'Test User',
          passwordHash: hash, // Same password for testing
          salt: salt,
          role: UserRole.USER,
          workspaceId: 'default',
          isActive: true,
          createdBy: admin.id,
        },
      });

      logger.info(`✅ Test user created: ${testUser.username}`);
    }

    // Create default workspace configuration
    await prisma.workspaceConfiguration.create({
      data: {
        id: 'default-workspace-config',
        workspaceId: 'default',
        name: 'Default Workspace',
        description: 'Default SprintAgentLens workspace',
        settings: {
          theme: 'light',
          timezone: 'UTC',
          dateFormat: 'YYYY-MM-DD',
          timeFormat: '24h',
        },
        features: {
          experiments: true,
          tracing: true,
          analytics: true,
          llmProviders: true,
        },
        createdBy: admin.id,
      },
    });

    logger.info('✅ Default workspace configuration created');

    // Create sample project for development
    if (config.NODE_ENV === 'development') {
      await prisma.project.create({
        data: {
          id: 'sample-project-id',
          name: 'Sample Project',
          description: 'A sample project for testing SprintAgentLens features',
          workspaceId: 'default',
          createdBy: admin.id,
        },
      });

      logger.info('✅ Sample project created');
    }

    logger.info('🌱 Database seeding completed successfully');
    logger.info('');
    logger.info('📝 Default credentials:');
    logger.info(`   Admin: admin / ${adminPassword}`);
    if (config.NODE_ENV === 'development') {
      logger.info(`   User:  testuser / ${adminPassword}`);
    }
    logger.info('');
    logger.info('⚠️  IMPORTANT: Change the admin password immediately in production!');
  } catch (error) {
    logger.error('❌ Database seeding failed:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

// Run the seed function
main().catch((error) => {
  logger.error('Seed script failed:', error);
  process.exit(1);
});