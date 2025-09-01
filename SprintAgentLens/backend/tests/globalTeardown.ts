/**
 * Jest global teardown
 * Runs once after all tests
 */

import { PrismaClient } from '@prisma/client';

export default async function globalTeardown(): Promise<void> {
  console.log('🧹 Cleaning up test environment...');

  try {
    // Clean up any remaining connections
    if (global.__PRISMA_CLIENT__) {
      await global.__PRISMA_CLIENT__.$disconnect();
    }

    console.log('✅ Test environment cleanup complete');
  } catch (error) {
    console.error('❌ Test cleanup failed:', error);
  }
}