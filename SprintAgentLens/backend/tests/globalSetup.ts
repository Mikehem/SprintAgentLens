/**
 * Jest global setup
 * Runs once before all tests
 */

import { PrismaClient } from '@prisma/client';
import { execSync } from 'child_process';

export default async function globalSetup(): Promise<void> {
  console.log('🧪 Setting up test environment...');

  // Ensure test database exists and is clean
  try {
    // Reset test database schema
    process.env.DATABASE_URL = 'mysql://root:@localhost:3306/sprintagentlens_test';
    
    console.log('📁 Creating test database...');
    execSync('mysql -u root -e "CREATE DATABASE IF NOT EXISTS sprintagentlens_test"', {
      stdio: 'pipe',
    });

    console.log('🔄 Running database migrations for test environment...');
    execSync('npx prisma migrate dev --name init', {
      stdio: 'pipe',
      env: { ...process.env, DATABASE_URL: 'mysql://root:@localhost:3306/sprintagentlens_test' },
    });

    console.log('✅ Test database setup complete');
  } catch (error) {
    console.error('❌ Test database setup failed:', error);
    throw error;
  }
}