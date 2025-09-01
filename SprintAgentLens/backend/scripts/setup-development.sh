#!/bin/bash

# SprintAgentLens Backend Development Setup Script
# This script sets up the development environment for the Node.js backend

set -e

echo "🚀 Setting up SprintAgentLens Backend Development Environment"

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18+ first."
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "❌ Node.js version 18+ is required. Current version: $(node --version)"
    exit 1
fi

echo "✅ Node.js version: $(node --version)"

# Check if pnpm is installed (recommended) or use npm
if command -v pnpm &> /dev/null; then
    PACKAGE_MANAGER="pnpm"
    echo "✅ Using pnpm as package manager"
elif command -v npm &> /dev/null; then
    PACKAGE_MANAGER="npm"
    echo "✅ Using npm as package manager"
else
    echo "❌ No package manager found. Please install Node.js with npm."
    exit 1
fi

# Create package.json if it doesn't exist
if [ ! -f "package.json" ]; then
    echo "📦 Creating package.json..."
    cat > package.json << 'EOF'
{
  "name": "sprintagentlens-backend",
  "version": "1.0.0",
  "description": "SprintAgentLens Backend - Node.js/TypeScript migration from OPIK Java backend",
  "main": "dist/app.js",
  "scripts": {
    "dev": "tsx watch src/app.ts",
    "build": "tsup src/app.ts --format cjs,esm --dts",
    "start": "node dist/app.js",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "lint": "eslint src/**/*.ts",
    "lint:fix": "eslint src/**/*.ts --fix",
    "format": "prettier --write src/**/*.ts",
    "type-check": "tsc --noEmit",
    "db:migrate": "prisma migrate dev",
    "db:generate": "prisma generate",
    "db:seed": "tsx prisma/seed.ts",
    "db:reset": "prisma migrate reset",
    "docker:build": "docker build -t sprintagentlens-backend .",
    "docker:run": "docker run -p 3000:3000 sprintagentlens-backend"
  },
  "keywords": [
    "nodejs",
    "typescript",
    "fastify",
    "authentication",
    "api",
    "backend",
    "sprintagentlens"
  ],
  "author": "SprintAgentLens Team",
  "license": "MIT",
  "devDependencies": {
    "@types/bcryptjs": "^2.4.6",
    "@types/jest": "^29.5.8",
    "@types/jsonwebtoken": "^9.0.5",
    "@types/node": "^20.9.0",
    "@types/supertest": "^2.0.16",
    "@typescript-eslint/eslint-plugin": "^6.12.0",
    "@typescript-eslint/parser": "^6.12.0",
    "eslint": "^8.54.0",
    "eslint-config-prettier": "^9.0.0",
    "eslint-plugin-prettier": "^5.0.1",
    "jest": "^29.7.0",
    "prettier": "^3.1.0",
    "supertest": "^6.3.3",
    "ts-jest": "^29.1.1",
    "tsx": "^4.2.0",
    "tsup": "^8.0.0",
    "typescript": "^5.3.2"
  },
  "dependencies": {
    "@fastify/cors": "^8.4.0",
    "@fastify/helmet": "^11.1.1",
    "@fastify/rate-limit": "^9.0.1",
    "@fastify/swagger": "^8.12.0",
    "@fastify/swagger-ui": "^2.0.0",
    "@prisma/client": "^5.6.0",
    "bcryptjs": "^2.4.3",
    "fastify": "^4.24.3",
    "ioredis": "^5.3.2",
    "joi": "^17.11.0",
    "jsonwebtoken": "^9.0.2",
    "pino": "^8.16.2",
    "prisma": "^5.6.0",
    "uuid": "^9.0.1"
  },
  "engines": {
    "node": ">=18.0.0"
  }
}
EOF
    echo "✅ Created package.json"
fi

# Create TypeScript configuration
if [ ! -f "tsconfig.json" ]; then
    echo "⚙️ Creating TypeScript configuration..."
    cat > tsconfig.json << 'EOF'
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2022"],
    "module": "CommonJS",
    "moduleResolution": "node",
    "declaration": true,
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "allowSyntheticDefaultImports": true,
    "emitDecoratorMetadata": true,
    "experimentalDecorators": true,
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"]
    }
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
EOF
    echo "✅ Created tsconfig.json"
fi

# Create ESLint configuration
if [ ! -f ".eslintrc.json" ]; then
    echo "🔍 Creating ESLint configuration..."
    cat > .eslintrc.json << 'EOF'
{
  "parser": "@typescript-eslint/parser",
  "extends": [
    "eslint:recommended",
    "@typescript-eslint/recommended",
    "prettier"
  ],
  "plugins": ["@typescript-eslint", "prettier"],
  "parserOptions": {
    "ecmaVersion": 2022,
    "sourceType": "module"
  },
  "rules": {
    "prettier/prettier": "error",
    "@typescript-eslint/no-unused-vars": "error",
    "@typescript-eslint/no-explicit-any": "warn",
    "no-console": "warn"
  },
  "env": {
    "node": true,
    "es6": true,
    "jest": true
  }
}
EOF
    echo "✅ Created .eslintrc.json"
fi

# Create Prettier configuration
if [ ! -f ".prettierrc" ]; then
    echo "💅 Creating Prettier configuration..."
    cat > .prettierrc << 'EOF'
{
  "semi": true,
  "trailingComma": "es5",
  "singleQuote": true,
  "printWidth": 100,
  "tabWidth": 2,
  "useTabs": false
}
EOF
    echo "✅ Created .prettierrc"
fi

# Create Jest configuration
if [ ! -f "jest.config.js" ]; then
    echo "🧪 Creating Jest configuration..."
    cat > jest.config.js << 'EOF'
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/types/**/*.ts',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
};
EOF
    echo "✅ Created jest.config.js"
fi

# Create environment configuration
if [ ! -f ".env.example" ]; then
    echo "🌍 Creating environment configuration..."
    cat > .env.example << 'EOF'
# Server Configuration
NODE_ENV=development
PORT=3000
HOST=0.0.0.0

# JWT Configuration
JWT_SECRET=your-super-secure-jwt-secret-key-change-in-production

# Database Configuration
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=
MYSQL_DATABASE=sprintagentlens_dev

# ClickHouse Configuration  
CLICKHOUSE_HOST=localhost
CLICKHOUSE_PORT=8123
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=
CLICKHOUSE_DATABASE=sprintagentlens_analytics

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# AWS S3 Configuration (for file uploads)
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_REGION=us-east-1
AWS_S3_BUCKET=sprintagentlens-files

# Rate Limiting
RATE_LIMIT_WINDOW=15m
RATE_LIMIT_MAX_REQUESTS=100
AUTH_RATE_LIMIT_MAX=5

# Security
BCRYPT_ROUNDS=12
SESSION_EXPIRE_HOURS=24
ACCOUNT_LOCKOUT_ATTEMPTS=5
ACCOUNT_LOCKOUT_DURATION=30m

# Logging
LOG_LEVEL=info
LOG_FORMAT=json

# Feature Toggles
ENABLE_SWAGGER_UI=true
ENABLE_METRICS=true
ENABLE_AUDIT_LOGGING=true
EOF
    echo "✅ Created .env.example"
fi

# Create .env for development if it doesn't exist
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "✅ Created .env from .env.example"
fi

# Create .gitignore
if [ ! -f ".gitignore" ]; then
    echo "📝 Creating .gitignore..."
    cat > .gitignore << 'EOF'
# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*
pnpm-debug.log*

# Build output
dist/
build/
*.tsbuildinfo

# Environment variables
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# Test coverage
coverage/
.nyc_output/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Logs
logs/
*.log

# Runtime data
pids/
*.pid
*.seed
*.pid.lock

# Prisma
prisma/migrations/
EOF
    echo "✅ Created .gitignore"
fi

# Install dependencies
echo "📦 Installing dependencies..."
if [ "$PACKAGE_MANAGER" = "pnpm" ]; then
    pnpm install
else
    npm install
fi

echo "✅ Dependencies installed successfully"

# Create basic application structure
echo "🏗️ Creating application structure..."

# Create main application file
mkdir -p src
if [ ! -f "src/app.ts" ]; then
    cat > src/app.ts << 'EOF'
import Fastify from 'fastify';
import { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';

const fastify = Fastify({
  logger: {
    level: process.env.LOG_LEVEL || 'info',
  },
}).withTypeProvider<TypeBoxTypeProvider>();

// Register plugins
async function registerPlugins() {
  // Security plugins
  await fastify.register(helmet);
  await fastify.register(cors, {
    origin: process.env.NODE_ENV === 'production' ? false : true,
  });
  
  await fastify.register(rateLimit, {
    max: 100,
    timeWindow: '15 minutes',
  });

  // Health check route
  fastify.get('/health', async () => {
    return { 
      status: 'healthy', 
      timestamp: new Date().toISOString(),
      version: '1.0.0',
    };
  });

  // API routes will be added here
  fastify.get('/', async () => {
    return { 
      message: 'SprintAgentLens Backend API',
      version: '1.0.0',
      docs: '/docs',
    };
  });
}

async function start() {
  try {
    await registerPlugins();
    
    const port = Number(process.env.PORT) || 3000;
    const host = process.env.HOST || '0.0.0.0';
    
    await fastify.listen({ port, host });
    
    console.log(`🚀 SprintAgentLens Backend running on http://${host}:${port}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGINT', async () => {
  await fastify.close();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await fastify.close();
  process.exit(0);
});

start();
EOF
    echo "✅ Created src/app.ts"
fi

# Create basic test file
mkdir -p tests
if [ ! -f "tests/app.test.ts" ]; then
    cat > tests/app.test.ts << 'EOF'
import { test } from '@jest/globals';
import Fastify from 'fastify';

test('health check returns status healthy', async () => {
  const fastify = Fastify();
  
  fastify.get('/health', async () => {
    return { 
      status: 'healthy', 
      timestamp: new Date().toISOString(),
      version: '1.0.0',
    };
  });

  const response = await fastify.inject({
    method: 'GET',
    url: '/health',
  });

  expect(response.statusCode).toBe(200);
  const payload = JSON.parse(response.payload);
  expect(payload.status).toBe('healthy');
});
EOF
    echo "✅ Created tests/app.test.ts"
fi

# Create Dockerfile
if [ ! -f "Dockerfile" ]; then
    echo "🐳 Creating Dockerfile..."
    cat > Dockerfile << 'EOF'
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./
COPY pnpm-lock.yaml* ./

# Install dependencies
RUN npm install -g pnpm && pnpm install --prod

# Copy source code
COPY . .

# Build application
RUN pnpm build

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Start application
CMD ["node", "dist/app.js"]
EOF
    echo "✅ Created Dockerfile"
fi

# Create Docker Compose for development
if [ ! -f "docker-compose.dev.yml" ]; then
    echo "🐳 Creating Docker Compose configuration..."
    cat > docker-compose.dev.yml << 'EOF'
version: '3.8'

services:
  # MySQL Database
  mysql:
    image: mysql:8.0
    container_name: sprintagentlens-mysql
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword
      MYSQL_DATABASE: sprintagentlens_dev
      MYSQL_USER: sprintagentlens
      MYSQL_PASSWORD: password
    ports:
      - "3306:3306"
    volumes:
      - mysql_data:/var/lib/mysql
    restart: unless-stopped

  # Redis Cache
  redis:
    image: redis:7-alpine
    container_name: sprintagentlens-redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped

  # ClickHouse Analytics Database
  clickhouse:
    image: clickhouse/clickhouse-server:latest
    container_name: sprintagentlens-clickhouse
    environment:
      CLICKHOUSE_DB: sprintagentlens_analytics
      CLICKHOUSE_USER: clickhouse
      CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: 1
      CLICKHOUSE_PASSWORD: password
    ports:
      - "8123:8123"
      - "9000:9000"
    volumes:
      - clickhouse_data:/var/lib/clickhouse
    restart: unless-stopped

volumes:
  mysql_data:
  redis_data:
  clickhouse_data:
EOF
    echo "✅ Created docker-compose.dev.yml"
fi

echo ""
echo "🎉 SprintAgentLens Backend development environment setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Start databases: docker-compose -f docker-compose.dev.yml up -d"
echo "2. Set up Prisma: $PACKAGE_MANAGER run db:generate"
echo "3. Run migrations: $PACKAGE_MANAGER run db:migrate"
echo "4. Start development server: $PACKAGE_MANAGER run dev"
echo "5. Run tests: $PACKAGE_MANAGER test"
echo ""
echo "📚 Available commands:"
echo "  $PACKAGE_MANAGER run dev          # Start development server"
echo "  $PACKAGE_MANAGER run build        # Build for production"
echo "  $PACKAGE_MANAGER run test         # Run tests"
echo "  $PACKAGE_MANAGER run lint         # Check code quality"
echo "  $PACKAGE_MANAGER run format       # Format code"
echo "  $PACKAGE_MANAGER run db:migrate   # Run database migrations"
echo ""
echo "🔧 Configuration files created:"
echo "  - package.json (dependencies and scripts)"
echo "  - tsconfig.json (TypeScript configuration)"  
echo "  - .eslintrc.json (code quality rules)"
echo "  - jest.config.js (testing configuration)"
echo "  - .env.example (environment variables template)"
echo "  - Dockerfile (container configuration)"
echo "  - docker-compose.dev.yml (development services)"
echo ""
echo "🌐 The server will run on: http://localhost:3000"
echo "📖 API documentation will be available at: http://localhost:3000/docs"
echo ""
echo "Happy coding! 🚀"
EOF

chmod +x /Users/michaeldsouza/Documents/Wordir/AGENT_LENS/agent_lense/SprintAgentLens/backend/scripts/setup-development.sh