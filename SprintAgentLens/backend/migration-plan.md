# SprintAgentLens Backend Migration Plan

## Migration Overview

This document outlines the comprehensive strategy for migrating the OPIK Java backend (Dropwizard + MySQL + ClickHouse) to a modern JavaScript/TypeScript backend for SprintAgentLens.

## Target Technology Stack

### Core Framework
- **Runtime**: Node.js 18+ with TypeScript 5.x
- **Web Framework**: Fastify 4.x (chosen for performance and TypeScript support)
- **Alternative**: Express.js 4.x (if team prefers familiar ecosystem)

### Database & ORM
- **State Database**: MySQL 8.0+ (maintain compatibility)
- **Analytics Database**: ClickHouse (maintain existing data)
- **ORM**: Prisma 5.x (recommended) or TypeORM
- **Query Builder**: Raw queries for ClickHouse, ORM for MySQL
- **Migrations**: Prisma Migrate or custom migration system

### Authentication & Security
- **Password Hashing**: bcryptjs 2.4.x (maintain BCrypt compatibility)
- **JWT Management**: jsonwebtoken 9.x
- **Session Storage**: Redis 7.x with ioredis
- **Security**: helmet, express-rate-limit, cors
- **Validation**: Joi or Zod for request validation

### Background Processing
- **Job Queue**: Bull/BullMQ with Redis
- **Cron Jobs**: node-cron
- **Async Processing**: Native async/await with proper error handling

### External Integrations
- **LLM Integration**: Custom clients or langchain.js
- **File Storage**: @aws-sdk/client-s3
- **Monitoring**: @opentelemetry/api + @opentelemetry/node
- **Logging**: winston or pino

### Development & Testing
- **Package Manager**: pnpm (recommended) or npm
- **Build Tool**: tsup or tsx for development
- **Testing**: Jest + Supertest
- **Code Quality**: ESLint + Prettier + Husky
- **API Documentation**: Swagger/OpenAPI with fastify-swagger

## Migration Phases

### Phase 1: Foundation Setup (Weeks 1-2)
**Goal**: Establish core infrastructure and authentication

#### Week 1: Project Bootstrap
- [x] Create project structure
- [ ] Initialize Node.js + TypeScript project
- [ ] Configure ESLint, Prettier, and development tools
- [ ] Set up MySQL and Redis connections
- [ ] Create base Fastify application
- [ ] Implement basic logging and error handling
- [ ] Set up environment configuration

#### Week 2: Authentication System (CRITICAL)
- [ ] Implement User model and database schema
- [ ] Create UserSession model and management
- [ ] Implement BCrypt password hashing (maintain compatibility)
- [ ] Build JWT token generation and validation
- [ ] Create authentication middleware
- [ ] Implement login/logout endpoints
- [ ] Add role-based access control (RBAC)
- [ ] Create audit logging system
- [ ] Add rate limiting and security headers

**Deliverables:**
- Working authentication system
- User management endpoints
- Session management
- Security middleware stack

### Phase 2: Core Business Logic (Weeks 3-6)
**Goal**: Migrate primary business entities and APIs

#### Week 3: Projects & Workspaces
- [ ] Implement Project model and CRUD operations
- [ ] Create Workspace management system
- [ ] Add project filtering and sorting
- [ ] Implement bulk operations
- [ ] Create project statistics endpoints
- [ ] Add project-level permissions

#### Week 4: Experiments & Datasets
- [ ] Implement Dataset model and operations
- [ ] Create Experiment model and lifecycle management
- [ ] Add dataset item management
- [ ] Implement experiment item operations
- [ ] Create comparison and grouping functionality
- [ ] Add bulk import/export capabilities

#### Week 5: Basic LLM Integration
- [ ] Create LLM provider abstraction
- [ ] Implement OpenAI client integration
- [ ] Add Anthropic (Claude) support  
- [ ] Create provider API key management
- [ ] Implement basic chat completions endpoint
- [ ] Add token usage tracking

#### Week 6: File Management
- [ ] Implement attachment model and operations
- [ ] Create S3 integration for file storage
- [ ] Add multipart upload support
- [ ] Implement file type validation
- [ ] Create file access control
- [ ] Add bulk file operations

**Deliverables:**
- Core CRUD operations for all major entities
- Basic LLM integration
- File upload/management system
- API compatibility with existing frontend

### Phase 3: Advanced Features (Weeks 7-10)
**Goal**: Implement observability, automation, and advanced LLM features

#### Week 7: Traces & Spans System
- [ ] Design ClickHouse integration architecture
- [ ] Implement Trace model and operations
- [ ] Create Span model and nested operations
- [ ] Add distributed tracing support
- [ ] Implement search and filtering
- [ ] Create streaming endpoints for large datasets

#### Week 8: Feedback & Scoring System
- [ ] Implement FeedbackDefinition model
- [ ] Create feedback scoring system
- [ ] Add numerical and categorical feedback
- [ ] Implement feedback aggregation
- [ ] Create feedback analytics
- [ ] Add feedback search and filtering

#### Week 9: Automation Rules Engine
- [ ] Design automation rule architecture
- [ ] Implement rule evaluation engine
- [ ] Create LLM-as-Judge evaluators
- [ ] Add Python metric evaluators
- [ ] Implement rule scheduling and execution
- [ ] Create rule monitoring and logging

#### Week 10: Background Processing
- [ ] Set up Bull/BullMQ job queues
- [ ] Implement job processors for all background tasks
- [ ] Create job monitoring and retry logic
- [ ] Add scheduled jobs (cron-like functionality)
- [ ] Implement event-driven processing
- [ ] Create job status monitoring endpoints

**Deliverables:**
- Complete observability system
- Automated rule processing
- Robust background job system
- Event-driven architecture

### Phase 4: Testing, Performance & Deployment (Weeks 11-12)
**Goal**: Ensure production readiness

#### Week 11: Comprehensive Testing
- [ ] Write unit tests for all models and services
- [ ] Create integration tests for API endpoints
- [ ] Add authentication and authorization tests
- [ ] Implement database integration tests
- [ ] Create end-to-end API tests
- [ ] Add performance benchmarks
- [ ] Test data migration scripts

#### Week 12: Production Preparation
- [ ] Optimize database queries and indexes
- [ ] Implement comprehensive monitoring
- [ ] Set up logging and alerting
- [ ] Create deployment scripts and Docker images
- [ ] Implement health checks
- [ ] Create API documentation
- [ ] Perform security audit
- [ ] Load testing and performance tuning

**Deliverables:**
- Production-ready application
- Complete test coverage
- Deployment automation
- Monitoring and alerting system

## Authentication Migration Strategy (Critical Priority)

### Current Java Implementation Analysis
```java
// Password hashing with salt concatenation
public static String hashPassword(String password, String salt) {
    return BCrypt.hashpw(password + salt, BCrypt.gensalt(12));
}

// Password verification
public boolean verifyPassword(String password, String salt, String hash) {
    return BCrypt.checkpw(password + salt, hash);
}
```

### JavaScript Implementation Strategy
```typescript
// Maintain exact compatibility with Java implementation
import bcrypt from 'bcryptjs';

export class AuthService {
  private static readonly SALT_ROUNDS = 12;

  static async hashPassword(password: string, salt: string): Promise<string> {
    // Maintain Java compatibility: concatenate password + salt
    const combined = password + salt;
    return bcrypt.hash(combined, this.SALT_ROUNDS);
  }

  static async verifyPassword(
    password: string, 
    salt: string, 
    hash: string
  ): Promise<boolean> {
    const combined = password + salt;
    return bcrypt.compare(combined, hash);
  }

  static generateSalt(): string {
    // Generate random salt (maintain existing format)
    return crypto.randomBytes(16).toString('hex');
  }
}
```

### User Model Structure
```typescript
interface User {
  id: string;
  username: string;
  email: string;
  fullName: string;
  role: 'admin' | 'user' | 'viewer';
  passwordHash: string;
  salt: string;
  isActive: boolean;
  workspaceId: string;
  createdAt: Date;
  lastLoginAt?: Date;
  failedLoginAttempts: number;
  accountLockedUntil?: Date;
}

interface UserSession {
  id: string;
  userId: string;
  sessionToken: string;
  expiresAt: Date;
  ipAddress: string;
  userAgent: string;
  createdAt: Date;
}
```

## Database Migration Strategy

### MySQL Schema Migration
1. **Preserve Existing Schema**: Keep current table structures
2. **ORM Mapping**: Create Prisma schemas matching existing tables
3. **Data Integrity**: Ensure no data loss during migration
4. **Backward Compatibility**: Maintain API response formats

### ClickHouse Integration
```typescript
// ClickHouse client setup
import { createClient } from '@clickhouse/client';

const clickhouse = createClient({
  host: process.env.CLICKHOUSE_HOST,
  username: process.env.CLICKHOUSE_USER,
  password: process.env.CLICKHOUSE_PASSWORD,
  database: process.env.CLICKHOUSE_DB,
});

// Example query implementation
export class TraceService {
  static async createTrace(trace: Trace): Promise<void> {
    await clickhouse.insert({
      table: 'traces',
      values: [trace],
      format: 'JSONEachRow',
    });
  }

  static async searchTraces(criteria: TraceCriteria): Promise<Trace[]> {
    const result = await clickhouse.query({
      query: `SELECT * FROM traces WHERE project_id = {project_id:String}`,
      query_params: { project_id: criteria.projectId },
      format: 'JSONEachRow',
    });
    
    return result.json<Trace[]>();
  }
}
```

### Migration Scripts
```typescript
// Database migration utility
export class MigrationService {
  static async migrateUsers(): Promise<void> {
    // Migrate users from Java format to Node.js format
    // Ensure password hashes remain compatible
  }

  static async verifyDataIntegrity(): Promise<boolean> {
    // Verify data consistency between old and new systems
  }

  static async createIndexes(): Promise<void> {
    // Create necessary indexes for performance
  }
}
```

## API Compatibility Strategy

### Request/Response Format Compatibility
- Maintain exact JSON structures
- Preserve HTTP status codes
- Keep pagination formats identical
- Ensure error message compatibility

### Endpoint Mapping
```typescript
// Maintain exact endpoint structure
const routes = {
  // Authentication
  'POST /v1/enterprise/auth/login': AuthController.login,
  'POST /v1/enterprise/auth/logout': AuthController.logout,
  'GET /v1/enterprise/auth/status': AuthController.status,
  
  // Projects  
  'GET /v1/private/projects': ProjectController.list,
  'POST /v1/private/projects': ProjectController.create,
  'GET /v1/private/projects/:id': ProjectController.getById,
  'PATCH /v1/private/projects/:id': ProjectController.update,
  'DELETE /v1/private/projects/:id': ProjectController.delete,
  
  // Continue for all endpoints...
};
```

## Development Workflow

### Project Structure
```
backend/
├── src/
│   ├── controllers/           # HTTP request handlers
│   ├── services/             # Business logic
│   ├── models/               # Data models and schemas
│   ├── middleware/           # Authentication, validation, etc.
│   ├── utils/                # Utility functions
│   ├── config/               # Configuration management
│   ├── jobs/                 # Background job processors
│   ├── types/                # TypeScript type definitions
│   └── app.ts                # Application entry point
├── tests/
│   ├── unit/                 # Unit tests
│   ├── integration/          # Integration tests
│   └── e2e/                  # End-to-end tests
├── prisma/
│   ├── schema.prisma         # Database schema
│   └── migrations/           # Database migrations
├── docs/                     # API documentation
├── scripts/                  # Build and deployment scripts
└── package.json
```

### Development Commands
```bash
# Development
npm run dev          # Start development server
npm run build        # Build for production
npm run test         # Run tests
npm run test:watch   # Watch mode testing
npm run lint         # Lint code
npm run format       # Format code

# Database
npm run db:migrate   # Run migrations
npm run db:seed      # Seed database
npm run db:reset     # Reset database

# Production
npm start            # Start production server
npm run docker:build # Build Docker image
```

## Risk Mitigation

### High-Risk Areas
1. **Authentication Compatibility**: Ensure password hashes work identically
2. **Database Performance**: ClickHouse queries may need optimization
3. **LLM Integration**: Provider-specific implementation differences
4. **Background Jobs**: Ensure job processing reliability
5. **File Handling**: S3 integration and multipart uploads

### Mitigation Strategies
1. **Comprehensive Testing**: Unit, integration, and end-to-end tests
2. **Gradual Migration**: Feature-by-feature migration with parallel running
3. **Data Validation**: Extensive data integrity checks
4. **Performance Monitoring**: Real-time performance tracking
5. **Rollback Plans**: Ability to quickly revert to Java system

## Success Metrics

### Technical Metrics
- [ ] 100% API endpoint compatibility
- [ ] <200ms average response time
- [ ] >99.9% uptime
- [ ] Zero authentication failures
- [ ] Complete test coverage (>90%)

### Business Metrics
- [ ] Zero data loss during migration
- [ ] No service interruption
- [ ] Maintained user experience
- [ ] Full feature parity
- [ ] Successful authentication for all existing users

## Post-Migration Optimization

### Performance Improvements
1. **Database Optimization**: Query optimization, proper indexing
2. **Caching Strategy**: Redis caching for frequently accessed data
3. **Connection Pooling**: Optimize database connections
4. **Memory Management**: Proper garbage collection and memory usage

### Monitoring & Observability
1. **Application Metrics**: Request rates, response times, error rates
2. **Database Metrics**: Query performance, connection pool status
3. **Business Metrics**: User activity, API usage patterns
4. **Alert System**: Proactive issue detection and notification

This migration plan ensures a systematic, low-risk transition from the Java backend to a modern JavaScript/TypeScript backend while maintaining full compatibility and improving maintainability.