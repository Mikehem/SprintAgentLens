# SprintAgentLens

A modern AI observability and evaluation platform built with Node.js/TypeScript, migrated from the OPIK Java backend architecture.

## Overview

SprintAgentLens is the next-generation evolution of the OPIK platform, providing comprehensive AI model observability, experimentation, and evaluation capabilities with a focus on enterprise-grade security and scalability.

### Key Features

🔐 **Enterprise Authentication**
- Database-backed user management
- BCrypt password hashing with custom salt logic
- JWT session management with Redis storage
- Role-based access control (Admin, User, Viewer)
- Account lockout protection and audit logging

🚀 **AI Observability**
- Distributed tracing for AI applications
- Comprehensive span and trace analytics
- Real-time performance monitoring
- Cost tracking and optimization

🧪 **Experimentation Platform**
- A/B testing for AI models
- Dataset management and versioning
- Experiment comparison and analysis
- Automated evaluation pipelines

🤖 **LLM Integration**
- Multi-provider LLM support (OpenAI, Anthropic, Google, etc.)
- Chat completions API
- Token usage tracking and cost optimization
- Provider API key management

📊 **Analytics & Insights**
- Advanced metrics and dashboards
- Custom feedback scoring systems
- Automated rule evaluation
- Business intelligence integration

## Architecture

### Technology Stack

**Backend**
- **Runtime**: Node.js 18+ with TypeScript 5.x
- **Framework**: Fastify 4.x (high-performance, TypeScript-first)
- **Database**: MySQL 8.0+ (state) + ClickHouse (analytics)
- **ORM**: Prisma 5.x for MySQL, native client for ClickHouse
- **Cache**: Redis 7.x with ioredis
- **Authentication**: JWT tokens with bcryptjs

**Security & Infrastructure**
- **Security**: Helmet, CORS, Rate limiting
- **Background Jobs**: Bull/BullMQ with Redis
- **File Storage**: AWS S3 SDK
- **Monitoring**: OpenTelemetry integration
- **Logging**: Structured logging with Pino

### Project Structure

```
SprintAgentLens/
├── backend/                 # Node.js/TypeScript backend
│   ├── src/                # Source code
│   │   ├── controllers/    # HTTP request handlers
│   │   ├── services/       # Business logic
│   │   ├── models/         # Data models and schemas
│   │   ├── middleware/     # Authentication, validation, etc.
│   │   ├── utils/          # Utility functions
│   │   ├── config/         # Configuration management
│   │   ├── jobs/           # Background job processors
│   │   └── types/          # TypeScript type definitions
│   ├── tests/              # Test suites
│   ├── docs/               # API documentation
│   ├── scripts/            # Build and deployment scripts
│   ├── features.md         # Complete API feature documentation
│   └── migration-plan.md   # Java-to-JavaScript migration strategy
├── frontend/               # Future frontend implementation
├── shared/                 # Shared utilities and types
├── docs/                   # Project documentation
└── README.md
```

## Quick Start

### Prerequisites

- Node.js 18 or higher
- MySQL 8.0+
- Redis 7.x
- ClickHouse (for analytics)
- Docker & Docker Compose (optional, for development)

### Development Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd SprintAgentLens/backend
   ```

2. **Run the setup script**
   ```bash
   ./scripts/setup-development.sh
   ```

3. **Start development services**
   ```bash
   docker-compose -f docker-compose.dev.yml up -d
   ```

4. **Install dependencies**
   ```bash
   pnpm install  # or npm install
   ```

5. **Set up the database**
   ```bash
   pnpm run db:generate
   pnpm run db:migrate
   pnpm run db:seed
   ```

6. **Start the development server**
   ```bash
   pnpm run dev
   ```

The API will be available at `http://localhost:3000`

### API Documentation

Once the server is running, visit:
- API Docs: `http://localhost:3000/docs`
- Health Check: `http://localhost:3000/health`

### Testing

```bash
# Run all tests
pnpm test

# Run tests in watch mode
pnpm run test:watch

# Run tests with coverage
pnpm run test:coverage
```

## Migration from OPIK Java Backend

This project is a complete migration from the original OPIK Java backend (Dropwizard) to modern Node.js/TypeScript architecture while maintaining 100% API compatibility.

### Migration Highlights

- ✅ **Authentication Compatibility**: Maintains exact BCrypt password hashing logic
- ✅ **API Compatibility**: All REST endpoints preserved with identical request/response formats
- ✅ **Database Schema**: Compatible with existing MySQL and ClickHouse databases
- ✅ **Feature Parity**: All business logic and features migrated
- ✅ **Performance**: Improved response times and resource efficiency

### Migration Documentation

See detailed migration information:
- [`backend/features.md`](backend/features.md) - Complete API and feature documentation
- [`backend/migration-plan.md`](backend/migration-plan.md) - Detailed migration strategy
- [`backend/docs/authentication-specification.md`](backend/docs/authentication-specification.md) - Authentication system details

## API Overview

### Core Endpoints

#### Authentication
```
POST   /v1/enterprise/auth/login      # User login
POST   /v1/enterprise/auth/logout     # User logout  
GET    /v1/enterprise/auth/status     # Check auth status
```

#### Projects
```
GET    /v1/private/projects           # List projects
POST   /v1/private/projects           # Create project
GET    /v1/private/projects/{id}      # Get project
PATCH  /v1/private/projects/{id}      # Update project
DELETE /v1/private/projects/{id}      # Delete project
```

#### Experiments & Datasets
```
GET    /v1/private/experiments        # List experiments
POST   /v1/private/experiments        # Create experiment
GET    /v1/private/datasets           # List datasets
POST   /v1/private/datasets           # Create dataset
```

#### Tracing & Observability
```
GET    /v1/private/traces            # List traces
POST   /v1/private/traces            # Create trace
GET    /v1/private/spans             # List spans
POST   /v1/private/spans             # Create span
```

#### LLM Integration
```
POST   /v1/private/chat/completions  # Chat completions
GET    /v1/private/llm-providers     # List LLM providers
```

For complete API documentation, see [`backend/features.md`](backend/features.md).

## Security Features

### Authentication Security
- **Password Hashing**: BCrypt with 12 rounds + custom salt logic
- **Session Management**: JWT tokens with Redis storage and expiration
- **Account Protection**: Failed login attempt tracking and account lockout
- **Audit Logging**: Comprehensive authentication and action logging
- **IP Tracking**: Request source monitoring and validation

### API Security
- **Rate Limiting**: Configurable request throttling per user/IP
- **CORS**: Controlled cross-origin resource sharing
- **Input Validation**: Comprehensive request validation with Joi
- **SQL Injection Protection**: Parameterized queries and ORM safety
- **XSS Protection**: Output sanitization and security headers

### Authorization
- **Role-Based Access Control**: Admin, User, and Viewer roles
- **Resource-Level Permissions**: Project and workspace-specific access
- **JWT Token Validation**: Secure token verification and refresh
- **Session Management**: Automatic session cleanup and validation

## Development

### Available Scripts

```bash
# Development
pnpm run dev          # Start development server with hot reload
pnpm run build        # Build for production
pnpm run start        # Start production server

# Testing
pnpm test             # Run all tests
pnpm run test:watch   # Run tests in watch mode
pnpm run test:coverage # Run tests with coverage report

# Code Quality
pnpm run lint         # Check code quality with ESLint
pnpm run lint:fix     # Fix linting issues automatically
pnpm run format       # Format code with Prettier
pnpm run type-check   # TypeScript type checking

# Database
pnpm run db:migrate   # Run database migrations
pnpm run db:generate  # Generate Prisma client
pnpm run db:seed      # Seed database with test data
pnpm run db:reset     # Reset database (caution: deletes data)

# Docker
pnpm run docker:build # Build Docker image
pnpm run docker:run   # Run Docker container
```

### Environment Configuration

Copy `.env.example` to `.env` and configure:

```env
# Server
NODE_ENV=development
PORT=3000

# Database
MYSQL_HOST=localhost
MYSQL_DATABASE=sprintagentlens_dev
CLICKHOUSE_HOST=localhost

# Security
JWT_SECRET=your-secure-secret
BCRYPT_ROUNDS=12

# External Services
AWS_S3_BUCKET=your-bucket
REDIS_URL=redis://localhost:6379
```

### Code Style

This project uses:
- **ESLint** for code quality
- **Prettier** for code formatting  
- **TypeScript strict mode** for type safety
- **Husky** for git hooks
- **Jest** for testing

## Deployment

### Production Deployment

1. **Build the application**
   ```bash
   pnpm run build
   ```

2. **Set up production environment**
   ```bash
   cp .env.example .env.production
   # Edit .env.production with production values
   ```

3. **Run database migrations**
   ```bash
   NODE_ENV=production pnpm run db:migrate
   ```

4. **Start the application**
   ```bash
   NODE_ENV=production pnpm start
   ```

### Docker Deployment

```bash
# Build image
docker build -t sprintagentlens-backend .

# Run container
docker run -p 3000:3000 -e NODE_ENV=production sprintagentlens-backend
```

### Docker Compose

```yaml
version: '3.8'
services:
  backend:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - MYSQL_HOST=mysql
      - REDIS_URL=redis://redis:6379
    depends_on:
      - mysql
      - redis
  
  mysql:
    image: mysql:8.0
    environment:
      MYSQL_DATABASE: sprintagentlens
      MYSQL_ROOT_PASSWORD: secure-password
  
  redis:
    image: redis:7-alpine
```

## Monitoring & Observability

### Health Checks
- Application health endpoint: `/health`
- Database connectivity checks
- Redis connectivity validation
- External service status monitoring

### Metrics
- Request/response metrics
- Database query performance
- Authentication success/failure rates
- LLM token usage and costs
- Background job processing stats

### Logging
- Structured JSON logging with Pino
- Request/response logging
- Error tracking and alerting
- Authentication audit logs
- Business event logging

## Contributing

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/your-feature`
3. **Make changes and add tests**
4. **Run tests**: `pnpm test`
5. **Check code quality**: `pnpm run lint && pnpm run type-check`
6. **Commit changes**: `git commit -m "Add your feature"`
7. **Push to branch**: `git push origin feature/your-feature`
8. **Create Pull Request**

### Development Guidelines

- Write tests for all new features
- Follow TypeScript strict mode
- Use meaningful commit messages
- Update documentation for API changes
- Ensure backward compatibility when possible

## Migration Utilities

The project includes comprehensive migration utilities for transitioning from the OPIK Java backend:

```bash
# Export data from Java backend
./scripts/migration-utilities.sh export_users
./scripts/migration-utilities.sh export_projects

# Import data to Node.js backend  
./scripts/migration-utilities.sh import_users

# Verify password compatibility
./scripts/migration-utilities.sh verify_password_compatibility

# Run complete migration
./scripts/migration-utilities.sh full_migration
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

## Support

For support and questions:
- 📧 Email: support@sprintagentlens.com
- 📖 Documentation: [docs/](docs/)
- 🐛 Bug Reports: [GitHub Issues](../../issues)
- 💬 Discussions: [GitHub Discussions](../../discussions)

## Roadmap

### Phase 1 (Completed)
- ✅ Project structure setup
- ✅ Complete feature documentation
- ✅ Migration planning and strategy
- ✅ Authentication system specification

### Phase 2 (In Progress)
- 🔄 Core authentication implementation
- 🔄 Database schema migration
- 🔄 Basic API endpoints
- 🔄 Testing framework setup

### Phase 3 (Planned)
- 📋 LLM integration
- 📋 Observability features
- 📋 Background job processing
- 📋 Advanced analytics

### Phase 4 (Future)
- 📋 Performance optimizations
- 📋 Advanced monitoring
- 📋 Horizontal scaling
- 📋 Plugin architecture

---

**SprintAgentLens** - Empowering AI development with comprehensive observability and evaluation tools.

Built with ❤️ using Node.js, TypeScript, and modern web technologies.