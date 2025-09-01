# SprintAgentLens Backend

Enterprise AI observability and evaluation platform backend built with Node.js, TypeScript, and Fastify.

## 🚀 Quick Start

### Prerequisites

- Node.js 18+
- MySQL 8.0+
- Redis 7.x
- pnpm (recommended) or npm

### Installation

1. **Install dependencies**
   ```bash
   pnpm install
   ```

2. **Set up environment**
   ```bash
   cp .env.example .env
   # Edit .env with your database credentials
   ```

3. **Set up database**
   ```bash
   # Create database
   mysql -u root -e "CREATE DATABASE sprintagentlens_dev"
   
   # Run migrations
   pnpm run db:migrate
   
   # Seed with admin user
   pnpm run db:seed
   ```

4. **Start development server**
   ```bash
   pnpm run dev
   ```

The server will start at `http://localhost:3000`

- **API Documentation**: http://localhost:3000/docs
- **Health Check**: http://localhost:3000/health

## 🔐 Default Credentials

After running the seed script:

- **Admin**: `admin` / `OpikAdmin2024!`
- **Test User** (dev only): `testuser` / `OpikAdmin2024!`

⚠️ **Change the admin password immediately in production!**

## 📁 Project Structure

```
backend/
├── src/
│   ├── config/          # Configuration and database setup
│   ├── controllers/     # HTTP request handlers
│   ├── middleware/      # Authentication, validation, etc.
│   ├── services/        # Business logic services
│   ├── types/           # TypeScript type definitions
│   ├── utils/           # Utility functions and helpers
│   └── server.ts        # Application entry point
├── tests/
│   ├── unit/           # Unit tests
│   ├── integration/    # Integration tests
│   └── e2e/           # End-to-end tests
├── prisma/
│   ├── schema.prisma   # Database schema
│   └── migrations/     # Database migrations
└── scripts/            # Build and deployment scripts
```

## 🛡️ Authentication System

### Features

✅ **Enterprise-grade authentication** with:
- BCrypt password hashing (12 rounds) with salt
- JWT token management with Redis session storage
- Role-based access control (Admin, User, Viewer)
- Account lockout protection (5 failed attempts)
- Comprehensive audit logging
- Rate limiting and security headers

✅ **100% Java backend compatibility**:
- Password verification uses `password + salt` concatenation
- Maintains exact same hashing behavior as OPIK Java backend
- Seamless migration path for existing users

### API Endpoints

#### Authentication
```
POST   /v1/enterprise/auth/login      # User authentication
POST   /v1/enterprise/auth/logout     # Session termination
GET    /v1/enterprise/auth/status     # Check authentication status
POST   /v1/enterprise/auth/create-user # Create user (admin only)
```

### Example Usage

```bash
# Login
curl -X POST http://localhost:3000/v1/enterprise/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "OpikAdmin2024!",
    "workspaceId": "default"
  }'

# Use returned token for authenticated requests
curl -X GET http://localhost:3000/v1/enterprise/auth/status \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## 🧪 Testing

### Run Tests

```bash
# All tests
pnpm test

# Unit tests only
pnpm run test:unit

# Integration tests only
pnpm run test:integration

# With coverage
pnpm run test:coverage

# Watch mode
pnpm run test:watch
```

### Test Database Setup

Tests use a separate `sprintagentlens_test` database:

```bash
# Create test database
mysql -u root -e "CREATE DATABASE sprintagentlens_test"
```

Tests automatically handle database migrations and cleanup.

## 🔧 Development

### Available Scripts

```bash
# Development
pnpm run dev          # Start with hot reload
pnpm run build        # Build for production
pnpm run start        # Start production server

# Database
pnpm run db:generate  # Generate Prisma client
pnpm run db:migrate   # Run database migrations
pnpm run db:seed      # Seed database with test data
pnpm run db:reset     # Reset database (caution!)

# Code Quality
pnpm run lint         # Run ESLint
pnpm run lint:fix     # Fix linting issues
pnpm run format       # Format code with Prettier
pnpm run type-check   # TypeScript type checking
```

### Environment Variables

Key configuration options in `.env`:

```env
# Application
NODE_ENV=development
PORT=3000

# Database
DATABASE_URL="mysql://user:password@host:port/database"
REDIS_URL="redis://localhost:6379"

# Security
JWT_SECRET=your-jwt-secret
BCRYPT_ROUNDS=12
ACCOUNT_LOCKOUT_ATTEMPTS=5

# Features
AUTH_ENABLED=true
ANALYTICS_ENABLED=true
DEBUG_ENABLED=true
```

## 🚢 Deployment

### Production Build

```bash
# Build application
pnpm run build

# Run database migrations
NODE_ENV=production pnpm run db:migrate

# Start production server
NODE_ENV=production pnpm start
```

### Docker Deployment

```bash
# Build image
docker build -t sprintagentlens-backend .

# Run container
docker run -p 3000:3000 \
  -e DATABASE_URL="mysql://..." \
  -e REDIS_URL="redis://..." \
  sprintagentlens-backend
```

## 📊 Monitoring

### Health Check

```bash
curl http://localhost:3000/health
```

Returns application status, version, and uptime information.

### Logging

Structured JSON logging with Pino:
- Request/response logging
- Authentication events
- Security violations
- Database operations
- Error tracking

### Metrics

Built-in metrics collection for:
- Request counts and latencies
- Authentication success/failure rates
- Database query performance
- Session management statistics

## 🔒 Security Features

### Authentication Security
- **Password Hashing**: BCrypt with 12 rounds + custom salt
- **Session Management**: JWT with Redis storage
- **Account Protection**: Lockout after 5 failed attempts
- **Audit Logging**: All authentication events tracked
- **IP Tracking**: Request source monitoring

### API Security
- **Rate Limiting**: 100 requests per 15 minutes (configurable)
- **CORS**: Configurable cross-origin policies
- **Security Headers**: Helmet.js protection
- **Input Validation**: Joi schema validation
- **SQL Injection Protection**: Prisma parameterized queries

### Authorization
- **Role-Based Access Control**: Admin, User, Viewer roles
- **Permission System**: Granular resource permissions
- **Workspace Isolation**: Multi-tenant support
- **Session Validation**: Automatic token refresh

## 📈 Performance

### Optimizations
- **Fastify Framework**: High-performance Node.js web framework
- **Connection Pooling**: Optimized database connections
- **Redis Caching**: Session and application caching
- **Structured Logging**: Low-overhead Pino logger
- **TypeScript**: Compile-time optimizations

### Benchmarks
- **Cold Start**: < 2 seconds
- **Authentication**: < 50ms average
- **Database Queries**: < 10ms average (local MySQL)
- **Memory Usage**: < 100MB baseline

## 🗺️ Migration Status

### Phase 1: Foundation ✅ COMPLETED
- [x] Project setup and configuration
- [x] Fastify web framework with plugins
- [x] Prisma ORM with MySQL integration
- [x] Enterprise authentication system
- [x] JWT and session management
- [x] Role-based access control
- [x] Comprehensive test suite
- [x] Security middleware stack

### Phase 2: Core Business Logic (Next)
- [ ] Projects and workspace management
- [ ] Experiments and datasets
- [ ] LLM provider integration
- [ ] Basic observability features

See [`migration-plan.md`](migration-plan.md) for complete roadmap.

## 🤝 Contributing

1. **Development Setup**
   ```bash
   git clone <repository>
   cd SprintAgentLens/backend
   pnpm install
   cp .env.example .env
   pnpm run db:migrate
   pnpm run db:seed
   ```

2. **Make Changes**
   - Follow existing code style
   - Add tests for new features
   - Update documentation

3. **Submit Changes**
   ```bash
   pnpm run lint
   pnpm run test
   pnpm run type-check
   git commit -m "Your changes"
   ```

### Code Style
- **ESLint** + **Prettier** for formatting
- **TypeScript strict mode** for type safety
- **Jest** for testing
- **Conventional Commits** for commit messages

## 📚 API Documentation

Interactive API documentation available at `/docs` when server is running:

- **Swagger UI**: Complete API specification
- **Authentication**: Bearer token examples
- **Request/Response**: Full schemas and examples
- **Error Codes**: Comprehensive error documentation

## 🆘 Troubleshooting

### Common Issues

**Database Connection Failed**
```bash
# Check MySQL is running
mysql -u root -p -e "SELECT 1"

# Verify database exists
mysql -u root -p -e "SHOW DATABASES"

# Check DATABASE_URL format
DATABASE_URL="mysql://user:password@host:port/database"
```

**Redis Connection Failed**
```bash
# Check Redis is running
redis-cli ping

# Verify Redis URL
REDIS_URL="redis://localhost:6379"
```

**Authentication Issues**
```bash
# Check JWT secret is set
JWT_SECRET=your-secret-key

# Verify admin user exists
pnpm run db:seed
```

**Test Failures**
```bash
# Ensure test database exists
mysql -u root -e "CREATE DATABASE sprintagentlens_test"

# Clean test environment
pnpm run db:reset
```

## 📄 License

MIT License - see [LICENSE](../LICENSE) file for details.

## 🔗 Links

- **Project Repository**: https://github.com/Mikehem/SprintAgentLens
- **Documentation**: [docs/](../docs/)
- **Migration Plan**: [migration-plan.md](migration-plan.md)
- **Feature Documentation**: [features.md](features.md)

---

**SprintAgentLens Backend** - Enterprise AI observability and evaluation platform.

Built with ❤️ using Node.js, TypeScript, and modern web technologies.