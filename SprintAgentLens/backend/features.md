# SprintAgentLens Backend Features & API Documentation

## Overview
This document comprehensively details all APIs, features, and technical architecture of the current OPIK Java backend that needs to be migrated to SprintAgentLens JavaScript backend.

## Current Technical Stack

### Core Framework & Libraries
- **Framework**: Dropwizard 4.0.14 (JAX-RS, Jersey, Jetty)
- **Dependency Injection**: Google Guice with Dropwizard-Guicey 7.2.1
- **Build Tool**: Maven with Java 21
- **Main Class**: `com.comet.opik.OpikApplication`

### Database Systems
- **State Database**: MySQL 9.4.0 with JDBI 3.x
- **Analytics Database**: ClickHouse with clickhouse-java 0.9.0  
- **Database Migrations**: Liquibase with ClickHouse support
- **Connection Pooling**: HikariCP (via Dropwizard)

### Authentication & Security
- **Authentication**: Database-backed with custom implementation
- **Password Hashing**: BCrypt with 12 rounds + custom salt logic
- **Session Management**: JWT tokens with Redis storage
- **Authorization**: Role-based access control (Admin, User, Viewer)
- **Security Features**: Account lockout, audit logging, rate limiting

### Caching & Background Processing
- **Caching**: Redis with Redisson 3.51.0
- **Background Jobs**: Quartz Scheduler
- **Async Processing**: Custom async utilities and context management

### External Integrations
- **LLM Providers**: LangChain4J with multiple providers
  - OpenAI, Anthropic, Google Gemini, Vertex AI, OpenRouter
- **File Storage**: AWS S3 SDK 2.32.4
- **Monitoring**: OpenTelemetry instrumentation 2.19.0
- **Message Queues**: Redis pub/sub for events

## API Endpoints & Resources

### 1. Authentication & Authorization

#### EnterpriseAuthResource (`/v1/enterprise/auth/`)
**Critical Feature - High Priority**

| Endpoint | Method | Description | Request | Response |
|----------|--------|-------------|---------|----------|
| `/login` | POST | User authentication | `LoginRequest` | `LoginResponse` |
| `/logout` | POST | User session termination | JWT Token | Status |
| `/status` | GET | Check auth status | JWT Token | User info |
| `/generate-hash` | POST | Generate password hash | Password + Salt | BCrypt hash |

**Key Features:**
- BCrypt password hashing with custom salt concatenation
- JWT session token generation and validation
- IP tracking and User-Agent logging  
- Account lockout protection
- Comprehensive audit logging
- Enterprise-level security standards

#### AuthResource (`/v1/auth/`)
**Legacy authentication endpoints for backward compatibility**

### 2. Projects Management

#### ProjectsResource (`/v1/private/projects/`)
**Core business logic - High Priority**

| Endpoint | Method | Description | Request | Response |
|----------|--------|-------------|---------|----------|
| `/` | GET | List projects | Pagination + Filters | `Page<Project>` |
| `/` | POST | Create project | `Project` | `Project` |
| `/{id}` | GET | Get project by ID | UUID | `ProjectRetrieve` |
| `/{id}` | PATCH | Update project | `ProjectUpdate` | `Project` |
| `/{id}` | DELETE | Delete project | UUID | Status |
| `/batch-delete` | DELETE | Bulk delete projects | `BatchDelete` | Status |
| `/{id}/feedback-scores/names` | GET | Get feedback score names | UUID | `FeedbackScoreNames` |
| `/{id}/stats-summary` | GET | Get project statistics | UUID | `ProjectStatsSummary` |
| `/{id}/metrics` | POST | Get project metrics | `ProjectMetricRequest` | `ProjectMetricResponse` |

**Features:**
- Project lifecycle management
- Bulk operations support
- Comprehensive filtering and sorting
- Statistics and metrics aggregation
- Feedback score integration

### 3. Experiments & Datasets

#### ExperimentsResource (`/v1/private/experiments/`)
**AI/ML Experimentation - High Priority**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | List experiments |
| `/` | POST | Create experiment |
| `/{id}` | GET | Get experiment details |
| `/{id}` | PATCH | Update experiment |
| `/{id}` | DELETE | Delete experiment |
| `/batch-delete` | DELETE | Bulk delete experiments |
| `/{datasetId}/compare` | GET | Compare experiments |
| `/{id}/feedback-scores/names` | GET | Get feedback scores |
| `/{id}/items` | GET, POST | Manage experiment items |
| `/{id}/groups` | GET | Get experiment groups |

#### DatasetsResource (`/v1/private/datasets/`)
**Dataset Management - High Priority**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET, POST | List/Create datasets |
| `/{id}` | GET, PATCH, DELETE | Dataset operations |
| `/{id}/items` | GET, POST | Dataset items CRUD |
| `/{id}/items/{itemId}` | GET, PATCH, DELETE | Item operations |
| `/{id}/items/batch` | POST | Bulk item operations |

### 4. Observability & Tracing

#### TracesResource (`/v1/private/traces/`)
**Distributed Tracing - Medium Priority**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET, POST | List/Create traces |
| `/{id}` | GET, PATCH, DELETE | Trace operations |
| `/batch` | POST | Bulk trace creation |
| `/search/stream` | POST | Stream trace search |
| `/{id}/feedback-scores` | GET, POST | Trace feedback |

#### SpansResource (`/v1/private/spans/`)
**Span Management - Medium Priority**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET, POST | List/Create spans |
| `/{id}` | GET, PATCH, DELETE | Span operations |
| `/batch` | POST | Bulk span creation |
| `/search/stream` | POST | Stream span search |

### 5. LLM Integration & Chat

#### ChatCompletionsResource (`/v1/private/chat/completions`)
**LLM Chat Interface - High Priority**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | POST | Chat completions |
| `/stream` | POST | Streaming chat |

**Supported Providers:**
- OpenAI (GPT models)
- Anthropic (Claude models) 
- Google Gemini
- Vertex AI
- Custom LLM endpoints

#### LlmProviderApiKeyResource (`/v1/private/llm-providers/api-keys`)
**LLM Provider Management**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET, POST | List/Create API keys |
| `/{id}` | GET, PATCH, DELETE | API key operations |

### 6. Feedback & Scoring

#### FeedbackDefinitionResource (`/v1/private/feedback-definitions/`)
**Feedback System - Medium Priority**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET, POST | List/Create definitions |
| `/{id}` | GET, PATCH, DELETE | Definition operations |
| `/batch-delete` | DELETE | Bulk delete |

**Feedback Types:**
- Numerical feedback (ratings, scores)
- Categorical feedback (thumbs up/down, classifications)
- Custom feedback schemas

### 7. Automation & Rules

#### AutomationRuleEvaluatorsResource (`/v1/private/automation-rule-evaluators/`)
**Automation Engine - Medium Priority**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET, POST | List/Create rules |
| `/{id}` | GET, PATCH, DELETE | Rule operations |
| `/{id}/logs` | GET | Rule execution logs |

**Evaluator Types:**
- LLM as Judge evaluators
- User-defined Python metric evaluators
- Trace thread evaluators

### 8. File Management & Attachments

#### AttachmentResource (`/v1/private/attachments/`)
**File Handling - Medium Priority**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET, POST | List/Create attachments |
| `/{id}` | GET, DELETE | Attachment operations |
| `/multipart-upload/start` | POST | Start multipart upload |
| `/multipart-upload/complete` | POST | Complete multipart upload |
| `/batch-delete` | DELETE | Bulk delete attachments |

**Supported File Types:**
- Images (PNG, JPG, GIF, SVG)
- Documents (PDF, TXT)
- Audio (WAV, MP3)
- Video (WEBM)
- JSON files

### 9. User & Workspace Management

#### AdminResource (`/v1/private/admin/`)
**Admin Functions - High Priority**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/users` | GET, POST | List/Create users |
| `/users/{id}` | GET, PATCH, DELETE | User operations |
| `/users/{id}/change-password` | POST | Change user password |

#### WorkspacesResource (`/v1/private/workspaces/`)
**Workspace Management - High Priority**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/configurations` | GET, POST | Workspace configs |
| `/metadata` | GET | Workspace metadata |
| `/metrics` | POST | Workspace metrics |
| `/metrics/summary` | POST | Metrics summary |

### 10. Prompt Management

#### PromptResource (`/v1/private/prompts/`)
**Prompt Library - Medium Priority**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET, POST | List/Create prompts |
| `/{id}` | GET, PATCH, DELETE | Prompt operations |
| `/{id}/versions` | GET, POST | Version management |

## Database Schemas

### MySQL State Database (db-app-state)

**Core Tables:**
- `users` - User accounts and authentication
- `user_sessions` - Active user sessions
- `user_audit_log` - Authentication audit trail
- `projects` - Project definitions
- `datasets` - Dataset metadata
- `experiments` - Experiment configurations
- `prompt_versions` - Prompt library
- `feedback_definitions` - Feedback schemas
- `automation_rules` - Automation configurations
- `automation_rule_evaluators` - Rule evaluators
- `llm_provider_api_keys` - LLM API keys
- `workspace_configurations` - Workspace settings

### ClickHouse Analytics Database (db-app-analytics)

**Core Tables:**
- `traces` - Distributed trace data
- `spans` - Span execution data
- `feedback_scores` - Feedback and ratings
- `experiment_items` - Experiment results
- `dataset_items` - Dataset entries
- `comments` - User comments
- `attachments` - File attachments
- `automation_rule_evaluator_logs` - Rule execution logs
- `trace_threads` - Thread management
- `optimizations` - Optimization results

## Security Features

### Authentication Security
- **Password Hashing**: BCrypt with 12 rounds
- **Salt Strategy**: Custom concatenation (password + salt)
- **Session Management**: JWT with Redis storage
- **Account Lockout**: Failed attempt protection
- **Audit Logging**: Comprehensive access logs
- **IP Tracking**: Request source monitoring

### Authorization Levels
- **Admin**: Full system access, user management
- **User**: Standard project access
- **Viewer**: Read-only access
- **Project-level**: Resource-specific permissions

### API Security
- **Rate Limiting**: Request throttling per user/IP
- **CORS**: Configurable cross-origin policies
- **Input Validation**: Comprehensive request validation
- **SQL Injection Protection**: Parameterized queries
- **XSS Protection**: Output sanitization

## Background Processing

### Job Types
- **Trace Thread Closing**: Automatic thread closure
- **Usage Reporting**: Daily usage statistics
- **Optimization Processing**: ML model optimization
- **File Processing**: Attachment handling
- **Notification Processing**: Alert delivery

### Event System
- **Trace Events**: Created, updated, deleted
- **Dataset Events**: CRUD operations
- **Experiment Events**: Lifecycle management
- **User Events**: Authentication, authorization
- **System Events**: Health checks, metrics

## Monitoring & Observability

### Metrics Collection
- **Application Metrics**: Request counts, latencies
- **Database Metrics**: Query performance, connections
- **Cache Metrics**: Hit rates, memory usage
- **LLM Metrics**: Token usage, costs
- **System Metrics**: CPU, memory, disk

### Health Checks
- **Database Connectivity**: MySQL, ClickHouse
- **Cache Connectivity**: Redis
- **External Services**: S3, LLM providers
- **Application Health**: Service status

## Configuration Management

### Environment Variables
- Database connection strings
- Redis configuration
- S3 credentials
- LLM provider API keys
- Feature toggles
- Rate limiting settings

### Feature Toggles
- Authentication modes
- LLM provider selection  
- Analytics collection
- Background job processing
- Debug logging levels

## Migration Priority Matrix

### Critical (Week 1-2)
1. Authentication & Authorization system
2. User & Session management
3. Basic project CRUD operations
4. Database connectivity (MySQL)

### High Priority (Week 3-4)
1. Experiments & Datasets APIs
2. Workspace management
3. LLM integration basics
4. File attachment handling

### Medium Priority (Week 5-8)
1. Traces & Spans system
2. Feedback & Scoring
3. Automation rules
4. Background job processing
5. Comprehensive monitoring

### Low Priority (Week 9-12)
1. Advanced analytics
2. Optimization features
3. Complex reporting
4. Performance optimizations

This comprehensive feature documentation serves as the blueprint for the SprintAgentLens JavaScript backend implementation, ensuring no critical functionality is lost during migration.