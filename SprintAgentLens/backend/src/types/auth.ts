/**
 * Authentication and authorization type definitions
 * Maintains compatibility with OPIK Java backend
 */

export interface LoginRequest {
  username: string;
  password: string;
  workspaceId?: string;
}

export interface LoginResponse {
  success: boolean;
  token: string;
  user: PublicUserInfo;
  expiresIn: number;
  workspaceId: string;
}

export interface PublicUserInfo {
  id: string;
  username: string;
  email: string;
  fullName: string | null;
  role: UserRole;
  workspaceId: string;
  isActive: boolean;
  lastLoginAt: Date | null;
}

export interface AuthenticatedUser extends PublicUserInfo {
  sessionId: string;
  permissions: string[];
}

export interface JwtPayload {
  userId: string;
  username: string;
  role: UserRole;
  workspaceId: string;
  sessionId: string;
  iat: number;
  exp: number;
}

export interface SessionInfo {
  id: string;
  userId: string;
  sessionToken: string;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: Date;
  expiresAt: Date;
  lastUsedAt: Date;
}

export interface CreateUserRequest {
  username: string;
  email: string;
  fullName?: string;
  password: string;
  role?: UserRole;
  workspaceId?: string;
}

export interface UpdateUserRequest {
  email?: string;
  fullName?: string;
  role?: UserRole;
  isActive?: boolean;
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
}

export interface AuthenticationResult {
  success: boolean;
  user?: PublicUserInfo;
  token?: string;
  sessionId?: string;
  error?: string;
  reason?: 'invalid_credentials' | 'account_locked' | 'account_disabled' | 'server_error';
}

export interface AuthContext {
  ipAddress: string | null;
  userAgent: string | null;
  requestId: string;
  timestamp: Date;
}

export interface SecuritySettings {
  maxFailedAttempts: number;
  lockoutDurationMinutes: number;
  sessionExpirySeconds: number;
  bcryptRounds: number;
  jwtExpiryTime: string;
}

export interface AuditLogEntry {
  event: string;
  eventType: AuditEventType;
  userId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  requestId: string | null;
  description?: string;
  metadata?: Record<string, any>;
  timestamp: Date;
}

export enum UserRole {
  ADMIN = 'ADMIN',
  USER = 'USER', 
  VIEWER = 'VIEWER',
}

export enum AuditEventType {
  LOGIN = 'LOGIN',
  LOGOUT = 'LOGOUT',
  LOGIN_FAILED = 'LOGIN_FAILED',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  ACCOUNT_UNLOCKED = 'ACCOUNT_UNLOCKED',
  PASSWORD_CHANGED = 'PASSWORD_CHANGED',
  USER_CREATED = 'USER_CREATED',
  USER_UPDATED = 'USER_UPDATED',
  USER_DELETED = 'USER_DELETED',
  PERMISSION_DENIED = 'PERMISSION_DENIED',
}

export interface PasswordHashResult {
  hash: string;
  salt: string;
}

export interface PasswordValidationResult {
  isValid: boolean;
  shouldLockAccount?: boolean;
  attemptsRemaining?: number;
}

// Rate limiting types
export interface RateLimitInfo {
  remaining: number;
  reset: Date;
  total: number;
}

// Middleware types
export interface AuthMiddlewareOptions {
  required?: boolean;
  roles?: UserRole[];
  permissions?: string[];
}

// Session management
export interface SessionCleanupResult {
  expiredSessions: number;
  cleanedSessions: number;
}

// API Response types
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  code?: string;
  timestamp: string;
}

export interface ApiError {
  message: string;
  code: string;
  statusCode: number;
  details?: Record<string, any>;
}

// Permission system
export interface Permission {
  resource: string;
  action: string;
  scope?: 'own' | 'workspace' | 'global';
}

export interface RolePermissions {
  role: UserRole;
  permissions: Permission[];
}