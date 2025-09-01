/**
 * LLM Provider Service - Enterprise LLM provider management with authentication
 * Provides secure API key management and workspace isolation
 */

import { PrismaClient } from '@prisma/client';
import { logger } from '@/utils/logger';
import crypto from 'crypto';
import type { AuthenticatedUser } from '@/types/auth';
import type {
  CreateLLMProviderRequest,
  UpdateLLMProviderRequest,
  LLMProviderResponse,
  LLMProviderListRequest,
  LLMProviderListResponse,
  LLMProviderUsageStats,
  LLMProviderHealthCheckRequest,
  LLMProviderHealthCheckResponse,
  BulkLLMProviderOperationRequest,
  BulkLLMProviderOperationResponse,
  LLMChatRequest,
  LLMChatResponse,
  LLMStreamRequest,
  LLMEmbeddingRequest,
  LLMEmbeddingResponse,
  LLMProviderConfiguration,
  LLMProviderType,
  LLMProviderStatus,
  LLMProviderPermissionChecker,
  LLMProviderNotFoundError,
  LLMProviderPermissionError,
  LLMProviderValidationError,
  LLMProviderConfigurationError,
  LLMProviderRateLimitError,
  LLMProviderQuotaExceededError,
  DEFAULT_LLM_PROVIDERS,
  LLM_VALIDATION_RULES,
} from '@/types/llm';

export class LLMProviderService implements LLMProviderPermissionChecker {
  private static prisma = new PrismaClient();
  private static encryptionKey = process.env.LLM_ENCRYPTION_KEY || 'default-key-change-in-production';

  // Permission checking methods
  static canCreateProvider(user: AuthenticatedUser, workspaceId: string): boolean {
    if (user.role === 'admin') return true;
    if (user.role === 'viewer') return false;
    return user.role === 'user' && user.workspaceId === workspaceId;
  }

  static canReadProvider(user: AuthenticatedUser, provider: any): boolean {
    if (user.role === 'admin') return true;
    return provider.workspaceId === user.workspaceId;
  }

  static canEditProvider(user: AuthenticatedUser, provider: any): boolean {
    if (user.role === 'admin') return true;
    if (user.role === 'viewer') return false;
    return provider.workspaceId === user.workspaceId && user.role === 'user';
  }

  static canDeleteProvider(user: AuthenticatedUser, provider: any): boolean {
    if (user.role === 'admin') return true;
    if (user.role === 'viewer') return false;
    return provider.workspaceId === user.workspaceId && user.role === 'user';
  }

  static canUseProvider(user: AuthenticatedUser, provider: any): boolean {
    if (user.role === 'admin') return true;
    return provider.workspaceId === user.workspaceId && provider.isActive;
  }

  static canViewUsage(user: AuthenticatedUser, provider: any): boolean {
    return this.canReadProvider(user, provider);
  }

  static canManageKeys(user: AuthenticatedUser, provider: any): boolean {
    if (user.role === 'admin') return true;
    if (user.role === 'viewer') return false;
    return provider.workspaceId === user.workspaceId && user.role === 'user';
  }

  // Encryption methods for API keys
  private static encryptApiKey(apiKey: string): string {
    const cipher = crypto.createCipher('aes-256-cbc', this.encryptionKey);
    let encrypted = cipher.update(apiKey, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  }

  private static decryptApiKey(encryptedKey: string): string {
    const decipher = crypto.createDecipher('aes-256-cbc', this.encryptionKey);
    let decrypted = decipher.update(encryptedKey, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  private static generateKeyHash(apiKey: string): string {
    return crypto.createHash('sha256').update(apiKey).digest('hex');
  }

  // Validation methods
  private static validateProviderName(name: string): void {
    const { minLength, maxLength, pattern } = LLM_VALIDATION_RULES.name;
    
    if (!name || name.length < minLength) {
      throw new LLMProviderValidationError('name', `Name must be at least ${minLength} characters`);
    }
    if (name.length > maxLength) {
      throw new LLMProviderValidationError('name', `Name cannot exceed ${maxLength} characters`);
    }
    if (!pattern.test(name)) {
      throw new LLMProviderValidationError('name', 'Name contains invalid characters');
    }
  }

  private static validateApiKey(apiKey: string): void {
    const { minLength, maxLength } = LLM_VALIDATION_RULES.apiKey;
    
    if (!apiKey || apiKey.length < minLength) {
      throw new LLMProviderValidationError('apiKey', `API key must be at least ${minLength} characters`);
    }
    if (apiKey.length > maxLength) {
      throw new LLMProviderValidationError('apiKey', `API key cannot exceed ${maxLength} characters`);
    }
  }

  private static validateConfiguration(configuration: LLMProviderConfiguration): void {
    const configString = JSON.stringify(configuration);
    if (configString.length > LLM_VALIDATION_RULES.configuration.maxSizeBytes) {
      throw new LLMProviderValidationError('configuration', 
        `Configuration size exceeds maximum of ${LLM_VALIDATION_RULES.configuration.maxSizeBytes} bytes`);
    }

    // Validate provider-specific configuration
    if (!configuration.supportedModels || configuration.supportedModels.length === 0) {
      throw new LLMProviderValidationError('configuration.supportedModels', 
        'At least one supported model must be specified');
    }

    if (!configuration.capabilities) {
      throw new LLMProviderValidationError('configuration.capabilities', 
        'Provider capabilities must be specified');
    }

    if (!configuration.rateLimits) {
      throw new LLMProviderValidationError('configuration.rateLimits', 
        'Rate limits must be specified');
    }

    if (!configuration.costConfig) {
      throw new LLMProviderValidationError('configuration.costConfig', 
        'Cost configuration must be specified');
    }
  }

  private static validateTags(tags?: string[]): void {
    if (!tags) return;
    
    const { maxCount, maxTagLength } = LLM_VALIDATION_RULES.tags;
    
    if (tags.length > maxCount) {
      throw new LLMProviderValidationError('tags', `Cannot have more than ${maxCount} tags`);
    }
    
    for (const tag of tags) {
      if (tag.length > maxTagLength) {
        throw new LLMProviderValidationError('tags', 
          `Tag "${tag}" cannot exceed ${maxTagLength} characters`);
      }
    }
  }

  // Core CRUD operations
  static async createProvider(
    request: CreateLLMProviderRequest,
    user: AuthenticatedUser
  ): Promise<LLMProviderResponse> {
    logger.info('Creating LLM provider', { 
      name: request.name, 
      type: request.type,
      workspaceId: request.workspaceId,
      userId: user.id 
    });

    // Validate request
    this.validateProviderName(request.name);
    this.validateApiKey(request.encryptedApiKey);
    this.validateConfiguration(request.configuration);
    this.validateTags(request.tags);

    // Check workspace permissions
    if (request.workspaceId !== user.workspaceId) {
      throw new LLMProviderPermissionError('create', 'workspace mismatch');
    }

    // Check if user can create providers
    if (!this.canCreateProvider(user, request.workspaceId)) {
      throw new LLMProviderPermissionError('create', request.workspaceId);
    }

    // Check for duplicate provider names in workspace
    const existingProvider = await this.prisma.llmProviderApiKey.findFirst({
      where: {
        name: request.name,
        workspaceId: request.workspaceId,
      },
    });

    if (existingProvider) {
      throw new LLMProviderValidationError('name', 
        `Provider with name "${request.name}" already exists in this workspace`);
    }

    // Encrypt API key and generate hash
    const encryptedKey = this.encryptApiKey(request.encryptedApiKey);
    const keyHash = this.generateKeyHash(request.encryptedApiKey);

    // Merge with default configuration for the provider type
    const defaultConfig = DEFAULT_LLM_PROVIDERS[request.type] || {};
    const finalConfiguration = {
      ...defaultConfig,
      ...request.configuration,
      name: request.name,
      type: request.type,
    };

    try {
      const provider = await this.prisma.llmProviderApiKey.create({
        data: {
          name: request.name,
          provider: request.type,
          encryptedKey,
          keyHash,
          workspaceId: request.workspaceId,
          isActive: request.isActive ?? true,
          configuration: JSON.stringify(finalConfiguration),
          tags: request.tags || [],
          usageCount: 0,
          createdBy: user.id,
          lastUpdatedBy: user.id,
        },
      });

      logger.info('LLM provider created successfully', { 
        providerId: provider.id, 
        name: provider.name,
        type: provider.provider,
        userId: user.id 
      });

      return this.formatProviderResponse(provider, user);
    } catch (error) {
      logger.error('Failed to create LLM provider', { 
        name: request.name, 
        type: request.type,
        error 
      });
      throw error;
    }
  }

  static async getProviderById(
    providerId: string,
    user: AuthenticatedUser
  ): Promise<LLMProviderResponse> {
    const provider = await this.prisma.llmProviderApiKey.findUnique({
      where: { id: providerId },
    });

    if (!provider) {
      throw new LLMProviderNotFoundError(providerId);
    }

    // Check workspace isolation
    if (!this.canReadProvider(user, provider)) {
      throw new LLMProviderPermissionError('read', providerId);
    }

    return this.formatProviderResponse(provider, user);
  }

  static async updateProvider(
    providerId: string,
    request: UpdateLLMProviderRequest,
    user: AuthenticatedUser
  ): Promise<LLMProviderResponse> {
    logger.info('Updating LLM provider', { providerId, userId: user.id });

    const provider = await this.prisma.llmProviderApiKey.findUnique({
      where: { id: providerId },
    });

    if (!provider) {
      throw new LLMProviderNotFoundError(providerId);
    }

    if (!this.canEditProvider(user, provider)) {
      throw new LLMProviderPermissionError('update', providerId);
    }

    // Validate updates
    if (request.name !== undefined) {
      this.validateProviderName(request.name);
    }
    if (request.encryptedApiKey !== undefined) {
      this.validateApiKey(request.encryptedApiKey);
    }
    if (request.configuration !== undefined) {
      // Merge with existing configuration
      const existingConfig = provider.configuration ? 
        JSON.parse(provider.configuration as string) : {};
      const updatedConfig = { ...existingConfig, ...request.configuration };
      this.validateConfiguration(updatedConfig);
    }
    if (request.tags !== undefined) {
      this.validateTags(request.tags);
    }

    // Prepare update data
    const updateData: any = {
      lastUpdatedBy: user.id,
      lastUpdatedAt: new Date(),
    };

    if (request.name) updateData.name = request.name;
    if (request.isActive !== undefined) updateData.isActive = request.isActive;
    if (request.tags) updateData.tags = request.tags;

    if (request.encryptedApiKey) {
      updateData.encryptedKey = this.encryptApiKey(request.encryptedApiKey);
      updateData.keyHash = this.generateKeyHash(request.encryptedApiKey);
    }

    if (request.configuration) {
      const existingConfig = provider.configuration ? 
        JSON.parse(provider.configuration as string) : {};
      const updatedConfig = { ...existingConfig, ...request.configuration };
      updateData.configuration = JSON.stringify(updatedConfig);
    }

    const updatedProvider = await this.prisma.llmProviderApiKey.update({
      where: { id: providerId },
      data: updateData,
    });

    logger.info('LLM provider updated successfully', { providerId, userId: user.id });
    return this.formatProviderResponse(updatedProvider, user);
  }

  static async deleteProvider(
    providerId: string,
    user: AuthenticatedUser
  ): Promise<void> {
    logger.info('Deleting LLM provider', { providerId, userId: user.id });

    const provider = await this.prisma.llmProviderApiKey.findUnique({
      where: { id: providerId },
    });

    if (!provider) {
      throw new LLMProviderNotFoundError(providerId);
    }

    if (!this.canDeleteProvider(user, provider)) {
      throw new LLMProviderPermissionError('delete', providerId);
    }

    // Check if provider is being used by any active experiments
    const activeExperiments = await this.prisma.experiment.count({
      where: {
        workspaceId: user.workspaceId,
        status: { in: ['running', 'queued'] },
        configuration: {
          path: ['modelProvider'],
          equals: provider.provider,
        },
      },
    });

    if (activeExperiments > 0) {
      throw new LLMProviderConfigurationError(provider.name, 
        `Cannot delete provider while ${activeExperiments} experiments are using it`);
    }

    // Delete provider
    await this.prisma.llmProviderApiKey.delete({
      where: { id: providerId },
    });

    logger.info('LLM provider deleted successfully', { providerId, userId: user.id });
  }

  static async listProviders(
    request: LLMProviderListRequest,
    user: AuthenticatedUser
  ): Promise<LLMProviderListResponse> {
    const page = Math.max(1, request.page || 1);
    const limit = Math.min(100, Math.max(1, request.limit || 20));
    const offset = (page - 1) * limit;

    // Build where conditions with workspace isolation
    const whereConditions: any = {
      workspaceId: user.workspaceId, // Enforce workspace isolation
    };

    if (request.type?.length) {
      whereConditions.provider = { in: request.type };
    }

    if (request.isActive !== undefined) {
      whereConditions.isActive = request.isActive;
    }

    if (request.tags?.length) {
      whereConditions.tags = { hasSome: request.tags };
    }

    if (request.search) {
      whereConditions.OR = [
        { name: { contains: request.search, mode: 'insensitive' } },
        { provider: { contains: request.search, mode: 'insensitive' } },
      ];
    }

    // Build order by
    const orderBy: any = {};
    const sortBy = request.sortBy || 'created_at';
    const sortOrder = request.sortOrder || 'desc';
    
    if (sortBy === 'created_at') {
      orderBy.createdAt = sortOrder;
    } else if (sortBy === 'name') {
      orderBy.name = sortOrder;
    } else if (sortBy === 'type') {
      orderBy.provider = sortOrder;
    } else if (sortBy === 'last_used_at') {
      orderBy.lastUsedAt = sortOrder;
    } else if (sortBy === 'usage_count') {
      orderBy.usageCount = sortOrder;
    }

    const [providers, total] = await Promise.all([
      this.prisma.llmProviderApiKey.findMany({
        where: whereConditions,
        orderBy,
        skip: offset,
        take: limit,
      }),
      this.prisma.llmProviderApiKey.count({ where: whereConditions }),
    ]);

    const formattedProviders = providers.map(provider => 
      this.formatProviderResponse(provider, user)
    );

    // Calculate aggregations
    const typeCounts = await this.calculateTypeCounts(whereConditions);
    const statusCounts = await this.calculateStatusCounts(whereConditions);
    const totalCost = await this.calculateTotalCost(whereConditions);
    const totalUsage = await this.calculateTotalUsage(whereConditions);

    return {
      providers: formattedProviders,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
      filters: {
        workspaceId: request.workspaceId,
        type: request.type,
        status: request.status,
        tags: request.tags,
      },
      sorting: {
        sortBy,
        sortOrder,
      },
      aggregations: {
        typeCounts,
        statusCounts,
        totalCost,
        totalUsage,
      },
    };
  }

  // Chat completion method
  static async chatCompletion(
    request: LLMChatRequest,
    user: AuthenticatedUser
  ): Promise<LLMChatResponse> {
    logger.info('Processing chat completion', { 
      providerId: request.providerId,
      model: request.model,
      userId: user.id 
    });

    const provider = await this.getProviderById(request.providerId, user);
    
    if (!this.canUseProvider(user, provider)) {
      throw new LLMProviderPermissionError('use', request.providerId);
    }

    if (!provider.isActive) {
      throw new LLMProviderConfigurationError(provider.name, 'Provider is not active');
    }

    // This would implement the actual LLM API calls
    // For now, return a placeholder response
    throw new Error('Chat completion not implemented yet');
  }

  // Provider health check
  static async healthCheck(
    request: LLMProviderHealthCheckRequest,
    user: AuthenticatedUser
  ): Promise<LLMProviderHealthCheckResponse> {
    const provider = await this.getProviderById(request.providerId, user);
    
    if (!this.canReadProvider(user, provider)) {
      throw new LLMProviderPermissionError('health_check', request.providerId);
    }

    // This would implement actual health checks
    // For now, return a placeholder response
    throw new Error('Health check not implemented yet');
  }

  // Helper methods
  private static formatProviderResponse(provider: any, user: AuthenticatedUser): LLMProviderResponse {
    const configuration = provider.configuration ? 
      JSON.parse(provider.configuration) : DEFAULT_LLM_PROVIDERS[provider.provider as LLMProviderType];
    
    return {
      id: provider.id,
      name: provider.name,
      type: provider.provider as LLMProviderType,
      workspaceId: provider.workspaceId,
      workspaceName: '', // Would be populated with actual workspace name
      configuration,
      hasApiKey: !!provider.encryptedKey,
      isActive: provider.isActive,
      tags: provider.tags || [],
      status: provider.isActive ? 'active' : 'inactive',
      lastUsedAt: provider.lastUsedAt,
      usageCount: provider.usageCount,
      totalCost: 0, // Would be calculated from usage data
      createdAt: provider.createdAt,
      createdBy: provider.createdBy,
      createdByName: '', // Would be populated with user name
      lastUpdatedAt: provider.lastUpdatedAt,
      lastUpdatedBy: provider.lastUpdatedBy,
      lastUpdatedByName: '', // Would be populated with user name
      // Permissions
      canRead: this.canReadProvider(user, provider),
      canEdit: this.canEditProvider(user, provider),
      canDelete: this.canDeleteProvider(user, provider),
      canUse: this.canUseProvider(user, provider),
      canViewUsage: this.canViewUsage(user, provider),
      canManageKeys: this.canManageKeys(user, provider),
    };
  }

  private static async calculateTypeCounts(whereConditions: any): Promise<Record<LLMProviderType, number>> {
    const counts = await this.prisma.llmProviderApiKey.groupBy({
      by: ['provider'],
      where: whereConditions,
      _count: true,
    });

    const typeCounts: any = {};
    counts.forEach(count => {
      typeCounts[count.provider as LLMProviderType] = count._count;
    });

    return typeCounts;
  }

  private static async calculateStatusCounts(whereConditions: any): Promise<Record<LLMProviderStatus, number>> {
    // This would calculate status based on isActive and other factors
    // For now, return basic counts
    const activeCounts = await this.prisma.llmProviderApiKey.groupBy({
      by: ['isActive'],
      where: whereConditions,
      _count: true,
    });

    const statusCounts: any = { active: 0, inactive: 0 };
    activeCounts.forEach(count => {
      if (count.isActive) {
        statusCounts.active = count._count;
      } else {
        statusCounts.inactive = count._count;
      }
    });

    return statusCounts;
  }

  private static async calculateTotalCost(whereConditions: any): Promise<number> {
    // This would calculate total cost from usage data
    // For now, return 0
    return 0;
  }

  private static async calculateTotalUsage(whereConditions: any): Promise<number> {
    const result = await this.prisma.llmProviderApiKey.aggregate({
      where: whereConditions,
      _sum: {
        usageCount: true,
      },
    });

    return result._sum.usageCount || 0;
  }

  // Placeholder methods for future implementation
  static async getProviderUsage(
    providerId: string,
    timeRange: { start: Date; end: Date },
    user: AuthenticatedUser
  ): Promise<LLMProviderUsageStats> {
    // Implementation would fetch usage stats from ClickHouse
    throw new Error('Provider usage stats not implemented yet');
  }

  static async bulkProviderOperation(
    request: BulkLLMProviderOperationRequest,
    user: AuthenticatedUser
  ): Promise<BulkLLMProviderOperationResponse> {
    // Implementation would handle bulk operations
    throw new Error('Bulk provider operations not implemented yet');
  }

  static async streamChatCompletion(
    request: LLMStreamRequest,
    user: AuthenticatedUser
  ): Promise<AsyncIterable<any>> {
    // Implementation would handle streaming responses
    throw new Error('Streaming chat completion not implemented yet');
  }

  static async generateEmbedding(
    request: LLMEmbeddingRequest,
    user: AuthenticatedUser
  ): Promise<LLMEmbeddingResponse> {
    // Implementation would generate embeddings
    throw new Error('Embedding generation not implemented yet');
  }
}