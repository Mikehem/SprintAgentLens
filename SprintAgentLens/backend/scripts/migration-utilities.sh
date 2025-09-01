#!/bin/bash

# SprintAgentLens Migration Utilities
# This script provides utilities for migrating data from OPIK Java backend

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
JAVA_BACKEND_DB_HOST=${JAVA_DB_HOST:-"localhost"}
JAVA_BACKEND_DB_PORT=${JAVA_DB_PORT:-"3306"}
JAVA_BACKEND_DB_NAME=${JAVA_DB_NAME:-"opik"}
JAVA_BACKEND_DB_USER=${JAVA_DB_USER:-"root"}

NODE_BACKEND_DB_HOST=${NODE_DB_HOST:-"localhost"}
NODE_BACKEND_DB_PORT=${NODE_DB_PORT:-"3306"}
NODE_BACKEND_DB_NAME=${NODE_DB_NAME:-"sprintagentlens_dev"}
NODE_BACKEND_DB_USER=${NODE_DB_USER:-"root"}

echo -e "${BLUE}🔄 SprintAgentLens Migration Utilities${NC}"
echo "======================================"

# Function to check if MySQL is available
check_mysql_connection() {
    local host=$1
    local port=$2
    local user=$3
    local db=$4
    
    echo -e "${YELLOW}Checking MySQL connection to ${host}:${port}/${db}...${NC}"
    
    if mysql -h"$host" -P"$port" -u"$user" -p -e "USE $db;" 2>/dev/null; then
        echo -e "${GREEN}✅ Connected successfully${NC}"
        return 0
    else
        echo -e "${RED}❌ Connection failed${NC}"
        return 1
    fi
}

# Function to export users from Java backend
export_users() {
    echo -e "${BLUE}📤 Exporting users from OPIK Java backend...${NC}"
    
    mysql -h"$JAVA_BACKEND_DB_HOST" -P"$JAVA_BACKEND_DB_PORT" -u"$JAVA_BACKEND_DB_USER" -p \
        -e "SELECT 
                id,
                username,
                email,
                full_name,
                role,
                password_hash,
                salt,
                is_active,
                workspace_id,
                created_at,
                created_by,
                last_updated_at,
                last_updated_by,
                last_login_at,
                failed_login_attempts,
                account_locked_until
            FROM $JAVA_BACKEND_DB_NAME.users;" \
        --batch --raw > users_export.tsv
    
    if [ -f "users_export.tsv" ]; then
        local user_count=$(wc -l < users_export.tsv)
        echo -e "${GREEN}✅ Exported $((user_count - 1)) users to users_export.tsv${NC}"
    else
        echo -e "${RED}❌ Failed to export users${NC}"
        exit 1
    fi
}

# Function to import users to Node.js backend
import_users() {
    echo -e "${BLUE}📥 Importing users to SprintAgentLens backend...${NC}"
    
    if [ ! -f "users_export.tsv" ]; then
        echo -e "${RED}❌ users_export.tsv not found. Run export_users first.${NC}"
        exit 1
    fi
    
    # Create SQL script for importing users
    cat > import_users.sql << 'EOF'
-- Import users while maintaining password hash compatibility
LOAD DATA LOCAL INFILE 'users_export.tsv'
INTO TABLE users
FIELDS TERMINATED BY '\t'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS
(id, username, email, full_name, role, password_hash, salt, is_active, 
 workspace_id, created_at, created_by, last_updated_at, last_updated_by, 
 last_login_at, failed_login_attempts, account_locked_until);
EOF

    mysql -h"$NODE_BACKEND_DB_HOST" -P"$NODE_BACKEND_DB_PORT" -u"$NODE_BACKEND_DB_USER" -p \
        --local-infile=1 "$NODE_BACKEND_DB_NAME" < import_users.sql
    
    echo -e "${GREEN}✅ Users imported successfully${NC}"
    rm -f import_users.sql
}

# Function to verify password hash compatibility
verify_password_compatibility() {
    echo -e "${BLUE}🔐 Verifying password hash compatibility...${NC}"
    
    # Create a Node.js script to test password verification
    cat > verify_passwords.js << 'EOF'
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');

async function verifyPasswords() {
    const connection = await mysql.createConnection({
        host: process.env.NODE_DB_HOST || 'localhost',
        port: process.env.NODE_DB_PORT || 3306,
        user: process.env.NODE_DB_USER || 'root',
        password: process.env.NODE_DB_PASSWORD || '',
        database: process.env.NODE_DB_NAME || 'sprintagentlens_dev',
    });

    // Test with known admin credentials
    const [rows] = await connection.execute(
        'SELECT username, password_hash, salt FROM users WHERE username = ? LIMIT 1',
        ['admin']
    );

    if (rows.length === 0) {
        console.log('❌ Admin user not found');
        return false;
    }

    const user = rows[0];
    const testPassword = 'OpikAdmin2024!'; // Known test password
    
    // Test Java compatibility: password + salt before BCrypt
    const combined = testPassword + user.salt;
    const isValid = await bcrypt.compare(combined, user.password_hash);
    
    if (isValid) {
        console.log('✅ Password hash compatibility verified');
        return true;
    } else {
        console.log('❌ Password hash compatibility failed');
        return false;
    }
}

verifyPasswords().then(success => {
    process.exit(success ? 0 : 1);
}).catch(err => {
    console.error('Error:', err);
    process.exit(1);
});
EOF

    if node verify_passwords.js; then
        echo -e "${GREEN}✅ Password hashes are compatible${NC}"
    else
        echo -e "${RED}❌ Password hash compatibility issue detected${NC}"
        echo -e "${YELLOW}💡 Check that the Node.js AuthService uses password + salt concatenation${NC}"
    fi
    
    rm -f verify_passwords.js
}

# Function to export projects
export_projects() {
    echo -e "${BLUE}📤 Exporting projects from OPIK Java backend...${NC}"
    
    mysql -h"$JAVA_BACKEND_DB_HOST" -P"$JAVA_BACKEND_DB_PORT" -u"$JAVA_BACKEND_DB_USER" -p \
        -e "SELECT * FROM $JAVA_BACKEND_DB_NAME.projects;" \
        --batch --raw > projects_export.tsv
    
    if [ -f "projects_export.tsv" ]; then
        local project_count=$(wc -l < projects_export.tsv)
        echo -e "${GREEN}✅ Exported $((project_count - 1)) projects to projects_export.tsv${NC}"
    else
        echo -e "${RED}❌ Failed to export projects${NC}"
        exit 1
    fi
}

# Function to export datasets
export_datasets() {
    echo -e "${BLUE}📤 Exporting datasets from OPIK Java backend...${NC}"
    
    mysql -h"$JAVA_BACKEND_DB_HOST" -P"$JAVA_BACKEND_DB_PORT" -u"$JAVA_BACKEND_DB_USER" -p \
        -e "SELECT * FROM $JAVA_BACKEND_DB_NAME.datasets;" \
        --batch --raw > datasets_export.tsv
    
    if [ -f "datasets_export.tsv" ]; then
        local dataset_count=$(wc -l < datasets_export.tsv)
        echo -e "${GREEN}✅ Exported $((dataset_count - 1)) datasets to datasets_export.tsv${NC}"
    else
        echo -e "${RED}❌ Failed to export datasets${NC}"
        exit 1
    fi
}

# Function to run complete data migration
full_migration() {
    echo -e "${BLUE}🚀 Running complete data migration...${NC}"
    
    # Check connections
    echo -e "${YELLOW}Checking source database connection...${NC}"
    if ! check_mysql_connection "$JAVA_BACKEND_DB_HOST" "$JAVA_BACKEND_DB_PORT" "$JAVA_BACKEND_DB_USER" "$JAVA_BACKEND_DB_NAME"; then
        echo -e "${RED}❌ Cannot connect to source database${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}Checking destination database connection...${NC}"
    if ! check_mysql_connection "$NODE_BACKEND_DB_HOST" "$NODE_BACKEND_DB_PORT" "$NODE_BACKEND_DB_USER" "$NODE_BACKEND_DB_NAME"; then
        echo -e "${RED}❌ Cannot connect to destination database${NC}"
        exit 1
    fi
    
    # Export data
    export_users
    export_projects
    export_datasets
    
    # Import data (users only for now, as we need to implement other tables)
    import_users
    
    # Verify
    verify_password_compatibility
    
    echo -e "${GREEN}✅ Migration completed successfully${NC}"
}

# Function to create backup
create_backup() {
    local backup_name="sprintagentlens_backup_$(date +%Y%m%d_%H%M%S)"
    
    echo -e "${BLUE}💾 Creating backup: $backup_name${NC}"
    
    mysqldump -h"$NODE_BACKEND_DB_HOST" -P"$NODE_BACKEND_DB_PORT" -u"$NODE_BACKEND_DB_USER" -p \
        "$NODE_BACKEND_DB_NAME" > "$backup_name.sql"
    
    if [ -f "$backup_name.sql" ]; then
        echo -e "${GREEN}✅ Backup created: $backup_name.sql${NC}"
    else
        echo -e "${RED}❌ Backup failed${NC}"
        exit 1
    fi
}

# Function to restore backup
restore_backup() {
    local backup_file=$1
    
    if [ -z "$backup_file" ]; then
        echo -e "${RED}❌ Please specify backup file${NC}"
        echo "Usage: $0 restore_backup backup_file.sql"
        exit 1
    fi
    
    if [ ! -f "$backup_file" ]; then
        echo -e "${RED}❌ Backup file not found: $backup_file${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}⚠️  This will overwrite the current database. Continue? (y/N)${NC}"
    read -r confirm
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}📥 Restoring from backup: $backup_file${NC}"
        
        mysql -h"$NODE_BACKEND_DB_HOST" -P"$NODE_BACKEND_DB_PORT" -u"$NODE_BACKEND_DB_USER" -p \
            "$NODE_BACKEND_DB_NAME" < "$backup_file"
        
        echo -e "${GREEN}✅ Backup restored successfully${NC}"
    else
        echo -e "${YELLOW}❌ Restore cancelled${NC}"
    fi
}

# Function to generate test data
generate_test_data() {
    echo -e "${BLUE}🧪 Generating test data...${NC}"
    
    # Create test data generation script
    cat > generate_test_data.sql << 'EOF'
-- Insert test admin user with known credentials
INSERT INTO users (
    id, 
    username, 
    email, 
    full_name, 
    role, 
    password_hash, 
    salt, 
    is_active, 
    workspace_id,
    created_at,
    created_by
) VALUES (
    'test-admin-id',
    'testadmin',
    'admin@test.com',
    'Test Administrator',
    'admin',
    '$2a$12$kA.Ni7IXlFsEpSO.udEsteNCknxHNOXX3fbldNC5uY79l2YUjJHeS', -- OpikAdmin2024! with salt
    'production-salt-change-immediately',
    1,
    'default',
    NOW(),
    'system'
) ON DUPLICATE KEY UPDATE
    username = VALUES(username);

-- Insert test regular user
INSERT INTO users (
    id,
    username,
    email,
    full_name,
    role,
    password_hash,
    salt,
    is_active,
    workspace_id,
    created_at,
    created_by
) VALUES (
    'test-user-id',
    'testuser',
    'user@test.com',
    'Test User',
    'user',
    '$2a$12$kA.Ni7IXlFsEpSO.udEsteNCknxHNOXX3fbldNC5uY79l2YUjJHeS', -- Same password for testing
    'production-salt-change-immediately',
    1,
    'default',
    NOW(),
    'system'
) ON DUPLICATE KEY UPDATE
    username = VALUES(username);

-- Insert test project
INSERT INTO projects (
    id,
    name,
    description,
    workspace_id,
    created_at,
    created_by
) VALUES (
    'test-project-id',
    'Test Project',
    'A test project for development and testing',
    'default',
    NOW(),
    'testadmin'
) ON DUPLICATE KEY UPDATE
    name = VALUES(name);
EOF

    mysql -h"$NODE_BACKEND_DB_HOST" -P"$NODE_BACKEND_DB_PORT" -u"$NODE_BACKEND_DB_USER" -p \
        "$NODE_BACKEND_DB_NAME" < generate_test_data.sql
    
    echo -e "${GREEN}✅ Test data generated${NC}"
    echo -e "${BLUE}Test credentials:${NC}"
    echo -e "  Admin: testadmin / OpikAdmin2024!"
    echo -e "  User:  testuser / OpikAdmin2024!"
    
    rm -f generate_test_data.sql
}

# Function to clean up migration files
cleanup() {
    echo -e "${BLUE}🧹 Cleaning up migration files...${NC}"
    
    rm -f users_export.tsv
    rm -f projects_export.tsv
    rm -f datasets_export.tsv
    rm -f import_users.sql
    rm -f verify_passwords.js
    rm -f generate_test_data.sql
    
    echo -e "${GREEN}✅ Cleanup completed${NC}"
}

# Function to show usage
show_usage() {
    echo -e "${BLUE}Usage: $0 [command]${NC}"
    echo ""
    echo "Available commands:"
    echo "  export_users              - Export users from OPIK Java backend"
    echo "  import_users              - Import users to SprintAgentLens backend"
    echo "  export_projects           - Export projects from OPIK Java backend"
    echo "  export_datasets           - Export datasets from OPIK Java backend"
    echo "  verify_password_compatibility - Test password hash compatibility"
    echo "  full_migration            - Run complete data migration"
    echo "  create_backup             - Create database backup"
    echo "  restore_backup <file>     - Restore from backup"
    echo "  generate_test_data        - Generate test data for development"
    echo "  cleanup                   - Clean up migration files"
    echo "  help                      - Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  JAVA_DB_HOST     - Java backend MySQL host (default: localhost)"
    echo "  JAVA_DB_PORT     - Java backend MySQL port (default: 3306)"
    echo "  JAVA_DB_NAME     - Java backend database name (default: opik)"
    echo "  JAVA_DB_USER     - Java backend MySQL user (default: root)"
    echo "  NODE_DB_HOST     - Node.js backend MySQL host (default: localhost)"
    echo "  NODE_DB_PORT     - Node.js backend MySQL port (default: 3306)"
    echo "  NODE_DB_NAME     - Node.js backend database name (default: sprintagentlens_dev)"
    echo "  NODE_DB_USER     - Node.js backend MySQL user (default: root)"
}

# Main command dispatcher
case "${1:-help}" in
    export_users)
        export_users
        ;;
    import_users)
        import_users
        ;;
    export_projects)
        export_projects
        ;;
    export_datasets)
        export_datasets
        ;;
    verify_password_compatibility)
        verify_password_compatibility
        ;;
    full_migration)
        full_migration
        ;;
    create_backup)
        create_backup
        ;;
    restore_backup)
        restore_backup "$2"
        ;;
    generate_test_data)
        generate_test_data
        ;;
    cleanup)
        cleanup
        ;;
    help)
        show_usage
        ;;
    *)
        echo -e "${RED}❌ Unknown command: $1${NC}"
        show_usage
        exit 1
        ;;
esac