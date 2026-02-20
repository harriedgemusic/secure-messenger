#!/bin/bash

# Pre-Install Setup Script for Secure Messenger

echo "=========================================================="
echo "          Secure Messenger Configuration Setup"
echo "=========================================================="
echo "Press ENTER to accept the default values in brackets []."
echo ""

# Configuration Files
COMPOSE_FILE="docker-compose.yml"
CONFIG_FILE="config.yaml"

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "Error: $COMPOSE_FILE not found in the current directory!"
    exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: $CONFIG_FILE not found in the current directory!"
    exit 1
fi

# Detect OS for sed inline replacement
OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then
  SED_I="sed -i ''"
else
  SED_I="sed -i"
fi

# --- 1. Gather Variables ---

# Database Variables
read -p "Database Name [messenger_db]: " DB_NAME
DB_NAME=${DB_NAME:-messenger_db}

read -p "Database User [messenger]: " DB_USER
DB_USER=${DB_USER:-messenger}

read -p "Database Password [messenger_secret]: " DB_PASSWORD
DB_PASSWORD=${DB_PASSWORD:-messenger_secret}

read -p "Database Host (for config.yaml) [localhost]: " DB_HOST_CONFIG
DB_HOST_CONFIG=${DB_HOST_CONFIG:-localhost}

# JWT Secrets
read -p "JWT Access Token Secret [production-access-secret-change-me]: " JWT_ACCESS_SECRET
JWT_ACCESS_SECRET=${JWT_ACCESS_SECRET:-production-access-secret-change-me}

read -p "JWT Refresh Token Secret [production-refresh-secret-change-me]: " JWT_REFRESH_SECRET
JWT_REFRESH_SECRET=${JWT_REFRESH_SECRET:-production-refresh-secret-change-me}

# MinIO Variables
read -p "MinIO Admin User [minioadmin]: " MINIO_USER
MINIO_USER=${MINIO_USER:-minioadmin}

read -p "MinIO Admin Password [minioadmin]: " MINIO_PASSWORD
MINIO_PASSWORD=${MINIO_PASSWORD:-minioadmin}

echo ""
echo "=========================================================="
echo "Updating configuration files..."
echo "=========================================================="

# --- 2. Update docker-compose.yml ---

echo "Updating $COMPOSE_FILE..."

# Update DB_NAME
$SED_I -e "s/DB_NAME=.*/DB_NAME=$DB_NAME/g" "$COMPOSE_FILE"
$SED_I -e "s/POSTGRES_DB=.*/POSTGRES_DB=$DB_NAME/g" "$COMPOSE_FILE"
# Also update the healthcheck db name
$SED_I -e "s/-d messenger_db/-d $DB_NAME/g" "$COMPOSE_FILE"

# Update DB_USER
$SED_I -e "s/DB_USER=.*/DB_USER=$DB_USER/g" "$COMPOSE_FILE"
$SED_I -e "s/POSTGRES_USER=.*/POSTGRES_USER=$DB_USER/g" "$COMPOSE_FILE"
# Also update the healthcheck user
$SED_I -e "s/-U messenger /-U $DB_USER /g" "$COMPOSE_FILE"

# Update DB_PASSWORD
$SED_I -e "s/DB_PASSWORD=.*/DB_PASSWORD=$DB_PASSWORD/g" "$COMPOSE_FILE"
$SED_I -e "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$DB_PASSWORD/g" "$COMPOSE_FILE"

# Update JWT Secrets
$SED_I -e "s/JWT_ACCESS_SECRET=.*/JWT_ACCESS_SECRET=$JWT_ACCESS_SECRET/g" "$COMPOSE_FILE"
$SED_I -e "s/JWT_REFRESH_SECRET=.*/JWT_REFRESH_SECRET=$JWT_REFRESH_SECRET/g" "$COMPOSE_FILE"

# Update MinIO Credentials
$SED_I -e "s/MINIO_ACCESS_KEY=.*/MINIO_ACCESS_KEY=$MINIO_USER/g" "$COMPOSE_FILE"
$SED_I -e "s/MINIO_ROOT_USER=.*/MINIO_ROOT_USER=$MINIO_USER/g" "$COMPOSE_FILE"
$SED_I -e "s/MINIO_SECRET_KEY=.*/MINIO_SECRET_KEY=$MINIO_PASSWORD/g" "$COMPOSE_FILE"
$SED_I -e "s/MINIO_ROOT_PASSWORD=.*/MINIO_ROOT_PASSWORD=$MINIO_PASSWORD/g" "$COMPOSE_FILE"

# --- 3. Update config.yaml ---

echo "Updating $CONFIG_FILE..."

# Update DB configuration explicitly in the database section only
$SED_I -e "/^database:/,/^redis:/ s/database: \"[^\"]*\"/database: \"$DB_NAME\"/" "$CONFIG_FILE"
$SED_I -e "/^database:/,/^redis:/ s/user: \"[^\"]*\"/user: \"$DB_USER\"/" "$CONFIG_FILE"
$SED_I -e "/^database:/,/^redis:/ s/password: \"[^\"]*\"/password: \"$DB_PASSWORD\"/" "$CONFIG_FILE"
$SED_I -e "/^database:/,/^redis:/ s/host: \"[^\"]*\"/host: \"$DB_HOST_CONFIG\"/" "$CONFIG_FILE"

# Update JWT secrets
$SED_I -e "s/access_token_secret: \"[^\"]*\"/access_token_secret: \"$JWT_ACCESS_SECRET\"/g" "$CONFIG_FILE"
$SED_I -e "s/refresh_token_secret: \"[^\"]*\"/refresh_token_secret: \"$JWT_REFRESH_SECRET\"/g" "$CONFIG_FILE"

# Update MinIO Credentials
$SED_I -e "/^minio:/,/^jwt:/ s/access_key: \"[^\"]*\"/access_key: \"$MINIO_USER\"/" "$CONFIG_FILE"
$SED_I -e "/^minio:/,/^jwt:/ s/secret_key: \"[^\"]*\"/secret_key: \"$MINIO_PASSWORD\"/" "$CONFIG_FILE"

echo "Configuration completed successfully!"
echo "You can now run 'docker-compose up -d' to start the services."
