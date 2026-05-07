# ==============================================================================
# Terraform — Zero-Trust Infrastructure as Code (Docker Provider)
# ==============================================================================
#
# WHY TERRAFORM OVER DOCKER COMPOSE ALONE?
#   Docker Compose: Great for development, but state is implicit.
#     - "Is this the deployed version?" — you don't know without checking.
#     - Rolling back means manual file edits.
#     - No drift detection.
#
#   Terraform:
#     - State file tracks EXACT deployed configuration.
#     - `terraform plan` shows you exactly what will change before applying.
#     - `terraform apply` converges to the desired state (idempotent).
#     - Rollback = revert .tf file, apply again.
#     - Skill transfers directly to AWS/GCP/Azure — same HCL syntax.
#
# WHY DOCKER PROVIDER?
#   We use the Docker provider locally so you learn Terraform patterns
#   without an AWS bill. When you're ready for cloud:
#   - Replace `provider "docker"` with `provider "aws"`
#   - Replace `docker_network` with `aws_vpc`/`aws_subnet`
#   - Replace `docker_container` with `aws_instance`/`aws_ecs_task`
#   The concepts and state management are identical.
#
# ==============================================================================

terraform {
  required_version = ">= 1.6"
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }

  # WHY local backend for this project?
  # The default backend stores state in terraform.tfstate locally.
  # For a team, use remote state (S3 + DynamoDB for AWS, or Terraform Cloud).
  # Remote state prevents two people applying simultaneously (state locking).
  backend "local" {
    path = "terraform.tfstate"
  }
}

provider "docker" {
  # Connects to the local Docker daemon via Unix socket
  # In CI/CD: set DOCKER_HOST env var to connect to a remote Docker host
  host = "npipe:////./pipe/docker_engine"
}

# ==============================================================================
# DATA SOURCES — Reference existing resources without managing them
# ==============================================================================

# Pull the official images (Terraform tracks these, reports if they change)
data "docker_registry_image" "nginx" {
  name = "owasp/modsecurity-crs:nginx-alpine"
}

data "docker_registry_image" "postgres" {
  name = "postgres:16-alpine"
}

data "docker_registry_image" "redis" {
  name = "redis:7-alpine"
}

data "docker_registry_image" "vault" {
  name = "hashicorp/vault:1.15"
}

# ==============================================================================
# NETWORKS — VPC-equivalent isolation
# ==============================================================================
# See networks.tf for all network definitions

# ==============================================================================
# VOLUMES — Persistent storage
# ==============================================================================
resource "docker_volume" "postgres_data" {
  name = "zt_postgres_data"

  # WHY driver "local"?
  # Local volumes are stored on the Docker host's filesystem.
  # For production: use a networked volume driver (NFS, Ceph, or cloud block storage)
  # to survive host failures.
  driver = "local"

  labels {
    label = "project"
    value = "zero-trust"
  }
  labels {
    label = "tier"
    value = "data"
  }
}

resource "docker_volume" "vault_data" {
  name   = "zt_vault_data"
  driver = "local"
  labels {
    label = "project"
    value = "zero-trust"
  }
}

resource "docker_volume" "redis_data" {
  name   = "zt_redis_data"
  driver = "local"
  labels {
    label = "project"
    value = "zero-trust"
  }
}

# ==============================================================================
# NGINX — Public Tier Edge Proxy
# ==============================================================================
resource "docker_container" "nginx" {
  name  = "zt-nginx"
  image = data.docker_registry_image.nginx.name

  # Recreate if the image changes (picks up security patches)
  # WHY? If nginx releases a CVE fix, `terraform apply` automatically
  # recreates the container with the new image.
  must_run = true
  restart  = "unless-stopped"

  # Exposed ports (public tier only)
  ports {
    external = 8080
    internal = 80
    ip       = "0.0.0.0"
    protocol = "tcp"
  }

  ports {
    external = 8443
    internal = 443
    ip       = "0.0.0.0"
    protocol = "tcp"
  }


  # Attach to both public and private networks
  networks_advanced {
    name = docker_network.public_net.name
  }
  networks_advanced {
    name = docker_network.private_net.name
  }

  # Mount configuration files as read-only
  # WHY :ro? The container reads config but cannot modify it.
  # If Nginx is compromised, the attacker can't persist config changes.
  mounts {
    target    = "/etc/nginx/nginx.conf"
    source    = "C:/Users/Sylvia Zwane/zero-trust-architecture/nginx/nginx.conf"
    type      = "bind"
    read_only = true
  }
  mounts {
    target    = "/etc/nginx/conf.d/security-headers.conf"
    source    = "C:/Users/Sylvia Zwane/zero-trust-architecture/nginx/security-headers.conf"
    type      = "bind"
    read_only = true
  }

  env = [
    "PARANOIA=2",
    "ANOMALY_INBOUND=5",
    "ANOMALY_OUTBOUND=4",
  ]

  # Health check
  healthcheck {
    test         = ["CMD", "curl", "-f", "http://localhost/health"]
    interval     = "30s"
    timeout      = "10s"
    retries      = 3
    start_period = "15s"
  }

  labels {
    label = "project"
    value = "zero-trust"
  }
  labels {
    label = "tier"
    value = "public"
  }
}

# ==============================================================================
# APP SERVERS — Private Tier (AZ1 + AZ2)
# ==============================================================================

# Build the app image from local Dockerfile
locals {
  # WHY abspath() + fileset()?
  # 1. abspath() resolves the path relative to cwd at plan time — works on
  #    Windows (backslashes) and Linux/macOS (forward slashes) identically.
  # 2. fileset() scans the directory and returns all matching file paths.
  #    sha1(join(...)) produces a single hash that changes whenever ANY file
  #    in the app/ directory changes — Terraform then rebuilds the image.
  # 3. filemd5("../app/Dockerfile") fails on Windows because Terraform
  #    evaluates the path before Docker resolves it, and Windows path
  #    separators trip up the function. abspath() + fileset() avoids this.
  app_dir = abspath("${path.module}/../app")
  app_src_hash = sha1(join("", [
    for f in sort(fileset(local.app_dir, "**")) :
    filesha1("${local.app_dir}/${f}")
  ]))
}

resource "docker_image" "app" {
  name = "zt-app:latest"
  build {
    context    = local.app_dir
    dockerfile = "Dockerfile"
    build_args = {
      APP_ENV = "production"
    }
  }
  # Rebuild whenever any file in app/ changes (Dockerfile, *.py, requirements.txt)
  triggers = {
    src_hash = local.app_src_hash
  }
}

resource "docker_container" "app_az1" {
  name    = "zt-app-az1"
  image   = docker_image.app.image_id
  restart = "unless-stopped"

  networks_advanced {
    name = docker_network.private_net.name
  }
  networks_advanced {
    name = docker_network.data_net.name
  }

  env = [
    "APP_ENV=production",
    "VAULT_ADDR=http://vault:8200",
    "REDIS_HOST=redis",
    "POSTGRES_HOST=postgres_primary",
  ]

  # Read-only filesystem with tmpfs for /tmp
  # WHY? Attackers can't write malware to a read-only filesystem.
  read_only = true
  tmpfs = {
    "/tmp" = "size=100m,mode=1777"
  }

  healthcheck {
    test     = ["CMD", "curl", "-f", "http://localhost:5000/health"]
    interval = "30s"
    timeout  = "10s"
    retries  = 3
  }

  labels {
    label = "project"
    value = "zero-trust"
  }
  labels {
    label = "tier"
    value = "private"
  }
  labels {
    label = "az"
    value = "1"
  }
}

# AZ2 is identical to AZ1 — this is "high availability"
resource "docker_container" "app_az2" {
  name    = "zt-app-az2"
  image   = docker_image.app.image_id
  restart = "unless-stopped"

  networks_advanced { name = docker_network.private_net.name }
  networks_advanced { name = docker_network.data_net.name }

  env = [
    "APP_ENV=production",
    "VAULT_ADDR=http://vault:8200",
    "REDIS_HOST=redis",
    "POSTGRES_HOST=postgres_primary",
  ]

  read_only = true
  tmpfs     = { "/tmp" = "size=100m,mode=1777" }

  healthcheck {
    test     = ["CMD", "curl", "-f", "http://localhost:5000/health"]
    interval = "30s"
    timeout  = "10s"
    retries  = 3
  }

  labels {
    label = "project"
    value = "zero-trust"
  }

  labels {
    label = "tier"
    value = "private"
  }

  labels {
    label = "az"
    value = "2"
  }

}

# ==============================================================================
# POSTGRESQL — Data Tier
# ==============================================================================
resource "docker_container" "postgres" {
  name    = "zt-postgres-primary"
  image   = data.docker_registry_image.postgres.name
  restart = "unless-stopped"

  # Data tier ONLY — no connection to public or private networks directly
  networks_advanced {
    name = docker_network.data_net.name
  }

  volumes {
    volume_name    = docker_volume.postgres_data.name
    container_path = "/var/lib/postgresql/data"
  }

  env = [
    "POSTGRES_DB=appdb",
    "POSTGRES_USER=postgres",
    "POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password",
  ]

  command = [
    "postgres",
    "-c", "ssl=on",
    "-c", "log_connections=on",
    "-c", "log_statement=all",
    "-c", "max_connections=100",
  ]

  healthcheck {
    test     = ["CMD-SHELL", "pg_isready -U postgres -d appdb"]
    interval = "10s"
    timeout  = "5s"
    retries  = 5
  }

  labels {
    label = "project"
    value = "zero-trust"
  }

  labels {
    label = "tier"
    value = "data"
  }

}

# ==============================================================================
# VAULT — Secret Management
# ==============================================================================
resource "docker_container" "vault" {
  name    = "zt-vault"
  image   = data.docker_registry_image.vault.name
  user    = "root"
  restart = "unless-stopped"

  networks_advanced {
    name = docker_network.data_net.name
  }

  volumes {
    volume_name    = docker_volume.vault_data.name
    container_path = "/vault/data"
  }

  mounts {
    target    = "/vault/config/config.hcl"
    source    = "C:\\Users\\Sylvia Zwane\\zero-trust-architecture\\vault\\config.hcl"
    type      = "bind"
    read_only = true
  }

  mounts {
    target    = "/run/secrets/vault_token"
    source    = "C:\\Users\\Sylvia Zwane\\zero-trust-architecture\\secrets\\vault_token"
    type      = "bind"
    read_only = true
  }

  capabilities {
    add = ["IPC_LOCK"]
  }

  command = ["vault", "server", "-config=/vault/config/config.hcl"]

  env = [
    "VAULT_ADDR=http://0.0.0.0:8200",
    "VAULT_API_ADDR=http://vault:8200",
  ]

  labels {
    label = "project"
    value = "zero-trust"
  }

  labels {
    label = "tier"
    value = "data"
  }
}


