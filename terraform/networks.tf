# ==============================================================================
# Terraform Networks — VPC-Equivalent Network Isolation
# ==============================================================================
#
# AWS COMPARISON:
#   docker_network (public_net)  ≈  aws_subnet (public)  + aws_internet_gateway
#   docker_network (private_net) ≈  aws_subnet (private) + aws_nat_gateway
#   docker_network (data_net)    ≈  aws_subnet (data/isolated) — no NAT
#
# HOW DOCKER NETWORK ISOLATION WORKS:
#   Docker creates a Linux bridge interface for each network.
#   Containers on different bridges cannot communicate unless explicitly
#   connected to both networks. This is enforced by Linux kernel netfilter
#   rules — not just Docker policy, actual kernel-level packet filtering.
#
#   Container A (public_net only) → Cannot reach Container B (data_net only)
#   Container C (public_net + private_net) → Can bridge, but deliberate
#
# WHY "internal: true" ON data_net?
#   internal = true adds an iptables rule that drops all packets from the
#   data_net bridge to any external network interface.
#   Even if the container tries to reach 8.8.8.8, the kernel drops the packet.
#   This is the equivalent of a VPC subnet with no internet gateway attached.
# ==============================================================================

resource "docker_network" "public_net" {
  name   = "public_net"
  driver = "bridge"

  ipam_config {
    subnet  = "172.20.0.0/24"
    gateway = "172.20.0.1"
  }

  options = {
    "com.docker.network.bridge.name"                 = "zt-public"
    "com.docker.network.bridge.enable_icc"           = "true"
    "com.docker.network.bridge.enable_ip_masquerade" = "true"
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


resource "docker_network" "private_net" {
  name   = "private_net"
  driver = "bridge"

  ipam_config {
    subnet  = "172.21.0.0/24"
    gateway = "172.21.0.1"
  }

  options = {
    "com.docker.network.bridge.name"                 = "zt-private"
    "com.docker.network.bridge.enable_icc"           = "true"
    "com.docker.network.bridge.enable_ip_masquerade" = "true"
  }

  labels {
    label = "project"
    value = "zero-trust"
  }

  labels {
    label = "tier"
    value = "private"
  }

}

resource "docker_network" "data_net" {
  name   = "zt_data_net"
  driver = "bridge"

  # ── CRITICAL SECURITY SETTING ──────────────────────────────────────────────
  # internal = true: no route to host network = no internet access
  # The PostgreSQL container physically cannot send packets to the internet.
  # If compromised, the attacker cannot exfiltrate data via the database tier.
  # This is the "VPC Endpoint" concept: services talk internally, never via internet.
  internal = true

  ipam_config {
    subnet = "172.22.0.0/24"
    # No gateway needed — internal networks have no external routing
  }

  options = {
    "com.docker.network.bridge.name"       = "zt-data"
    "com.docker.network.bridge.enable_icc" = "true"
    # enable_ip_masquerade irrelevant for internal networks
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