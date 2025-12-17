import React, { useMemo, useState } from "react";
import { motion } from "framer-motion";
import JSZip from "jszip";
import {
  Laptop,
  Boxes,
  Server,
  Database,
  HardDrive,
  Lock,
  ShieldCheck,
  Copy,
  Plus,
  Trash2,
  Settings2,
  Download,
  Globe,
  Network,
} from "lucide-react";

type Region =
  | "eastus"
  | "eastus2"
  | "westus"
  | "westeurope"
  | "northeurope"
  | "uksouth"
  | "ukwest"
  | "centralus";

type BaseNode = { id: string; name: string; location: Region };
type VMNode = BaseNode & {
  kind: "vm";
  os: "linux" | "windows";
  size: string;
  admin_username: string;
  ssh_public_key_var?: string;
  admin_password_var?: string;
  os_disk_gb: number;
  install_jenkins: boolean;
};
type VMSSNode = BaseNode & {
  kind: "vmss";
  size: string;
  instances: number;
  admin_username: string;
  ssh_public_key_var: string;
};
type AKSNode = BaseNode & {
  kind: "aks";
  kubernetes_version: string;
  node_count: number;
  node_vm_size: string;
};
type StorageNode = BaseNode & {
  kind: "storage";
  account_tier: "Standard" | "Premium";
  replication_type: "LRS" | "GRS" | "RAGRS" | "ZRS";
};
type KeyVaultNode = BaseNode & {
  kind: "keyvault";
  purge_protection: boolean;
  soft_delete_retention_days: number;
};
type NSGNode = BaseNode & {
  kind: "nsg";
  allow_ssh: boolean;
  allow_http: boolean;
  allow_https: boolean;
  allow_jenkins: boolean;
  extra_ports: string;
};
type LBNode = BaseNode & {
  kind: "lb";
  lb_type: "public" | "internal";
  fe_port: number;
  be_port: number;
};
type AppGWNode = BaseNode & {
  kind: "appgw";
  listener_port: number;
  backend_port: number;
};
type ResourceGroupNode = BaseNode & {
  kind: "rg";
};
type VNetNode = BaseNode & {
  kind: "vnet";
  address_space: string;
  subnet_prefix: string;
};
type SqlNode = BaseNode & {
  kind: "sql";
  server_name: string;
  database_name: string;
  administrator_login: string;
  administrator_password_var: string;
  sku_name: string;
  collation: string;
};
type CosmosNode = BaseNode & {
  kind: "cosmos";
  offer_type: "Standard";
  consistency: "Session" | "Strong" | "Eventual" | "BoundedStaleness";
};
type AppServiceNode = BaseNode & {
  kind: "appservice";
  plan_sku_tier: "Basic" | "Standard" | "PremiumV2";
  plan_sku_size: string;
  runtime_stack: string;
};
type FunctionAppNode = BaseNode & {
  kind: "functionapp";
  runtime_stack: string;
  storage_account_name: string;
  plan_sku_tier: "Dynamic" | "ElasticPremium";
  plan_sku_size: string;
};
type RedisNode = BaseNode & {
  kind: "redis";
  capacity: number;
  family: "C" | "P";
  sku_name: "Basic" | "Standard" | "Premium";
  enable_non_ssl_port: boolean;
};
type PrivateDnsNode = BaseNode & {
  kind: "privatedns";
  zone_name: string;
};
type LogAnalyticsNode = BaseNode & {
  kind: "loganalytics";
  retention_in_days: number;
  sku: "PerGB2018" | "Free" | "Standalone" | "CapacityReservation";
};

type Node =
  | VMNode
  | VMSSNode
  | AKSNode
  | StorageNode
  | KeyVaultNode
  | NSGNode
  | LBNode
  | AppGWNode
  | ResourceGroupNode
  | VNetNode
  | SqlNode
  | CosmosNode
  | AppServiceNode
  | FunctionAppNode
  | RedisNode
  | PrivateDnsNode
  | LogAnalyticsNode;

const newId = () => Math.random().toString(36).slice(2, 9);
const DEFAULT_REGION: Region = "uksouth";
const REGION_OPTIONS: Region[] = [
  "eastus",
  "eastus2",
  "westus",
  "westeurope",
  "northeurope",
  "uksouth",
  "ukwest",
  "centralus",
];

const DEFAULTS = {
  vmLinux: (): VMNode => ({
    id: newId(),
    kind: "vm",
    os: "linux",
    name: `vm-${newId().slice(0, 4)}`,
    location: DEFAULT_REGION,
    size: "Standard_B2s",
    admin_username: "azureuser",
    ssh_public_key_var: "var.ssh_public_key",
    os_disk_gb: 64,
    install_jenkins: false,
  }),
  vmWindows: (): VMNode => ({
    id: newId(),
    kind: "vm",
    os: "windows",
    name: `win-${newId().slice(0, 4)}`,
    location: DEFAULT_REGION,
    size: "Standard_B2ms",
    admin_username: "azureuser",
    admin_password_var: "var.windows_admin_password",
    os_disk_gb: 128,
    install_jenkins: false,
  }),
  vmss: (): VMSSNode => ({
    id: newId(),
    kind: "vmss",
    name: `vmss-${newId().slice(0, 4)}`,
    location: DEFAULT_REGION,
    size: "Standard_DS2_v2",
    instances: 2,
    admin_username: "azureuser",
    ssh_public_key_var: "var.ssh_public_key",
  }),
  aks: (): AKSNode => ({
    id: newId(),
    kind: "aks",
    name: `aks-${newId().slice(0, 4)}`,
    location: DEFAULT_REGION,
    kubernetes_version: "1.29.7",
    node_count: 3,
    node_vm_size: "Standard_DS2_v2",
  }),
  storage: (): StorageNode => ({
    id: newId(),
    kind: "storage",
    name: `st${newId().slice(0, 6)}`.replace(/[^a-z0-9]/g, ""),
    location: DEFAULT_REGION,
    account_tier: "Standard",
    replication_type: "LRS",
  }),
  keyvault: (): KeyVaultNode => ({
    id: newId(),
    kind: "keyvault",
    name: `kv-${newId().slice(0, 4)}`,
    location: DEFAULT_REGION,
    purge_protection: false,
    soft_delete_retention_days: 7,
  }),
  nsg: (): NSGNode => ({
    id: newId(),
    kind: "nsg",
    name: `nsg-${newId().slice(0, 4)}`,
    location: DEFAULT_REGION,
    allow_ssh: true,
    allow_http: false,
    allow_https: true,
    allow_jenkins: false,
    extra_ports: "",
  }),
  lb: (): LBNode => ({
    id: newId(),
    kind: "lb",
    name: `lb-${newId().slice(0, 4)}`,
    location: DEFAULT_REGION,
    lb_type: "public",
    fe_port: 80,
    be_port: 80,
  }),
  appgw: (): AppGWNode => ({
    id: newId(),
    kind: "appgw",
    name: `agw-${newId().slice(0, 4)}`,
    location: DEFAULT_REGION,
    listener_port: 80,
    backend_port: 80,
  }),
  resourceGroup: (): ResourceGroupNode => ({
    id: newId(),
    kind: "rg",
    name: `rg-${newId().slice(0, 4)}`,
    location: DEFAULT_REGION,
  }),
  vnet: (): VNetNode => ({
    id: newId(),
    kind: "vnet",
    name: `vnet-${newId().slice(0, 4)}`,
    location: DEFAULT_REGION,
    address_space: "10.0.0.0/16",
    subnet_prefix: "10.0.1.0/24",
  }),
  sql: (): SqlNode => ({
    id: newId(),
    kind: "sql",
    name: `sql-${newId().slice(0, 4)}`,
    location: DEFAULT_REGION,
    server_name: `sqlsrv${newId().slice(0, 6)}`.toLowerCase(),
    database_name: "appdb",
    administrator_login: "sqladminuser",
    administrator_password_var: "var.sql_admin_password",
    sku_name: "GP_S_Gen5_2",
    collation: "SQL_Latin1_General_CP1_CI_AS",
  }),
  cosmos: (): CosmosNode => ({
    id: newId(),
    kind: "cosmos",
    name: `cosmos-${newId().slice(0, 4)}`,
    location: DEFAULT_REGION,
    offer_type: "Standard",
    consistency: "Session",
  }),
  appservice: (): AppServiceNode => ({
    id: newId(),
    kind: "appservice",
    name: `web-${newId().slice(0, 4)}`,
    location: DEFAULT_REGION,
    plan_sku_tier: "Standard",
    plan_sku_size: "S1",
    runtime_stack: "NODE|18-lts",
  }),
  functionapp: (): FunctionAppNode => ({
    id: newId(),
    kind: "functionapp",
    name: `func-${newId().slice(0, 4)}`,
    location: DEFAULT_REGION,
    runtime_stack: "node",
    storage_account_name: `funcsa${newId().slice(0, 6)}`.toLowerCase(),
    plan_sku_tier: "ElasticPremium",
    plan_sku_size: "EP1",
  }),
  redis: (): RedisNode => ({
    id: newId(),
    kind: "redis",
    name: `redis-${newId().slice(0, 4)}`,
    location: DEFAULT_REGION,
    capacity: 1,
    family: "C",
    sku_name: "Standard",
    enable_non_ssl_port: false,
  }),
  privatedns: (): PrivateDnsNode => ({
    id: newId(),
    kind: "privatedns",
    name: `pdns-${newId().slice(0, 4)}`,
    location: DEFAULT_REGION,
    zone_name: "privatelink.blob.core.windows.net",
  }),
  loganalytics: (): LogAnalyticsNode => ({
    id: newId(),
    kind: "loganalytics",
    name: `law-${newId().slice(0, 4)}`,
    location: DEFAULT_REGION,
    retention_in_days: 30,
    sku: "PerGB2018",
  }),
};

const palette = [
  { type: "resource-group" as const, label: "Resource Group", icon: Database },
  { type: "vnet" as const, label: "Virtual Network", icon: Network },
  { type: "vm-linux" as const, label: "Linux VM", icon: Laptop },
  { type: "vm-windows" as const, label: "Windows VM", icon: Laptop },
  { type: "vmss" as const, label: "VM Scale Set", icon: Server },
  { type: "aks" as const, label: "AKS Cluster", icon: Boxes },
  { type: "storage" as const, label: "Storage Account", icon: HardDrive },
  { type: "keyvault" as const, label: "Key Vault", icon: Lock },
  { type: "nsg" as const, label: "Network Security Group", icon: ShieldCheck },
  { type: "lb" as const, label: "Load Balancer", icon: Network },
  { type: "appgw" as const, label: "App Gateway", icon: Globe },
  { type: "sql" as const, label: "Azure SQL", icon: Database },
  { type: "cosmos" as const, label: "Cosmos DB", icon: Database },
  { type: "appservice" as const, label: "App Service", icon: Laptop },
  { type: "functionapp" as const, label: "Function App", icon: Laptop },
  { type: "redis" as const, label: "Redis Cache", icon: Server },
  { type: "privatedns" as const, label: "Private DNS Zone", icon: Globe },
  { type: "loganalytics" as const, label: "Log Analytics", icon: Boxes },
];
type PaletteType = typeof palette[number]["type"];

const tfEscape = (s: string) => s.replace(/[^a-zA-Z0-9-_]/g, "-");

type TerraformArtifacts = {
  main: string;
  state: string;
  variables: string;
  tfvars: string;
};

function linuxCustomData(install: boolean, admin: string) {
  if (!install) return undefined;
  const script = `#cloud-config
runcmd:
  - apt-get update
  - apt-get install -y curl gnupg openjdk-17-jre ca-certificates
  - install -m 0755 -d /etc/apt/keyrings
  - curl -fsSL https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key | tee /etc/apt/keyrings/jenkins-keyring.asc > /dev/null
  - echo deb [signed-by=/etc/apt/keyrings/jenkins-keyring.asc] https://pkg.jenkins.io/debian-stable binary/ | tee /etc/apt/sources.list.d/jenkins.list > /dev/null
  - apt-get update
  - apt-get install -y jenkins
  - systemctl enable --now jenkins
  - usermod -aG sudo ${admin}
`;
  return btoa(unescape(encodeURIComponent(script)));
}

function generateTerraformArtifacts(
  nodes: Node[],
  projectName: string
): TerraformArtifacts {
  const stateBlock = `terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.12.0"
    }
  }
}

provider "azurerm" {
  features {}
}

data "azurerm_client_config" "current" {}
`;

  const variablesBlock = `variable "project_name" {
  type        = string
  description = "Name prefix for all resources"
}

variable "location" {
  type        = string
  description = "Azure region for the deployment"
}

variable "ssh_public_key" {
  type        = string
  description = "SSH public key for Linux VMs and scale sets"
}

variable "windows_admin_password" {
  type        = string
  description = "Admin password for Windows VMs"
}

variable "sql_admin_password" {
  type        = string
  description = "Admin password for Azure SQL server"
}

variable "subnet_id" {
  type        = string
  description = "Existing subnet ID for internal load balancers"
  default     = ""
}

variable "appgw_subnet_id" {
  type        = string
  description = "Subnet ID for Application Gateway"
  default     = ""
}

variable "virtual_network_id" {
  type        = string
  description = "Virtual network ID for Private DNS links"
  default     = ""
}`;

  const resourceGroupNode = nodes.find(
    (n) => n.kind === "rg"
  ) as ResourceGroupNode | undefined;
  const parts: string[] = [];

  if (!resourceGroupNode) {
    return {
      main: `# Add a Resource Group from the palette to start generating Terraform output.`,
      state: stateBlock,
      variables: variablesBlock,
      tfvars: `project_name = "${projectName}"\nlocation = "${DEFAULT_REGION}"`,
    };
  }

  const rgName = resourceGroupNode.name;
  const rgLocation = resourceGroupNode.location;

  const rg = `resource "azurerm_resource_group" "rg" {
  name     = "${rgName}"
  location = "${rgLocation}"
}`;

  const vms = nodes.filter((n) => n.kind === "vm") as VMNode[];
  const vmssNodes = nodes.filter((n) => n.kind === "vmss") as VMSSNode[];
  const aksClusters = nodes.filter((n) => n.kind === "aks") as AKSNode[];
  const storageAccounts = nodes.filter(
    (n) => n.kind === "storage"
  ) as StorageNode[];
  const keyVaults = nodes.filter(
    (n) => n.kind === "keyvault"
  ) as KeyVaultNode[];
  const nsgs = nodes.filter((n) => n.kind === "nsg") as NSGNode[];
  const loadBalancers = nodes.filter((n) => n.kind === "lb") as LBNode[];
  const gateways = nodes.filter((n) => n.kind === "appgw") as AppGWNode[];
  const virtualNetworks = nodes.filter(
    (n) => n.kind === "vnet"
  ) as VNetNode[];
  const sqlServers = nodes.filter((n) => n.kind === "sql") as SqlNode[];
  const cosmosAccounts = nodes.filter(
    (n) => n.kind === "cosmos"
  ) as CosmosNode[];
  const appServices = nodes.filter(
    (n) => n.kind === "appservice"
  ) as AppServiceNode[];
  const functionApps = nodes.filter(
    (n) => n.kind === "functionapp"
  ) as FunctionAppNode[];
  const redisCaches = nodes.filter((n) => n.kind === "redis") as RedisNode[];
  const privateDnsZones = nodes.filter(
    (n) => n.kind === "privatedns"
  ) as PrivateDnsNode[];
  const logAnalytics = nodes.filter(
    (n) => n.kind === "loganalytics"
  ) as LogAnalyticsNode[];

  parts.push(rg);

  // Generate VNets
  for (const vnet of virtualNetworks) {
    const rn = tfEscape(vnet.name);
    parts.push(`# Virtual Network: ${vnet.name}
resource "azurerm_virtual_network" "${rn}" {
  name                = "${vnet.name}"
  location            = "${rgLocation}"
  resource_group_name = azurerm_resource_group.rg.name
  address_space       = ["${vnet.address_space}"]
}

resource "azurerm_subnet" "${rn}_subnet" {
  name                 = "${vnet.name}-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.${rn}.name
  address_prefixes     = ["${vnet.subnet_prefix}"]
}`);
  }

  // Generate SQL Servers/Databases
  for (const sql of sqlServers) {
    const rn = tfEscape(sql.name);
    parts.push(`# Azure SQL: ${sql.database_name}
resource "azurerm_mssql_server" "${rn}" {
  name                         = "${sql.server_name}"
  resource_group_name          = azurerm_resource_group.rg.name
  location                     = "${rgLocation}"
  version                      = "12.0"
  administrator_login          = "${sql.administrator_login}"
  administrator_login_password = ${sql.administrator_password_var}
}

resource "azurerm_mssql_database" "${rn}_db" {
  name           = "${sql.database_name}"
  server_id      = azurerm_mssql_server.${rn}.id
  sku_name       = "${sql.sku_name}"
  collation      = "${sql.collation}"
  zone_redundant = false
}`);
  }

  // Generate Cosmos DB Accounts
  for (const cosmos of cosmosAccounts) {
    const rn = tfEscape(cosmos.name);
    parts.push(`# Cosmos DB: ${cosmos.name}
resource "azurerm_cosmosdb_account" "${rn}" {
  name                = "${cosmos.name}"
  location            = "${rgLocation}"
  resource_group_name = azurerm_resource_group.rg.name
  offer_type          = "${cosmos.offer_type}"
  kind                = "GlobalDocumentDB"

  consistency_policy {
    consistency_level       = "${cosmos.consistency}"
    max_staleness_interval  = 300
    max_interval_in_seconds = 300
  }

  geo_location {
    location          = "${rgLocation}"
    failover_priority = 0
  }
}`);
  }

  // Generate App Services
  for (const app of appServices) {
    const rn = tfEscape(app.name);
    parts.push(`# App Service: ${app.name}
resource "azurerm_service_plan" "${rn}_plan" {
  name                = "${app.name}-plan"
  resource_group_name = azurerm_resource_group.rg.name
  location            = "${rgLocation}"
  os_type             = "Linux"
  sku_name            = "${app.plan_sku_size}"
}

resource "azurerm_linux_web_app" "${rn}" {
  name                = "${app.name}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = "${rgLocation}"
  service_plan_id     = azurerm_service_plan.${rn}_plan.id

  site_config {
    application_stack {
      node_version = "${app.runtime_stack}"
    }
  }
}`);
  }

  // Generate Function Apps
  for (const func of functionApps) {
    const rn = tfEscape(func.name);
    parts.push(`# Function App: ${func.name}
resource "azurerm_storage_account" "${rn}_sa" {
  name                     = "${func.storage_account_name}"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = "${rgLocation}"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_service_plan" "${rn}_plan" {
  name                = "${func.name}-plan"
  resource_group_name = azurerm_resource_group.rg.name
  location            = "${rgLocation}"
  os_type             = "Linux"
  sku_name            = "${func.plan_sku_size}"
}

resource "azurerm_linux_function_app" "${rn}" {
  name                       = "${func.name}"
  resource_group_name        = azurerm_resource_group.rg.name
  location                   = "${rgLocation}"
  service_plan_id            = azurerm_service_plan.${rn}_plan.id
  storage_account_name       = azurerm_storage_account.${rn}_sa.name
  storage_account_access_key = azurerm_storage_account.${rn}_sa.primary_access_key

  site_config {
    application_stack {
      node_version = "${func.runtime_stack}"
    }
  }
}`);
  }

  // Generate Redis caches
  for (const redis of redisCaches) {
    const rn = tfEscape(redis.name);
    parts.push(`# Redis Cache: ${redis.name}
resource "azurerm_redis_cache" "${rn}" {
  name                = "${redis.name}"
  location            = "${rgLocation}"
  resource_group_name = azurerm_resource_group.rg.name
  capacity            = ${redis.capacity}
  family              = "${redis.family}"
  sku_name            = "${redis.sku_name}"
  enable_non_ssl_port = ${redis.enable_non_ssl_port}
}`);
  }

  // Generate Private DNS Zones
  for (const dns of privateDnsZones) {
    const rn = tfEscape(dns.name);
    parts.push(`# Private DNS Zone: ${dns.zone_name}
resource "azurerm_private_dns_zone" "${rn}" {
  name                = "${dns.zone_name}"
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_private_dns_zone_virtual_network_link" "${rn}_link" {
  name                  = "${dns.zone_name}-link"
  resource_group_name   = azurerm_resource_group.rg.name
  private_dns_zone_name = azurerm_private_dns_zone.${rn}.name
  virtual_network_id    = var.virtual_network_id
  registration_enabled  = false
}`);
  }

  // Generate Log Analytics
  for (const law of logAnalytics) {
    const rn = tfEscape(law.name);
    parts.push(`# Log Analytics: ${law.name}
resource "azurerm_log_analytics_workspace" "${rn}" {
  name                = "${law.name}"
  location            = "${rgLocation}"
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "${law.sku}"
  retention_in_days   = ${law.retention_in_days}
}`);
  }

  // Generate NSGs
  for (const sg of nsgs) {
    const rn = tfEscape(sg.name);
    const rules = [];
    if (sg.allow_ssh)
      rules.push(`security_rule { name="SSH" priority=1001 direction="Inbound" access="Allow" protocol="Tcp" destination_port_range="22" }`);
    if (sg.allow_http)
      rules.push(`security_rule { name="HTTP" priority=1002 direction="Inbound" access="Allow" protocol="Tcp" destination_port_range="80" }`);
    if (sg.allow_https)
      rules.push(`security_rule { name="HTTPS" priority=1003 direction="Inbound" access="Allow" protocol="Tcp" destination_port_range="443" }`);
    if (sg.allow_jenkins)
      rules.push(`security_rule { name="Jenkins" priority=1004 direction="Inbound" access="Allow" protocol="Tcp" destination_port_range="8080" }`);
    const customPorts = sg.extra_ports
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);
    customPorts.forEach((port, index) => {
      const priority = 2000 + index;
      rules.push(
        `security_rule { name="Custom-${port}" priority=${priority} direction="Inbound" access="Allow" protocol="Tcp" destination_port_range="${port}" }`
      );
    });

    parts.push(`# Network Security Group
resource "azurerm_network_security_group" "${rn}" {
  name     = "${sg.name}"
  location = "${rgLocation}"
  ${rules.join("\n  ")}
}`);
  }

  // Generate VM Scale Sets
  for (const vmss of vmssNodes) {
    const rn = tfEscape(vmss.name);
    parts.push(`# VM Scale Set: ${vmss.name}
resource "azurerm_linux_virtual_machine_scale_set" "${rn}" {
  name                = "${vmss.name}"
  location            = "${rgLocation}"
  resource_group_name = azurerm_resource_group.rg.name

  sku       = "${vmss.size}"
  instances = ${vmss.instances}

  admin_username = "${vmss.admin_username}"
  admin_ssh_key {
    username   = "${vmss.admin_username}"
    public_key = ${vmss.ssh_public_key_var || "var.ssh_public_key"}
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }

  os_disk {
    storage_account_type = "Standard_LRS"
    caching              = "ReadWrite"
  }

  # TODO: add network_interface and subnet configuration
}`);
  }

  // Generate Storage Accounts
  for (const sa of storageAccounts) {
    const rn = tfEscape(sa.name);
    parts.push(`# Storage Account: ${sa.name}
resource "azurerm_storage_account" "${rn}" {
  name                     = "${sa.name}"
  location                 = "${rgLocation}"
  resource_group_name      = azurerm_resource_group.rg.name
  account_tier             = "${sa.account_tier}"
  account_replication_type = "${sa.replication_type}"
  allow_nested_items_to_be_public = false
}`);
  }

  // Generate Key Vaults
  for (const kv of keyVaults) {
    const rn = tfEscape(kv.name);
    parts.push(`# Key Vault: ${kv.name}
resource "azurerm_key_vault" "${rn}" {
  name                        = "${kv.name}"
  location                    = "${rgLocation}"
  resource_group_name         = azurerm_resource_group.rg.name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "standard"
  purge_protection_enabled    = ${kv.purge_protection}
  soft_delete_retention_days  = ${kv.soft_delete_retention_days}

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = ["Get", "List", "Set"]
  }
}`);
  }

  // Generate Load Balancers
  for (const lb of loadBalancers) {
    const rn = tfEscape(lb.name);
    const frontendName =
      lb.lb_type === "public" ? "PublicFrontEnd" : "InternalFrontEnd";
    const sku = lb.lb_type === "public" ? "Standard" : "Basic";
    const publicIp =
      lb.lb_type === "public"
        ? `resource "azurerm_public_ip" "${rn}_pip" {
  name                = "${lb.name}-pip"
  location            = "${rgLocation}"
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "${sku}"
}

`
        : "";
    const frontendConfig =
      lb.lb_type === "public"
        ? `frontend_ip_configuration {
    name                 = "${frontendName}"
    public_ip_address_id = azurerm_public_ip.${rn}_pip.id
  }`
        : `frontend_ip_configuration {
    name      = "${frontendName}"
    subnet_id = var.subnet_id
  }`;
    parts.push(`${publicIp}# Load Balancer: ${lb.name}
resource "azurerm_lb" "${rn}" {
  name                = "${lb.name}"
  location            = "${rgLocation}"
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "${sku}"

  ${frontendConfig}
}

resource "azurerm_lb_backend_address_pool" "${rn}_pool" {
  loadbalancer_id = azurerm_lb.${rn}.id
  name            = "${lb.name}-be"
}

resource "azurerm_lb_probe" "${rn}_probe" {
  resource_group_name = azurerm_resource_group.rg.name
  loadbalancer_id     = azurerm_lb.${rn}.id
  name                = "${lb.name}-probe"
  protocol            = "Tcp"
  port                = ${lb.be_port}
}

resource "azurerm_lb_rule" "${rn}_rule" {
  resource_group_name            = azurerm_resource_group.rg.name
  loadbalancer_id                = azurerm_lb.${rn}.id
  name                           = "${lb.name}-rule"
  protocol                       = "Tcp"
  frontend_port                  = ${lb.fe_port}
  backend_port                   = ${lb.be_port}
  frontend_ip_configuration_name = "${frontendName}"
  backend_address_pool_id        = azurerm_lb_backend_address_pool.${rn}_pool.id
  probe_id                       = azurerm_lb_probe.${rn}_probe.id
}`);
  }

  // Generate Application Gateways
  for (const gw of gateways) {
    const rn = tfEscape(gw.name);
    parts.push(`# Application Gateway: ${gw.name}
resource "azurerm_public_ip" "${rn}_pip" {
  name                = "${gw.name}-pip"
  location            = "${rgLocation}"
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_application_gateway" "${rn}" {
  name                = "${gw.name}"
  location            = "${rgLocation}"
  resource_group_name = azurerm_resource_group.rg.name

  sku {
    name = "WAF_v2"
    tier = "WAF_v2"
  }

  gateway_ip_configuration {
    name      = "gw-ipcfg"
    subnet_id = var.appgw_subnet_id
  }

  frontend_port {
    name = "frontend"
    port = ${gw.listener_port}
  }

  frontend_ip_configuration {
    name                 = "public"
    public_ip_address_id = azurerm_public_ip.${rn}_pip.id
  }

  backend_address_pool {
    name = "defaultpool"
  }

  backend_http_settings {
    name                  = "defaultsetting"
    cookie_based_affinity = "Disabled"
    port                  = ${gw.backend_port}
    protocol              = "Http"
    request_timeout       = 60
  }

  http_listener {
    name                           = "listener"
    frontend_ip_configuration_name = "public"
    frontend_port_name             = "frontend"
    protocol                       = "Http"
  }

  request_routing_rule {
    name                       = "rule1"
    rule_type                  = "Basic"
    http_listener_name         = "listener"
    backend_address_pool_name  = "defaultpool"
    backend_http_settings_name = "defaultsetting"
  }
}`);
  }

  // Generate VMs
  for (const vm of vms) {
    const rn = tfEscape(vm.name);
    const cd = linuxCustomData(vm.install_jenkins, vm.admin_username);
    parts.push(`# ${vm.os === "linux" ? "Linux" : "Windows"} VM: ${vm.name}
resource "azurerm_${vm.os}_virtual_machine" "${rn}" {
  name                = "${vm.name}"
  location            = "${rgLocation}"
  resource_group_name = azurerm_resource_group.rg.name
  size                = "${vm.size}"
  admin_username      = "${vm.admin_username}"
  ${vm.os === "windows" ? `admin_password = ${vm.admin_password_var || "var.windows_admin_password"}` : ""}
  ${vm.os === "linux" ? `disable_password_authentication = true` : ""}
  ${vm.os === "linux" ? `admin_ssh_key { username = "${vm.admin_username}" public_key = ${vm.ssh_public_key_var || "var.ssh_public_key"} }` : ""}
  ${cd ? `custom_data = "${cd}"` : ""}
  tags = { role = "${vm.install_jenkins ? "jenkins" : "general"}" }
}`);
  }

  // Generate AKS clusters
  for (const aks of aksClusters) {
    const rn = tfEscape(aks.name);
    const dns = `${tfEscape(aks.name)}-dns`.toLowerCase();
    parts.push(`# AKS cluster: ${aks.name}
resource "azurerm_kubernetes_cluster" "${rn}" {
  name                = "${aks.name}"
  location            = "${rgLocation}"
  resource_group_name = azurerm_resource_group.rg.name
  dns_prefix          = "${dns}"
  kubernetes_version  = "${aks.kubernetes_version}"

  default_node_pool {
    name       = "system"
    node_count = ${aks.node_count}
    vm_size    = "${aks.node_vm_size}"
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin    = "azure"
    load_balancer_sku = "standard"
  }
}`);
  }

  const tips = `
# Save as main.tf then:
# terraform init
# terraform apply`;

  return {
    main: parts.concat([tips]).join("\n\n"),
    state: stateBlock,
    variables: variablesBlock,
    tfvars: `project_name = "${projectName}"\nlocation = "${rgLocation}"`,
  };
}

export default function AzureTerraformBuilder() {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [projectName, setProjectName] = useState("tfapp");

  const hasResourceGroup = nodes.some((n) => n.kind === "rg");
  const selected = nodes.find((n) => n.id === selectedId) || null;
  const artifacts = useMemo(
    () => generateTerraformArtifacts(nodes, projectName),
    [nodes, projectName]
  );
  const terraformText = `${artifacts.state}\n\n${artifacts.main}`.trim();

  function addNode(type: PaletteType) {
    if (!hasResourceGroup && type !== "resource-group") {
      alert("Add a Resource Group first before other components.");
      return;
    }
    if (type === "resource-group") {
      const existing = nodes.find((n) => n.kind === "rg");
      if (existing) {
        setSelectedId(existing.id);
        return;
      }
    }
    let n: Node;
    switch (type) {
      case "resource-group":
        n = DEFAULTS.resourceGroup();
        break;
      case "vm-linux":
        n = DEFAULTS.vmLinux();
        break;
      case "vm-windows":
        n = DEFAULTS.vmWindows();
        break;
      case "vmss":
        n = DEFAULTS.vmss();
        break;
      case "aks":
        n = DEFAULTS.aks();
        break;
      case "storage":
        n = DEFAULTS.storage();
        break;
      case "keyvault":
        n = DEFAULTS.keyvault();
        break;
      case "nsg":
        n = DEFAULTS.nsg();
        break;
      case "lb":
        n = DEFAULTS.lb();
        break;
      case "appgw":
        n = DEFAULTS.appgw();
        break;
      case "vnet":
        n = DEFAULTS.vnet();
        break;
      case "sql":
        n = DEFAULTS.sql();
        break;
      case "cosmos":
        n = DEFAULTS.cosmos();
        break;
      case "appservice":
        n = DEFAULTS.appservice();
        break;
      case "functionapp":
        n = DEFAULTS.functionapp();
        break;
      case "redis":
        n = DEFAULTS.redis();
        break;
      case "privatedns":
        n = DEFAULTS.privatedns();
        break;
      case "loganalytics":
        n = DEFAULTS.loganalytics();
        break;
      default:
        n = DEFAULTS.vmLinux();
    }
    setNodes((p) => [...p, n]);
    setSelectedId(n.id);
  }

  function updateNode(u: Node) {
    setNodes((p) => p.map((n) => (n.id === u.id ? u : n)));
  }

  function removeSelected() {
    if (!selected) return;
    setNodes((p) => p.filter((n) => n.id !== selected.id));
    setSelectedId(null);
  }

  async function copyTF() {
    await navigator.clipboard.writeText(terraformText);
  }

  function exportMainTf() {
    if (!hasResourceGroup) {
      alert("Add a Resource Group first before exporting.");
      return;
    }
    const blob = new Blob([artifacts.main], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "main.tf";
    a.click();
    URL.revokeObjectURL(a.href);
  }

  async function exportZip() {
    if (!hasResourceGroup) {
      alert("Add a Resource Group first before exporting.");
      return;
    }
    const zip = new JSZip();
    zip.file("state.tf", artifacts.state);
    zip.file("main.tf", artifacts.main);
    zip.file("variables.tf", artifacts.variables);
    zip.file("terraform.tfvars", artifacts.tfvars);
    const content = await zip.generateAsync({ type: "blob" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(content);
    a.download = "terraform-bundle.zip";
    a.click();
    URL.revokeObjectURL(a.href);
  }

  return (
    <div className="space-y-4">
      <div className="card p-4 flex items-center gap-3">
        <span className="label">Project</span>
        <input
          className="input w-40"
          value={projectName}
          onChange={(e) => setProjectName(e.target.value)}
        />
        <div className="ml-auto flex items-center gap-2">
          <button className="btn" onClick={exportMainTf}>
            <Download className="h-4 w-4" /> Export main.tf
          </button>
          <button className="btn" onClick={exportZip}>
            <Download className="h-4 w-4" /> Export ZIP
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="card p-4 space-y-3">
          <h2 className="font-semibold">Palette</h2>
          {!hasResourceGroup && (
            <p className="text-xs text-slate-500">
              Add a Resource Group first to unlock other components.
            </p>
          )}
          {palette.map((p) => {
            const Icon = p.icon;
            const locked = !hasResourceGroup && p.type !== "resource-group";
            return (
              <motion.button
                key={p.type}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => addNode(p.type)}
                className={`w-full btn ${
                  locked ? "opacity-60 cursor-not-allowed" : ""
                }`}
                aria-disabled={locked}
                title={
                  locked ? "Add a Resource Group first" : undefined
                }
              >
                <Icon className="h-4 w-4" />
                <span>{p.label}</span>
                <Plus className="h-4 w-4 ml-auto" />
              </motion.button>
            );
          })}
        </div>

        <div className="card p-4 space-y-3 lg:col-span-2">
          <h2 className="font-semibold">Canvas</h2>
          {nodes.length === 0 ? (
            <div className="border border-dashed rounded-2xl p-8 text-center text-sm text-slate-500">
              Add components from the palette.
            </div>
          ) : (
            <div className="flex flex-wrap gap-2">
              {nodes.map((n) => {
                const Icon =
                  n.kind === "vm"
                    ? Laptop
                    : n.kind === "vmss"
                    ? Server
                    : n.kind === "aks"
                    ? Boxes
                    : n.kind === "storage"
                    ? HardDrive
                    : n.kind === "keyvault"
                    ? Lock
                    : n.kind === "nsg"
                    ? ShieldCheck
                    : n.kind === "lb"
                    ? Network
                    : n.kind === "appgw"
                    ? Globe
                    : n.kind === "vnet"
                    ? Network
                    : n.kind === "sql"
                    ? Database
                    : n.kind === "cosmos"
                    ? Database
                    : n.kind === "appservice"
                    ? Laptop
                    : n.kind === "functionapp"
                    ? Laptop
                    : n.kind === "redis"
                    ? Server
                    : n.kind === "privatedns"
                    ? Globe
                    : n.kind === "loganalytics"
                    ? Boxes
                    : Database;
                return (
                  <button
                    key={n.id}
                    className={
                      "btn " + (selectedId === n.id ? "ring-2" : "")
                    }
                    onClick={() => setSelectedId(n.id)}
                  >
                    <Icon className="h-4 w-4" />
                    <span className="mono text-xs">{n.name}</span>
                  </button>
                );
              })}
            </div>
          )}
          <div className="mt-2">
            {selected ? (
              <Properties
                node={selected}
                onChange={updateNode}
                onRemove={removeSelected}
              />
            ) : (
              <div className="text-sm text-slate-500">
                Select an item to edit.
              </div>
            )}
          </div>
        </div>

        <div className="card p-4 space-y-3">
          <div className="flex items-center gap-2">
            <h2 className="font-semibold">Terraform</h2>
            <button className="btn-ghost btn" onClick={copyTF} title="Copy">
              <Copy className="h-4 w-4" />
            </button>
          </div>
          <textarea
            className="w-full h-[520px] mono text-xs rounded-xl border p-3 bg-white dark:bg-slate-900"
            readOnly
            value={terraformText}
          ></textarea>
        </div>
      </div>
    </div>
  );
}

function Properties({
  node,
  onChange,
  onRemove,
}: {
  node: Node;
  onChange: (n: Node) => void;
  onRemove: () => void;
}) {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Settings2 className="h-4 w-4" />
        <h3 className="font-semibold">Properties</h3>
        <div className="ml-auto" />
        <button
          className="btn border-red-600 text-red-700"
          onClick={onRemove}
        >
          <Trash2 className="h-4 w-4" /> Remove
        </button>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2">
          <label className="label">Name</label>
          <input
            className="input"
            value={(node as any).name}
            onChange={(e) =>
              onChange({ ...node, name: e.target.value } as Node)
            }
          />
        </div>

        {node.kind === "rg" && (
          <div className="col-span-2">
            <label className="label">Location</label>
            <select
              className="input"
              value={(node as ResourceGroupNode).location}
              onChange={(e) =>
                onChange({
                  ...node,
                  location: e.target.value as Region,
                } as Node)
              }
            >
              {REGION_OPTIONS.map((region) => (
                <option key={region} value={region}>
                  {region}
                </option>
              ))}
            </select>
          </div>
        )}

        {node.kind === "vnet" && (
          <>
            <div>
              <label className="label">Address Space</label>
              <input
                className="input"
                value={(node as VNetNode).address_space}
                onChange={(e) =>
                  onChange({
                    ...node,
                    address_space: e.target.value,
                  } as Node)
                }
              />
            </div>
            <div>
              <label className="label">Subnet Prefix</label>
              <input
                className="input"
                value={(node as VNetNode).subnet_prefix}
                onChange={(e) =>
                  onChange({
                    ...node,
                    subnet_prefix: e.target.value,
                  } as Node)
                }
              />
            </div>
          </>
        )}

        {node.kind === "vm" && (
          <>
            <div>
              <label className="label">OS</label>
              <select
                className="input"
                value={(node as any).os}
                onChange={(e) =>
                  onChange({ ...node, os: e.target.value } as Node)
                }
              >
                <option value="linux">linux</option>
                <option value="windows">windows</option>
              </select>
            </div>
            <div>
              <label className="label">VM Size</label>
              <input
                className="input"
                value={(node as any).size}
                onChange={(e) =>
                  onChange({ ...node, size: e.target.value } as Node)
                }
              />
            </div>
            <div>
              <label className="label">OS Disk (GB)</label>
              <input
                type="number"
                className="input"
                value={(node as any).os_disk_gb}
                onChange={(e) =>
                  onChange({
                    ...node,
                    os_disk_gb: Number(e.target.value),
                  } as Node)
                }
              />
            </div>
            <div>
              <label className="label">Admin Username</label>
              <input
                className="input"
                value={(node as any).admin_username}
                onChange={(e) =>
                  onChange({
                    ...node,
                    admin_username: e.target.value,
                  } as Node)
                }
              />
            </div>
            {(node as any).os === "linux" ? (
              <>
                <div className="col-span-2">
                  <label className="label">
                    SSH Public Key (var or literal)
                  </label>
                  <input
                    className="input"
                    value={(node as any).ssh_public_key_var || ""}
                    onChange={(e) =>
                      onChange({
                        ...node,
                        ssh_public_key_var: e.target.value,
                      } as Node)
                    }
                  />
                </div>
                <label className="flex items-center gap-2 col-span-2">
                  <input
                    type="checkbox"
                    checked={(node as any).install_jenkins}
                    onChange={(e) =>
                      onChange({
                        ...node,
                        install_jenkins: e.target.checked,
                      } as Node)
                    }
                  />
                  Install Jenkins (cloud-init)
                </label>
              </>
            ) : (
              <div className="col-span-2">
                <label className="label">Admin Password (var)</label>
                <input
                  className="input"
                  value={
                    (node as any).admin_password_var ||
                    "var.windows_admin_password"
                  }
                  onChange={(e) =>
                    onChange({
                      ...node,
                      admin_password_var: e.target.value,
                    } as Node)
                  }
                />
              </div>
            )}
          </>
        )}

        {node.kind === "sql" && (
          <>
            <div>
              <label className="label">Server Name</label>
              <input
                className="input"
                value={(node as SqlNode).server_name}
                onChange={(e) =>
                  onChange({
                    ...node,
                    server_name: e.target.value,
                  } as Node)
                }
              />
            </div>
            <div>
              <label className="label">Database Name</label>
              <input
                className="input"
                value={(node as SqlNode).database_name}
                onChange={(e) =>
                  onChange({
                    ...node,
                    database_name: e.target.value,
                  } as Node)
                }
              />
            </div>
            <div>
              <label className="label">Admin Login</label>
              <input
                className="input"
                value={(node as SqlNode).administrator_login}
                onChange={(e) =>
                  onChange({
                    ...node,
                    administrator_login: e.target.value,
                  } as Node)
                }
              />
            </div>
            <div className="col-span-2">
              <label className="label">Admin Password (var)</label>
              <input
                className="input"
                value={(node as SqlNode).administrator_password_var}
                onChange={(e) =>
                  onChange({
                    ...node,
                    administrator_password_var: e.target.value,
                  } as Node)
                }
              />
            </div>
            <div>
              <label className="label">SKU Name</label>
              <input
                className="input"
                value={(node as SqlNode).sku_name}
                onChange={(e) =>
                  onChange({
                    ...node,
                    sku_name: e.target.value,
                  } as Node)
                }
              />
            </div>
            <div className="col-span-2">
              <label className="label">Collation</label>
              <input
                className="input"
                value={(node as SqlNode).collation}
                onChange={(e) =>
                  onChange({
                    ...node,
                    collation: e.target.value,
                  } as Node)
                }
              />
            </div>
          </>
        )}

        {node.kind === "cosmos" && (
          <>
            <div>
              <label className="label">Consistency</label>
              <select
                className="input"
                value={(node as CosmosNode).consistency}
                onChange={(e) =>
                  onChange({
                    ...node,
                    consistency: e.target.value as CosmosNode["consistency"],
                  } as Node)
                }
              >
                <option value="Session">Session</option>
                <option value="Strong">Strong</option>
                <option value="Eventual">Eventual</option>
                <option value="BoundedStaleness">BoundedStaleness</option>
              </select>
            </div>
          </>
        )}

        {node.kind === "appservice" && (
          <>
            <div>
              <label className="label">Plan Tier</label>
              <select
                className="input"
                value={(node as AppServiceNode).plan_sku_tier}
                onChange={(e) =>
                  onChange({
                    ...node,
                    plan_sku_tier: e.target.value as AppServiceNode["plan_sku_tier"],
                  } as Node)
                }
              >
                <option value="Basic">Basic</option>
                <option value="Standard">Standard</option>
                <option value="PremiumV2">PremiumV2</option>
              </select>
            </div>
            <div>
              <label className="label">Plan Size</label>
              <input
                className="input"
                value={(node as AppServiceNode).plan_sku_size}
                onChange={(e) =>
                  onChange({
                    ...node,
                    plan_sku_size: e.target.value,
                  } as Node)
                }
              />
            </div>
            <div className="col-span-2">
              <label className="label">Runtime Stack</label>
              <input
                className="input"
                value={(node as AppServiceNode).runtime_stack}
                onChange={(e) =>
                  onChange({
                    ...node,
                    runtime_stack: e.target.value,
                  } as Node)
                }
              />
            </div>
          </>
        )}

        {node.kind === "functionapp" && (
          <>
            <div>
              <label className="label">Runtime Stack</label>
              <input
                className="input"
                value={(node as FunctionAppNode).runtime_stack}
                onChange={(e) =>
                  onChange({
                    ...node,
                    runtime_stack: e.target.value,
                  } as Node)
                }
              />
            </div>
            <div>
              <label className="label">Storage Account Name</label>
              <input
                className="input"
                value={(node as FunctionAppNode).storage_account_name}
                onChange={(e) =>
                  onChange({
                    ...node,
                    storage_account_name: e.target.value,
                  } as Node)
                }
              />
            </div>
            <div>
              <label className="label">Plan Tier</label>
              <select
                className="input"
                value={(node as FunctionAppNode).plan_sku_tier}
                onChange={(e) =>
                  onChange({
                    ...node,
                    plan_sku_tier: e.target.value as FunctionAppNode["plan_sku_tier"],
                  } as Node)
                }
              >
                <option value="ElasticPremium">Elastic Premium</option>
                <option value="Dynamic">Consumption</option>
              </select>
            </div>
            <div>
              <label className="label">Plan Size</label>
              <input
                className="input"
                value={(node as FunctionAppNode).plan_sku_size}
                onChange={(e) =>
                  onChange({
                    ...node,
                    plan_sku_size: e.target.value,
                  } as Node)
                }
              />
            </div>
          </>
        )}

        {node.kind === "redis" && (
          <>
            <div>
              <label className="label">Capacity</label>
              <input
                type="number"
                min={0}
                className="input"
                value={(node as RedisNode).capacity}
                onChange={(e) =>
                  onChange({
                    ...node,
                    capacity: Number(e.target.value),
                  } as Node)
                }
              />
            </div>
            <div>
              <label className="label">Family</label>
              <select
                className="input"
                value={(node as RedisNode).family}
                onChange={(e) =>
                  onChange({
                    ...node,
                    family: e.target.value as RedisNode["family"],
                  } as Node)
                }
              >
                <option value="C">C (Basic/Standard)</option>
                <option value="P">P (Premium)</option>
              </select>
            </div>
            <div>
              <label className="label">SKU</label>
              <select
                className="input"
                value={(node as RedisNode).sku_name}
                onChange={(e) =>
                  onChange({
                    ...node,
                    sku_name: e.target.value as RedisNode["sku_name"],
                  } as Node)
                }
              >
                <option value="Basic">Basic</option>
                <option value="Standard">Standard</option>
                <option value="Premium">Premium</option>
              </select>
            </div>
            <label className="flex items-center gap-2 col-span-2">
              <input
                type="checkbox"
                checked={(node as RedisNode).enable_non_ssl_port}
                onChange={(e) =>
                  onChange({
                    ...node,
                    enable_non_ssl_port: e.target.checked,
                  } as Node)
                }
              />
              Enable non-SSL port
            </label>
          </>
        )}

        {node.kind === "privatedns" && (
          <div className="col-span-2">
            <label className="label">Zone Name</label>
            <input
              className="input"
              value={(node as PrivateDnsNode).zone_name}
              onChange={(e) =>
                onChange({
                  ...node,
                  zone_name: e.target.value,
                } as Node)
              }
            />
          </div>
        )}

        {node.kind === "loganalytics" && (
          <>
            <div>
              <label className="label">Retention (days)</label>
              <input
                type="number"
                min={7}
                className="input"
                value={(node as LogAnalyticsNode).retention_in_days}
                onChange={(e) =>
                  onChange({
                    ...node,
                    retention_in_days: Number(e.target.value),
                  } as Node)
                }
              />
            </div>
            <div>
              <label className="label">SKU</label>
              <select
                className="input"
                value={(node as LogAnalyticsNode).sku}
                onChange={(e) =>
                  onChange({
                    ...node,
                    sku: e.target.value as LogAnalyticsNode["sku"],
                  } as Node)
                }
              >
                <option value="PerGB2018">PerGB2018</option>
                <option value="Free">Free</option>
                <option value="Standalone">Standalone</option>
                <option value="CapacityReservation">Capacity Reservation</option>
              </select>
            </div>
          </>
        )}
        {node.kind === "vmss" && (
          <>
            <div>
              <label className="label">VM Size</label>
              <input
                className="input"
                value={(node as VMSSNode).size}
                onChange={(e) =>
                  onChange({ ...node, size: e.target.value } as Node)
                }
              />
            </div>
            <div>
              <label className="label">Instances</label>
              <input
                type="number"
                min={1}
                className="input"
                value={(node as VMSSNode).instances}
                onChange={(e) =>
                  onChange({
                    ...node,
                    instances: Number(e.target.value),
                  } as Node)
                }
              />
            </div>
            <div>
              <label className="label">Admin Username</label>
              <input
                className="input"
                value={(node as VMSSNode).admin_username}
                onChange={(e) =>
                  onChange({
                    ...node,
                    admin_username: e.target.value,
                  } as Node)
                }
              />
            </div>
            <div className="col-span-2">
              <label className="label">SSH Public Key (var or literal)</label>
              <input
                className="input"
                value={(node as VMSSNode).ssh_public_key_var}
                onChange={(e) =>
                  onChange({
                    ...node,
                    ssh_public_key_var: e.target.value,
                  } as Node)
                }
              />
            </div>
          </>
        )}

        {node.kind === "aks" && (
          <>
            <div>
              <label className="label">Kubernetes Version</label>
              <input
                className="input"
                value={(node as AKSNode).kubernetes_version}
                onChange={(e) =>
                  onChange({
                    ...node,
                    kubernetes_version: e.target.value,
                  } as Node)
                }
              />
            </div>
            <div>
              <label className="label">Node Count</label>
              <input
                type="number"
                className="input"
                value={(node as AKSNode).node_count}
                onChange={(e) =>
                  onChange({
                    ...node,
                    node_count: Number(e.target.value),
                  } as Node)
                }
              />
            </div>
            <div className="col-span-2">
              <label className="label">Node VM Size</label>
              <input
                className="input"
                value={(node as AKSNode).node_vm_size}
                onChange={(e) =>
                  onChange({
                    ...node,
                    node_vm_size: e.target.value,
                  } as Node)
                }
              />
            </div>
          </>
        )}

        {node.kind === "storage" && (
          <>
            <div>
              <label className="label">Account Tier</label>
              <select
                className="input"
                value={(node as StorageNode).account_tier}
                onChange={(e) =>
                  onChange({
                    ...node,
                    account_tier: e.target.value as StorageNode["account_tier"],
                  } as Node)
                }
              >
                <option value="Standard">Standard</option>
                <option value="Premium">Premium</option>
              </select>
            </div>
            <div>
              <label className="label">Replication Type</label>
              <select
                className="input"
                value={(node as StorageNode).replication_type}
                onChange={(e) =>
                  onChange({
                    ...node,
                    replication_type: e.target.value as StorageNode["replication_type"],
                  } as Node)
                }
              >
                <option value="LRS">LRS</option>
                <option value="GRS">GRS</option>
                <option value="RAGRS">RAGRS</option>
                <option value="ZRS">ZRS</option>
              </select>
            </div>
          </>
        )}

        {node.kind === "keyvault" && (
          <>
            <label className="flex items-center gap-2 col-span-2">
              <input
                type="checkbox"
                checked={(node as KeyVaultNode).purge_protection}
                onChange={(e) =>
                  onChange({
                    ...node,
                    purge_protection: e.target.checked,
                  } as Node)
                }
              />
              Enable purge protection
            </label>
            <div className="col-span-2">
              <label className="label">Soft Delete Retention (days)</label>
              <input
                type="number"
                className="input"
                min={7}
                value={(node as KeyVaultNode).soft_delete_retention_days}
                onChange={(e) =>
                  onChange({
                    ...node,
                    soft_delete_retention_days: Number(e.target.value),
                  } as Node)
                }
              />
            </div>
          </>
        )}

        {node.kind === "nsg" && (
          <>
            <label className="flex items-center gap-2 col-span-2">
              <input
                type="checkbox"
                checked={(node as NSGNode).allow_ssh}
                onChange={(e) =>
                  onChange({
                    ...node,
                    allow_ssh: e.target.checked,
                  } as Node)
                }
              />
              Allow SSH (22)
            </label>
            <label className="flex items-center gap-2 col-span-2">
              <input
                type="checkbox"
                checked={(node as NSGNode).allow_http}
                onChange={(e) =>
                  onChange({
                    ...node,
                    allow_http: e.target.checked,
                  } as Node)
                }
              />
              Allow HTTP (80)
            </label>
            <label className="flex items-center gap-2 col-span-2">
              <input
                type="checkbox"
                checked={(node as NSGNode).allow_https}
                onChange={(e) =>
                  onChange({
                    ...node,
                    allow_https: e.target.checked,
                  } as Node)
                }
              />
              Allow HTTPS (443)
            </label>
            <label className="flex items-center gap-2 col-span-2">
              <input
                type="checkbox"
                checked={(node as NSGNode).allow_jenkins}
                onChange={(e) =>
                  onChange({
                    ...node,
                    allow_jenkins: e.target.checked,
                  } as Node)
                }
              />
              Allow Jenkins (8080)
            </label>
            <div className="col-span-2">
              <label className="label">Extra Ports (comma separated)</label>
              <input
                className="input"
                value={(node as NSGNode).extra_ports}
                onChange={(e) =>
                  onChange({
                    ...node,
                    extra_ports: e.target.value,
                  } as Node)
                }
                placeholder="e.g. 3000, 5000"
              />
            </div>
          </>
        )}

        {node.kind === "lb" && (
          <>
            <div>
              <label className="label">Type</label>
              <select
                className="input"
                value={(node as LBNode).lb_type}
                onChange={(e) =>
                  onChange({
                    ...node,
                    lb_type: e.target.value as LBNode["lb_type"],
                  } as Node)
                }
              >
                <option value="public">Public</option>
                <option value="internal">Internal</option>
              </select>
            </div>
            <div>
              <label className="label">Frontend Port</label>
              <input
                type="number"
                className="input"
                value={(node as LBNode).fe_port}
                onChange={(e) =>
                  onChange({
                    ...node,
                    fe_port: Number(e.target.value),
                  } as Node)
                }
              />
            </div>
            <div>
              <label className="label">Backend Port</label>
              <input
                type="number"
                className="input"
                value={(node as LBNode).be_port}
                onChange={(e) =>
                  onChange({
                    ...node,
                    be_port: Number(e.target.value),
                  } as Node)
                }
              />
            </div>
          </>
        )}

        {node.kind === "appgw" && (
          <>
            <div>
              <label className="label">Listener Port</label>
              <input
                type="number"
                className="input"
                value={(node as AppGWNode).listener_port}
                onChange={(e) =>
                  onChange({
                    ...node,
                    listener_port: Number(e.target.value),
                  } as Node)
                }
              />
            </div>
            <div>
              <label className="label">Backend Port</label>
              <input
                type="number"
                className="input"
                value={(node as AppGWNode).backend_port}
                onChange={(e) =>
                  onChange({
                    ...node,
                    backend_port: Number(e.target.value),
                  } as Node)
                }
              />
            </div>
          </>
        )}
      </div>
    </div>
  );
}
