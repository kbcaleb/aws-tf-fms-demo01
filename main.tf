# Firewall manager VPC
module "firewall_manager_vpc" {
  source = "terraform-aws-modules/vpc/aws"
  version = "3.7.0"

  name = "firewall-manager-vpc"
  cidr = var.vpc_cidr

  azs = ["us-west-2a", "us-west-2b", "us-west-2c", "us-west-2d"]

  enable_nat_gateway = false
  enable_vpn_gateway = false
  create_egress_only_igw = false
  create_igw = false

  tags = {
    Name = "firewall-manager-vpc"
  }

}

# Blue Security Zone SGs
module "blue_zone_sg" {
  depends_on = [module.firewall_manager_vpc]
  count = length(chunklist(var.blue_zone_cidrs,3))
  source = "terraform-aws-modules/security-group/aws"
  name = "tls-blue-0${count.index}"
  description = "TLS Blue 0${count.index}"
  vpc_id = module.firewall_manager_vpc.vpc_id
  ingress_rules = ["https-443-tcp"]
  ingress_cidr_blocks = element(chunklist(var.blue_zone_cidrs,3), count.index)
}

# Red Security Zone SGs
module "red_zone_sg" {
  depends_on = [module.firewall_manager_vpc]
  count = length(chunklist(var.red_zone_cidrs,3))
  source = "terraform-aws-modules/security-group/aws"
  name = "tls-red-0${count.index}"
  description = "TLS Red 0${count.index}"
  vpc_id = module.firewall_manager_vpc.vpc_id
  ingress_rules = ["https-443-tcp"]
  ingress_cidr_blocks = element(chunklist(var.red_zone_cidrs,3), count.index)
}

# Yellow Security Zone SGs
module "yellow_zone_sg" {
  depends_on = [module.firewall_manager_vpc]
  count = length(chunklist(var.yellow_zone_cidrs,3))
  source = "terraform-aws-modules/security-group/aws"
  name = "tls-yellow-0${count.index}"
  description = "TLS Yellow 0${count.index}"
  vpc_id = module.firewall_manager_vpc.vpc_id
  ingress_rules = ["https-443-tcp"]
  ingress_cidr_blocks = element(chunklist(var.yellow_zone_cidrs,3), count.index)
}

# Blue Firewall Manager Policies
resource "aws_fms_policy" "firewall_tls_blue_policy" {
  depends_on = [module.blue_zone_sg]
  count = length(module.blue_zone_sg.*.security_group_id)
  name                  = "FMS-Policy-TLS-Blue-0${count.index}"
  exclude_resource_tags = false
  remediation_enabled   = false
  resource_type_list    = ["AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::EC2::Instance"]

  include_map {
    account = [var.app01_account_id]
  }

  security_service_policy_data {
    type = "SECURITY_GROUPS_COMMON"

    managed_service_data = jsonencode({
      type = "SECURITY_GROUPS_COMMON",
      revertManualSecurityGroupChanges = "false",
      exclusiveResourceSecurityGroupManagement = "false",
      applyToAllEC2InstanceENIs = "false",
      securityGroups = [{
        id = module.blue_zone_sg[count.index].security_group_id,
      }]
    })
  }
}

# Red Firewall Manager Policies
resource "aws_fms_policy" "firewall_tls_red_policy" {
  depends_on = [module.red_zone_sg]
  count = length(module.red_zone_sg.*.security_group_id)
  name                  = "FMS-Policy-TLS-Red-0${count.index}"
  exclude_resource_tags = false
  remediation_enabled   = false
  resource_type_list    = ["AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::EC2::Instance"]

  include_map {
    account = [var.app02_account_id]
  }

  security_service_policy_data {
    type = "SECURITY_GROUPS_COMMON"

    managed_service_data = jsonencode({
      type = "SECURITY_GROUPS_COMMON",
      revertManualSecurityGroupChanges = "false",
      exclusiveResourceSecurityGroupManagement = "false",
      applyToAllEC2InstanceENIs = "false",
      securityGroups = [{
        id = module.red_zone_sg[count.index].security_group_id,
      }]
    })
  }
}

# Yellow Firewall Manager Policies
resource "aws_fms_policy" "firewall_tls_yellow_policy" {
  depends_on = [module.yellow_zone_sg]
  count = length(module.yellow_zone_sg.*.security_group_id)
  name                  = "FMS-Policy-TLS-Yellow-0${count.index}"
  exclude_resource_tags = false
  remediation_enabled   = false
  resource_type_list    = ["AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::EC2::Instance"]

  include_map {
    account = [var.app03_account_id]
  }

  security_service_policy_data {
    type = "SECURITY_GROUPS_COMMON"

    managed_service_data = jsonencode({
      type = "SECURITY_GROUPS_COMMON",
      revertManualSecurityGroupChanges = "false",
      exclusiveResourceSecurityGroupManagement = "false",
      applyToAllEC2InstanceENIs = "false",
      securityGroups = [{
        id = module.yellow_zone_sg[count.index].security_group_id,
      }]
    })
  }
}
