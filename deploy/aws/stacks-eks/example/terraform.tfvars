########################################
# Environment Configuration
########################################
region   = "eu-west-2"
env      = "Dev"
app_name = "Stacks-DotNet"
owner    = "Terraform"

########################################
# Cluster Configuration
########################################

cluster_name                    = "amido-stacks"
cluster_version                 = "1.21"
enable_irsa                     = true
cluster_endpoint_private_access = false
cluster_endpoint_public_access  = true
eks_desired_nodes               = 2

map_users = [
  {
    userarn  = "arn:aws:iam::316154162729:user/dibya.dhar@amido.com"
    username = "dibya.dhar@amido.com"
    groups   = ["system:masters"]
  },
  {
    userarn  = "arn:aws:iam::316154162729:user/ali.russell@amido.com"
    username = "ali.russell@amido.com"
    groups   = ["system:masters"]
  },
  {
    userarn  = "arn:aws:iam::316154162729:user/william.ayerst@amido.com"
    username = "william.ayerst@amido.com"
    groups   = ["system:masters"]
  },
  {
    userarn  = "arn:aws:iam::316154162729:user/terraform"
    username = "terraform"
    groups   = ["system:masters"]
  }
]
map_roles = [{
  groups   = ["system:masters"]
  rolearn  = "arn:aws:iam::316154162729:role/eks-admin-role"
  username = "eks-admin-role"
}]


########################################
# DNS Configuration
########################################

dns_hostedzone_name = "nonprodaws.amidostacks.com"

enable_zone = true
public_zones = {
  "test.amido.com" = {
    comment = "This is a sample hosted zone don't use in production or any deployment purpose"
  }
}

########################################
# IRSA Configuration
########################################
s3_irsa = {
  create               = true
  namespace            = "default",
  service-account-name = "access-s3-only"
}

stacks_dotnet_irsa = {
  create               = true
  namespace            = "nonprod-dev-netcore-api-cqrs",
  service-account-name = "access-sqs-sns-dd"
}
 