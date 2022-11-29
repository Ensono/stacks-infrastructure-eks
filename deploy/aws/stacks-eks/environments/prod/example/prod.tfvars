########################################
# Environment Configuration
########################################
region   = "eu-west-2"
env      = "Prod"
app_name = "Stacks"
owner    = "Terraform"

########################################
# Cluster Configuration
########################################

cluster_name                    = "amido-stacks"
cluster_version                 = "1.24"
enable_irsa                     = true
cluster_endpoint_private_access = false
cluster_endpoint_public_access  = true
eks_desired_nodes               = 3

map_users = [
  {
    userarn  = "arn:aws:iam::316154162729:user/terraform"
    username = "terraform"
    groups   = ["system:masters"]
  }
]

map_roles = [{
  rolearn  = "arn:aws:iam::316154162729:role/eks-admin-role"
  username = "eks-admin-role"
  groups   = ["system:masters"]
}]

########################################
# DNS Configuration
########################################

dns_hostedzone_name = "prodaws.amidostacks.com"

enable_zone = false #In Amido's case while deployment "prodaws.amidostacks.com" exist and delegates to the root domain "amidostacks.com" in root account

public_zones = {
  "prodaws.amidostacks.com" = {
    comment = "This hosted zone serves production traffic"
  }
}

########################################
# IRSA Configuration
########################################
s3_irsa = {
  create               = false
  namespace            = "default",
  service-account-name = "access-s3-only"
}

# It it's true, this will fail initially as there will be no name-space nonprod-dev-netcore-api-cqrs present while creating the cluster
stacks_dotnet_irsa = {
  create               = false
  namespace            = "nonprod-dev-netcore-api-cqrst", 
  service-account-name = "access-sqs-sns-dd"
}
 