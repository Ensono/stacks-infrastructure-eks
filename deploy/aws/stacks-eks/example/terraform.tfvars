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
    userarn  = "arn:aws:iam::316154162729:user/darren.smallwood@amido.com"
    username = "darren.smallwood@amido.com"
    groups   = ["system:masters"]
  }
]

########################################
# DNS Configuration
########################################

dns_hostedzone_name = "nonprodaws.amidostacks.com"