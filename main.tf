data "aws_iam_policy" "ebs_csi_policy" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

module "cluster" {
  source  = "gitlab.com/vkpr/terraform-aws-eks/aws"
  version = "~> 1.3.0"

  cluster_name              = local.config.cluster_name
  cluster_version           = local.config.cluster_version
  cidr_block                = local.config.cidr_block
  private_subnets           = local.config.private_subnets
  public_subnets            = local.config.public_subnets
  node_groups               = local.config.node_groups
  tags                      = local.config.tags
  cluster_enabled_log_types = try(local.config.cluster_enabled_log_types, [""])
  aws_availability_zones    = try(local.config.aws_availability_zones, [""])
}

data "aws_eks_cluster" "cluster" {
  name = local.config.cluster_name
  depends_on = [module.cluster]  
}
   
data "aws_eks_cluster_auth" "cluster" {
  name = local.config.cluster_name
  depends_on = [module.cluster]  
}

data "tls_certificate" "cert" {
  url = data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer
  depends_on = [module.cluster]  
}

resource "aws_iam_openid_connect_provider" "openid_connect" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.cert.certificates.0.sha1_fingerprint]
  url             = data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer
  depends_on = [module.cluster]  
}


module "irsa-ebs-csi" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version = "4.7.0"

  create_role                   = true
  role_name                     = "AmazonEKSTFEBSCSIRole_${local.config.cluster_name}"
  provider_url                  = replace(data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer, "https://", "")
  role_policy_arns              = [data.aws_iam_policy.ebs_csi_policy.arn]
  oidc_fully_qualified_subjects = ["system:serviceaccount:kube-system:ebs-csi-controller-sa"]
  depends_on = [module.cluster]  

}

resource "aws_eks_addon" "ebs-csi" {
  cluster_name             = local.config.cluster_name
  addon_name               = "aws-ebs-csi-driver"
  service_account_role_arn = module.irsa-ebs-csi.iam_role_arn
  tags = {
    "eks_addon" = "ebs-csi"
    "terraform" = "true"
  }
}

resource "kubectl_manifest" "storageclass" {
     yaml_body = <<YAML
   apiVersion: storage.k8s.io/v1
   kind: StorageClass
   metadata:
     name: gp3
   provisioner: ebs.csi.aws.com
   parameters:
     csi.storage.k8s.io/provisioner-secret-name: aws-secret
     csi.storage.k8s.io/provisioner-secret-namespace: kube-system
     type: gp3
     fsType: ext4
     encrypted: "true"
     tags: "vkpr=true, terraform=true"  # Add tags here
YAML
  depends_on = [module.cluster]
}

# Access EKS with AWS CLI
## Create IAM Root User 
resource "aws_iam_user" "root-user" {
  name = "root-user"

  depends_on = [
    module.cluster.aws_eks_cluster.this,
    module.cluster.aws_eks_node_group.workers
  ]
}

resource "aws_iam_access_key" "root-user_key" {
  user = aws_iam_user.root-user.name

  depends_on = [
    aws_iam_user.root-user
  ]
}

output "root_user_access_key_id" {
  value     = aws_iam_access_key.root-user_key.id
  sensitive = true
}

output "root_user_secret_access_key" {
  value     = aws_iam_access_key.root-user_key.secret
  sensitive = true
}

output "root_user_name" {
  value = aws_iam_user.root-user.name
}

output "root_user_arn" {
  value = aws_iam_user.root-user.arn
}

## Create IAM Developer User

resource "aws_iam_policy" "developer" {
  name        = "developer"
  description = "Política para desenvolvedores com permissões limitadas"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
          "eks:Describe*",
          "eks:List*",
          "s3:Get*",
          "s3:List*"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user" "developer" {
  name = "developer"
}

resource "aws_iam_access_key" "developer_key" {
  user = aws_iam_user.developer.name
}

resource "aws_iam_user_policy_attachment" "developer" {
  user       = aws_iam_user.developer.name
  policy_arn = aws_iam_policy.developer.arn
}

## Apply IAM Users in Cluster Auth ConfigMap
resource "kubernetes_config_map" "aws_auth" {

  metadata {
    name      = "root-aws-auth"
    namespace = "kube-system"
  }

  data = {
    mapUsers = jsonencode([{
      userarn  = aws_iam_user.root-user.arn
      username = aws_iam_user.root-user.name
      groups   = ["system:masters"]
    }])
    mapRoles = jsonencode([{
      groups   = ["system:bootstrappers", "system:nodes"],
      rolearn  = aws_iam_role.workers.arn,
      username = "system:node:{{EC2PrivateDNSName}}"
    }])
  }
  depends_on = [local_file.kubeconfig]
}