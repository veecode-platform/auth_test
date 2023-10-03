terraform {
  backend "s3" {
    bucket = "vkpr-teste"
    key    = "auth_test/terraform.tfstate"
    region = "us-east-1"
  }
}