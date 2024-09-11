# Terraform version
terraform {
  required_version = ">= 1.3.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.10.0"
      # configuration_aliases = [ aws.test ]
    }
  }
}