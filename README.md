# elbv2

This is a Terraform module to manage Elastic V2 network and application load balancers.

## Example

```
module "lb_tsa" {
  source  = "cloudboss/elbv2/aws"
  version = "0.1.0"

  listener = {
    port     = 2222
    protocol = "TCP"
    rules = {
      default = {
        type = "forward"
      }
    }
  }
  name               = "application-tsa"
  security_group_ids = [var.security_group_tsa]
  subnet_mapping = [for subnet_id in local.private_subnet_ids : {
    subnet_id = subnet_id
  }]
  tags = local.tags
  target_group = {
    deregistration_delay = 0
    port                 = 2222
    protocol             = "TCP"
  }
  type   = "network"
  vpc_id = var.vpc_id
}


module "lb_web" {
  source  = "cloudboss/elbv2/aws"
  version = "0.1.0"

  internal = false
  listener = {
    default_action = {
      type = "forward"
    }
    port             = 443
    protocol         = "HTTPS"
    certificate_arns = [module.acm_certificate_web.certificate_arn]
    rules = {
      default = {
        type = "forward"
      }
    }
  }
  name               = "application-web"
  security_group_ids = [var.security_group_web]
  subnet_mapping = [for subnet_id in local.public_subnet_ids : {
    subnet_id = subnet_id
  }]
  tags = local.tags
  target_group = {
    deregistration_delay = 15
    port                 = 8080
    protocol             = "HTTP"
  }
  type   = "application"
  vpc_id = var.vpc_id
}
```
