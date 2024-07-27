# Copyright © 2024 Joseph Wright <joseph@cloudboss.co>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

variable "access_logs" {
  type = object({
    bucket = string
    prefix = optional(string, null)
  })
  description = "Configuration for access logs."

  default = null
}

variable "application" {
  type = object({
    connection_logs = optional(object({
      bucket = string
      prefix = optional(string, null)
    }), null)
    drop_invalid_header_fields = optional(bool, null)
    enable_tls_headers         = optional(bool, null)
    enable_xff_client_port     = optional(bool, null)
    enable_waf_fail_open       = optional(bool, null)
    idle_timeout               = optional(number, null)
    ip_address_type            = optional(string, null)
    preserve_host_header       = optional(bool, null)
    xff_header_processing_mode = optional(string, null)
  })
  description = "Configuration specific to application load balancers."

  default = {}
}

variable "client_keep_alive" {
  type        = number
  description = "Client keep alive in seconds."

  default = null
}

variable "customer_owned_ipv4_pool" {
  type        = string
  description = "ID of clustomer owned ipv4 pool for the load balancer to use."

  default = null
}

variable "enable_cross_zone" {
  type        = bool
  description = "Whether or not to enable cross zone load balancing."

  default = null
}

variable "enable_deletion_protection" {
  type        = bool
  description = "Whether or not to enable deletion protection."

  default = false
}

variable "network" {
  type = object({
    enforce_private_link_security_group = optional(string, null)
  })
  description = "Configuration specific to network load balancers."

  default = {}
}

variable "internal" {
  type        = bool
  description = "Whether or not the load balancer is internal."

  default = true
}

variable "listener" {
  type = object({
    alpn_policy      = optional(string, null)
    certificate_arns = optional(list(string), [])
    mutual_authentication = optional(object({
      mode                             = string
      trust_store_arn                  = string
      ignore_client_certificate_expiry = optional(bool, null)
    }), null)
    port     = optional(number, null)
    protocol = optional(string, null)
    rules = map(object({
      authenticate_cognito = optional(object({
        authentication_request_extra_params = optional(map(string), null)
        on_unauthenticated_request          = optional(string, null)
        scope                               = optional(string, null)
        session_cookie_name                 = optional(string, null)
        session_timeout                     = optional(number, null)
        user_pool_arn                       = string
        user_pool_client_id                 = string
        user_pool_domain                    = string
      }), null)
      authenticate_oidc = optional(object({
        authentication_request_extra_params = optional(map(string), null)
        authorization_endpoint              = string
        client_id                           = string
        # For client_secret: add an entry in var.oidc_client_secrets
        # with the same key as the rule.
        issuer                     = string
        on_unauthenticated_request = optional(string, null)
        scope                      = optional(string, null)
        session_cookie_name        = optional(string, null)
        session_timeout            = optional(number, null)
        token_endpoint             = string
        user_info_endpoint         = string
      }), null)
      condition = optional(object({
        host_header = optional(object({
          values = set(string)
        }), null)
        http_header = optional(object({
          http_header_name = string
          values           = set(string)
        }), null)
        http_request_method = optional(object({
          values = set(string)
        }), null)
        path_pattern = optional(object({
          values = set(string)
        }), null)
        query_strings = optional(list(object({
          key   = optional(string, null)
          value = string
        })), [])
        source_ip = optional(object({
          values = set(string)
        }), null)
      }), null)
      fixed_response = optional(object({
        content_type = string
        message_body = optional(string, null)
        status_code  = optional(string, null)
      }), null)
      priority = optional(number, null)
      redirect = optional(object({
        host        = optional(string, null)
        path        = optional(string, null)
        port        = optional(string, null)
        protocol    = optional(string, null)
        query       = optional(string, null)
        status_code = string
      }), null)
      type = string
    }))
    ssl_policy = optional(string, null)
  })
  description = "Configuration for the listener."

  validation {
    condition     = contains(keys(var.listener.rules), "default")
    error_message = "There must be at least one listener rule called default."
  }
}

variable "oidc_client_secrets" {
  type        = map(string)
  description = "OIDC client secrets for listener rules with authenticate_oidc defined. The key of the secret must match the rule name."

  default   = {}
  sensitive = true
}

variable "name" {
  type        = string
  description = "The name of the load balancer."
}

variable "security_group_ids" {
  type        = list(string)
  description = "Security group IDs for the load balancer."

  default = null
}

variable "subnet_mapping" {
  type = list(object({
    allocation_id        = optional(string, null)
    ipv6_address         = optional(string, null)
    private_ipv4_address = optional(string, null)
    subnet_id            = string
  }))
  description = "Subnet mappings for the load balancer."
}

variable "tags" {
  type = object({
    default       = optional(map(string), null)
    lb            = optional(map(string), null)
    listener      = optional(map(string), null)
    listener_rule = optional(map(string), null)
    target_group  = optional(map(string), null)
  })
  description = "Tags to assign to resources. If only default is defined, it will be applied to all."

  default = {}
}

variable "target_group" {
  type = object({
    connection_termination = optional(bool, null)
    deregistration_delay   = optional(number, null)
    health_check = optional(object({
      enabled             = optional(bool, null)
      healthy_threshold   = optional(number, null)
      interval            = optional(number, null)
      matcher             = optional(string, null)
      path                = optional(string, null)
      port                = optional(string, null)
      protocol            = optional(string, null)
      timeout             = optional(number, null)
      unhealthy_threshold = optional(number, null)
    }), null)
    ip_address_type                    = optional(string, null)
    lambda_multi_value_headers_enabled = optional(bool, null)
    load_balancing_algorithm_type      = optional(string, null)
    load_balancing_anomaly_mitigation  = optional(string, null)
    load_balancing_cross_zone_enabled  = optional(bool, null)
    port                               = optional(number, null)
    preserve_client_ip                 = optional(bool, null)
    protocol                           = optional(string, null)
    protocol_version                   = optional(string, null)
    proxy_protocol_v2                  = optional(bool, null)
    slow_start                         = optional(number, null)
    stickiness = optional(object({
      cookie_duration = optional(number, null)
      cookie_name     = optional(string, null)
      enabled         = optional(bool, null)
      type            = optional(string, null)
    }), null)
    target_failover = optional(object({
      on_deregistration = optional(string, null)
      on_unhealthy      = optional(string, null)
    }), null)
    target_group_health = optional(object({
      dns_failover = optional(object({
        minimum_healthy_targets_count      = optional(string, null)
        minimum_healthy_targets_percentage = optional(string, null)
      }), null)
      unhealthy_state_routing = optional(object({
        minimum_healthy_targets_count      = optional(string, null)
        minimum_healthy_targets_percentage = optional(string, null)
      }), null)
    }), null)
    target_health_state = optional(object({
      enable_unhealthy_connection_termination = optional(bool, null)
    }), null)
    target_type = optional(string, null)
  })
  description = "Configuration for the target group."

  default = {}
}

variable "type" {
  type        = string
  description = "Type of the load balancer."

  validation {
    condition     = contains(["application", "gateway", "network"], var.type)
    error_message = "The type must be one of application, gateway, or network."
  }
}

variable "vpc_id" {
  type        = string
  description = "ID of the VPC."
}
