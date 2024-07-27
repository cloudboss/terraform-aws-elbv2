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

locals {
  connection_logs = (
    var.type == "application"
    ? var.application.connection_logs
    : null
  )

  drop_invalid_header_fields = (
    var.type == "application"
    ? var.application.drop_invalid_header_fields
    : null
  )

  # For application this is always enabled so use null to prevent invalid value.
  enable_cross_zone = var.type == "application" ? null : var.enable_cross_zone

  enable_tls_headers = (
    var.type == "application"
    ? var.application.enable_tls_headers
    : null
  )

  enable_xff_client_port = (
    var.type == "application"
    ? var.application.enable_xff_client_port
    : null
  )

  enable_waf_fail_open = (
    var.type == "application"
    ? var.application.enable_waf_fail_open
    : null
  )

  idle_timeout = (
    var.type == "application"
    ? var.application.idle_timeout
    : null
  )

  ip_address_type = (
    var.type == "application"
    ? var.application.ip_address_type
    : null
  )

  preserve_host_header = (
    var.type == "application"
    ? var.application.preserve_host_header
    : null
  )

  private_link_sg = (
    var.type == "network"
    ? var.network.enforce_private_link_security_group
    : null
  )

  security_group_ids = (
    var.type == "application" || var.type == "network"
    ? var.security_group_ids
    : null
  )

  xff_header_processing_mode = (
    var.type == "application"
    ? var.application.xff_header_processing_mode
    : null
  )

  alpn_policy = (
    var.listener.protocol == "TLS"
    ? var.listener.alpn_policy
    : null
  )

  certificate_arn = (
    var.listener.protocol == "HTTPS"
    ? length(var.listener.certificate_arns) > 0 ? var.listener.certificate_arns[0] : null
    : null
  )
  certificate_arns_other = (
    length(var.listener.certificate_arns) > 1
    ? slice(var.listener.certificate_arns, 1, length(var.listener.certificate_arns))
    : []
  )
  extra_certificate_arns = (
    var.listener.protocol == "HTTPS"
    ? toset(local.certificate_arns_other)
    : []
  )

  listener_port = (
    var.type == "gateway"
    ? null
    : var.listener.port
  )
  listener_protocol = (
    var.type == "gateway"
    ? null
    : var.listener.protocol
  )
  listener_default_action = try(var.listener.rules["default"], null)
  listener_rules          = { for k, rule in var.listener.rules : k => rule if k != "default" }

  tags_lb            = merge(var.tags.default, var.tags.lb)
  tags_listener      = merge(var.tags.default, var.tags.listener)
  tags_listener_rule = merge(local.tags_listener, var.tags.listener)
  tags_target_group  = merge(var.tags.default, var.tags.target_group)

  target_protocol_version = (
    var.target_group.protocol == "HTTP" || var.target_group.protocol == "HTTPS"
    ? var.target_group.protocol_version
    : null
  )
  target_proxy_protocol_v2 = (
    var.type == "network"
    ? var.target_group.proxy_protocol_v2
    : null
  )
  target_ip_address_type = (
    var.target_group.target_type == "ip"
    ? var.target_group.ip_address_type
    : null
  )
}

resource "terraform_data" "certificate_validate" {
  lifecycle {
    precondition {
      condition = (
        var.listener.protocol == "HTTPS"
        ? length(var.listener.certificate_arns) > 0
        : true
      )
      error_message = "An HTTPS listener requires at least one certificate ARN."
    }
  }
}

resource "terraform_data" "oidc_client_secret_validate" {
  lifecycle {
    precondition {
      condition = (
        alltrue([for key, rule in var.listener.rules :
          rule.authenticate_oidc != null ? try(var.oidc_client_secrets[key], null) != null : true
        ])
      )
      error_message = "When authenticate_oidc is defined for a listener rule, oidc_client_secrets must have an entry with the same key."
    }
  }
}

resource "aws_lb" "it" {
  client_keep_alive                                            = var.client_keep_alive
  customer_owned_ipv4_pool                                     = var.customer_owned_ipv4_pool
  drop_invalid_header_fields                                   = local.drop_invalid_header_fields
  enable_cross_zone_load_balancing                             = local.enable_cross_zone
  enable_deletion_protection                                   = var.enable_deletion_protection
  enable_tls_version_and_cipher_suite_headers                  = local.enable_tls_headers
  enable_xff_client_port                                       = local.enable_xff_client_port
  enable_waf_fail_open                                         = local.enable_waf_fail_open
  enforce_security_group_inbound_rules_on_private_link_traffic = local.private_link_sg
  idle_timeout                                                 = local.idle_timeout
  ip_address_type                                              = local.ip_address_type
  internal                                                     = var.internal
  load_balancer_type                                           = var.type
  name                                                         = var.name
  preserve_host_header                                         = local.preserve_host_header
  security_groups                                              = local.security_group_ids
  tags                                                         = length(local.tags_lb) > 0 ? local.tags_lb : null
  xff_header_processing_mode                                   = local.xff_header_processing_mode

  dynamic "access_logs" {
    for_each = var.access_logs == null ? [] : [1]
    content {
      bucket  = var.access_logs.bucket
      prefix  = var.access_logs.prefix
      enabled = true
    }
  }

  dynamic "connection_logs" {
    for_each = local.connection_logs == null ? [] : [1]
    content {
      bucket  = local.connection_logs.bucket
      prefix  = local.connection_logs.prefix
      enabled = true
    }
  }

  dynamic "subnet_mapping" {
    for_each = var.subnet_mapping
    content {
      allocation_id        = subnet_mapping.value.allocation_id
      ipv6_address         = subnet_mapping.value.ipv6_address
      private_ipv4_address = subnet_mapping.value.private_ipv4_address
      subnet_id            = subnet_mapping.value.subnet_id
    }
  }
}

resource "aws_lb_listener" "it" {
  alpn_policy       = local.alpn_policy
  load_balancer_arn = aws_lb.it.arn
  port              = local.listener_port
  protocol          = local.listener_protocol
  ssl_policy        = var.listener.ssl_policy
  certificate_arn   = local.certificate_arn
  tags              = length(local.tags_listener) > 0 ? local.tags_listener : null

  default_action {
    type = local.listener_default_action.type
    target_group_arn = (
      local.listener_default_action.type == "forward"
      ? aws_lb_target_group.it.arn
      : null
    )

    dynamic "authenticate_cognito" {
      for_each = (
        local.listener_default_action.authenticate_cognito == null
        ? []
        : [local.listener_default_action.authenticate_cognito]
      )
      iterator = auth
      content {
        authentication_request_extra_params = auth.value.authentication_request_extra_params
        on_unauthenticated_request          = auth.value.on_unauthenticated_request
        scope                               = auth.value.scope
        session_cookie_name                 = auth.value.session_cookie_name
        session_timeout                     = auth.value.session_timeout
        user_pool_arn                       = auth.value.user_pool_arn
        user_pool_client_id                 = auth.value.user_pool_client_id
        user_pool_domain                    = auth.value.user_pool_domain
      }
    }

    dynamic "authenticate_oidc" {
      for_each = (
        local.listener_default_action.authenticate_oidc == null
        ? []
        : [local.listener_default_action.authenticate_oidc]
      )
      iterator = auth
      content {
        authentication_request_extra_params = auth.value.authentication_request_extra_params
        authorization_endpoint              = auth.value.authorization_endpoint
        client_id                           = auth.value.client_id
        client_secret                       = try(var.oidc_client_secrets["default"], null)
        issuer                              = auth.value.issuer
        on_unauthenticated_request          = auth.value.on_unauthenticated_request
        scope                               = auth.value.scope
        session_cookie_name                 = auth.value.session_cookie_name
        session_timeout                     = auth.value.session_timeout
        token_endpoint                      = auth.value.token_endpoint
        user_info_endpoint                  = auth.value.user_info_endpoint
      }
    }

    dynamic "fixed_response" {
      for_each = (
        local.listener_default_action.fixed_response == null
        ? []
        : [local.listener_default_action.fixed_response]
      )
      content {
        content_type = fixed_response.value.content_type
        message_body = fixed_response.value.message_body
        status_code  = fixed_response.value.status_code
      }
    }

    dynamic "redirect" {
      for_each = (
        local.listener_default_action.redirect == null
        ? []
        : [local.listener_default_action.redirect]
      )
      content {
        host        = redirect.value.host
        path        = redirect.value.path
        port        = redirect.value.port
        protocol    = redirect.value.protocol
        query       = redirect.value.query
        status_code = redirect.value.status_code
      }
    }
  }

  dynamic "mutual_authentication" {
    for_each = (
      var.listener.mutual_authentication == null
      ? []
      : [var.listener.mutual_authentication]
    )
    iterator = auth
    content {
      mode                             = auth.value.mode
      trust_store_arn                  = auth.value.trust_store_arn
      ignore_client_certificate_expiry = auth.value.ignore_client_certificate_expiry
    }
  }
}

resource "aws_lb_listener_rule" "them" {
  for_each = local.listener_rules

  listener_arn = aws_lb_listener.it.arn
  priority     = each.value.priority
  tags         = length(local.tags_listener_rule) > 0 ? local.tags_listener_rule : null

  action {
    type = each.value.type
    target_group_arn = (
      each.value.type == "forward"
      ? aws_lb_target_group.it.arn
      : null
    )

    dynamic "authenticate_cognito" {
      for_each = (
        each.value.authenticate_cognito == null
        ? []
        : [each.value.authenticate_cognito]
      )
      iterator = auth
      content {
        authentication_request_extra_params = auth.value.authentication_request_extra_params
        on_unauthenticated_request          = auth.value.on_unauthenticated_request
        scope                               = auth.value.scope
        session_cookie_name                 = auth.value.session_cookie_name
        session_timeout                     = auth.value.session_timeout
        user_pool_arn                       = auth.value.user_pool_arn
        user_pool_client_id                 = auth.value.user_pool_client_id
        user_pool_domain                    = auth.value.user_pool_domain
      }
    }

    dynamic "authenticate_oidc" {
      for_each = (
        each.value.authenticate_oidc == null
        ? []
        : [each.value.authenticate_oidc]
      )
      iterator = auth
      content {
        authentication_request_extra_params = auth.value.authentication_request_extra_params
        authorization_endpoint              = auth.value.authorization_endpoint
        client_id                           = auth.value.client_id
        client_secret                       = try(var.oidc_client_secrets[each.key], null)
        issuer                              = auth.value.issuer
        on_unauthenticated_request          = auth.value.on_unauthenticated_request
        scope                               = auth.value.scope
        session_cookie_name                 = auth.value.session_cookie_name
        session_timeout                     = auth.value.session_timeout
        token_endpoint                      = auth.value.token_endpoint
        user_info_endpoint                  = auth.value.user_info_endpoint
      }
    }

    dynamic "fixed_response" {
      for_each = (
        each.value.fixed_response == null
        ? []
        : [each.value.fixed_response]
      )
      content {
        content_type = fixed_response.value.content_type
        message_body = fixed_response.value.message_body
        status_code  = fixed_response.value.status_code
      }
    }

    dynamic "redirect" {
      for_each = (
        each.value.redirect == null
        ? []
        : [each.value.redirect]
      )
      content {
        host        = redirect.value.host
        path        = redirect.value.path
        port        = redirect.value.port
        protocol    = redirect.value.protocol
        query       = redirect.value.query
        status_code = redirect.value.status_code
      }
    }
  }

  dynamic "condition" {
    for_each = each.value.condition == null ? [] : [each.value.condition]
    content {
      dynamic "host_header" {
        for_each = condition.value.host_header == null ? [] : [condition.value.host_header]
        content {
          values = host_header.value.values
        }
      }

      dynamic "http_header" {
        for_each = condition.value.http_header == null ? [] : [condition.value.http_header]
        content {
          http_header_name = http_header.value.http_header_name
          values           = http_header.value.values
        }
      }

      dynamic "http_request_method" {
        for_each = (
          condition.value.http_request_method == null
          ? []
          : [condition.value.http_request_method]
        )
        content {
          values = http_request_method.value.values
        }
      }

      dynamic "path_pattern" {
        for_each = (
          condition.value.path_pattern == null
          ? []
          : [condition.value.path_pattern]
        )
        content {
          values = path_pattern.value.values
        }
      }

      dynamic "query_string" {
        for_each = condition.value.query_strings
        content {
          key   = query_string.value.key
          value = query_string.value.value
        }
      }

      dynamic "source_ip" {
        for_each = condition.value.source_ip == null ? [] : [condition.value.source_ip]
        content {
          values = source_ip.value.values
        }
      }
    }
  }
}

resource "aws_lb_listener_certificate" "them" {
  for_each = local.extra_certificate_arns

  listener_arn    = aws_lb_listener.it.arn
  certificate_arn = each.value
}

resource "aws_lb_target_group" "it" {
  connection_termination = var.target_group.connection_termination
  deregistration_delay   = var.target_group.deregistration_delay
  ip_address_type        = local.target_ip_address_type
  name                   = var.name
  port                   = var.target_group.port
  protocol               = var.target_group.protocol
  protocol_version       = local.target_protocol_version
  proxy_protocol_v2      = local.target_proxy_protocol_v2
  tags                   = length(local.tags_target_group) > 0 ? local.tags_target_group : null
  target_type            = var.target_group.target_type
  vpc_id                 = var.vpc_id
}
