vault {
  address   = "https://do-not-delete-ever-v2-public-vault-cf6a1d76.5773df81.z1.hashicorp.cloud:8200"
  namespace = "admin/ibm"
}

auto_auth {
  method "approle" {
    config = {
      role_id_file_path                   = "/vault/config/role-id"
      secret_id_file_path                 = "/vault/config/secret-id"
      remove_secret_id_file_after_reading = false
    }
  }

  sink "file" {
    config = {
      path = "/vault/token"
    }
  }
}

template_config {
  static_secret_render_interval = "10s"
}

template {
  source      = "/vault/templates/extrato-api-key.tpl"
  destination = "/vault/secrets/extrato-api-key"
  perms       = "0644"
  wait {
    min = "1s"
    max = "5s"
  }
}

template {
  source      = "/vault/templates/ca-cert.tpl"
  destination = "/vault/secrets/ca.crt"
  perms       = "0644"
  wait {
    min = "1s"
    max = "5s"
  }
}

exit_after_auth = false
pid_file        = "/vault/agent.pid"
