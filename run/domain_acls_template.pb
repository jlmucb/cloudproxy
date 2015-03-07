config: {
  domain_info: {
    name: "Process ACLs Demo"
    policy_keys_path: "policy_keys"
    guard_type: "ACLs"
  }

  x509_info: {
    common_name: "Test"
    country: "US"
    state: "WA"
    organization: "CloudProxy"
  }

  acl_guard_info: {
    signed_acls_path: "acls" 
  }
}

program_paths: "demo_server"
program_paths: "demo_client"
