config: {
  domain_info: {
    name: "Process Datalog Demo"
    policy_keys_path: "policy_keys"
    guard_type: "Datalog"
  }

  x509_info: {
    common_name: "Test"
    country: "US"
    state: "WA"
    organization: "CloudProxy"
  }

  datalog_guard_info: {
    signed_rules_path: "rules" 
  }
}

datalog_rules: "(forall P: forall Host: forall Hash: TrustedHost(Host) and TrustedProgramHash(Hash) and Subprin(P, Host, Hash) implies MemberProgram(P))"
datalog_rules: "(forall P: MemberProgram(P) implies Authorized(P, \"Execute\"))"
datalog_rules: "(forall T: forall PCRs: forall P: TrustedTPM(T) and TrustedOS(PCRs) and Subprin(P, T, PCRs) implies TrustedHost(P))"

program_paths: "demo_server"
program_paths: "demo_client"

program_predicate_name: "TrustedProgramHash"
