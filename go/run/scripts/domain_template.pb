config: {
  domain_info: {
    name: "Demo"
    policy_keys_path: "policy_keys"
    guard_type: "REPLACE_WITH_DOMAIN_GUARD_TYPE"
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

  datalog_guard_info: {
    signed_rules_path: "rules"
  }

  tpm_info: {
    tpm_path: "/dev/tpm0"
    aik_path: "aikblob"
    pcrs: "17,18"
  }
}

datalog_rules: "(forall P: forall Host: forall Hash: TrustedHost(Host) and TrustedProgramHash(Hash) and Subprin(P, Host, Hash) implies MemberProgram(P))"
datalog_rules: "(forall P: forall Host: forall Hash: TrustedHost(Host) and TrustedContainerHash(Hash) and Subprin(P, Host, Hash) implies MemberProgram(P))"
datalog_rules: "(forall P: forall Host: forall Hash: TrustedVMHost(Host) and TrustedProgramHash(Hash) and Subprin(P, Host, Hash) implies MemberProgram(P))"
datalog_rules: "(forall P: forall Host: forall Hash: TrustedGuardedHost(Host) and TrustedProgramHash(Hash) and Subprin(P, Host, Hash) implies MemberProgram(P))"

datalog_rules: "(forall T: forall PCRs: forall P: TrustedTPM(T) and TrustedOS(PCRs) and Subprin(P, T, PCRs) implies TrustedHost(P))"
datalog_rules: "(forall P: forall VM: forall Host: TrustedHost(Host) and TrustedVMImage(VM) and Subprin(P, Host, VM) implies TrustedVM(P))"
datalog_rules: "(forall P: forall VM: forall Hash: TrustedVM(VM) and TrustedLinuxHost(Hash) and Subprin(P, VM, Hash) implies TrustedVMHost(P))"
datalog_rules: "(forall P: forall VM: forall Guard: TrustedVMHost(VM) and TrustedGuard(Guard) and Subprin(P, VM, Guard) implies TrustedGuardedHost(P))"

datalog_rules: "(forall P: TrustedVMHost(P) implies Authorized(P, \"Execute\"))"
datalog_rules: "(forall P: MemberProgram(P) implies Authorized(P, \"Execute\"))"

host_predicate_name: "TrustedHost"

program_paths: "mixnet_router"
program_paths: "demo_server"
program_paths: "demo_client"
program_predicate_name: "TrustedProgramHash"

container_paths: "demo_server.img.tgz"
container_paths: "demo_client.img.tgz"
container_predicate_name: "TrustedContainerHash"

vm_paths: "coreos_production_qemu_image.img"
vm_predicate_name: "TrustedVMImage"

linux_host_paths: "linux_host.img.tgz"
linux_host_predicate_name: "TrustedLinuxHost"

guard_predicate_name: "TrustedGuard"
tpm_predicate_name: "TrustedTPM"
os_predicate_name: "TrustedOS"
