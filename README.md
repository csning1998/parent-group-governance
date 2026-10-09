# Parent Group Governance

This repository is the upstream governance root of a single developer workstation. Three concerns belong to this repository: the SELinux configuration of the host, the container services running under rootless Podman, and the GitLab group topology declared through Terraform. A Go command line tool named `governance` is the operator entry point for every runtime action.

## Section 1. Repository Scope

### Item A. Ownership Boundary

Six assets are owned here:

- The workstation SELinux policy module, together with the persistent file context registry covering every local repository on the host.
- The Bastion Vault instance acting as the trust root for every downstream platform repository.
- The host prerequisites of the Bastion Vault container, comprising the `vault-bastion-publish` libvirt network, the `virtnetworkd.service` unit, the firewalld rule for the Vault port, and the memlock limits of the operator user.
- The operator Vault Proxies on the host, one per operator identity of `workstation-topology.yaml`, which carry every non-root login to the Bastion Vault.
- The GitLab group topology under the `csning1998-lab` namespace, including group labels, group CI variables, the shared runner, and the SonarQube analysis token.
- The `governance` CLI, whose source resides under `tools/governance`.

A downstream platform repository consumes the Bastion Vault instance and the GitLab topology declared here. A downstream repository MUST NOT redeclare either asset.

### Item B. Directory Layout

| Path                        | Contents                                                                                              |
| --------------------------- | ----------------------------------------------------------------------------------------------------- |
| `ansible/`                  | The `workstation_*` roles, the local inventory, and the host playbooks                                |
| `terraform/layers/`         | Independently applied Terraform layers, each holding its own remote state                             |
| `terraform/modules/`        | Shared modules consumed by the layers                                                                 |
| `tools/governance/`         | Go source of the `governance` CLI, with its own design document                                       |
| `vault/`                    | `vault.hcl` rendered by `workstation_libvirt`, the raft storage, the TLS material, and the unseal key |
| `compose.yml`               | Declaration of every container service on the host                                                    |
| `workstation-topology.yaml` | The Bastion Vault listeners, the operator Vault Proxies, and the service admin passwords              |
| `.githooks/`                | Secret scanning and commit message hooks executed through short lived containers                      |
| `.gitlab/`                  | CODEOWNERS, the merge request template, the linter configuration, and the tagging schema              |

Paths holding runtime state are excluded from version control. The excluded set comprises `vault/data/`, `vault/keys/`, `vault/tls/`, `sonarqube/`, `gitlab-runner-configs/`, `.env`, and the compiled `governance` binary.

### Item C. Bootstrap Order

The bootstrap is one linear sequence. Each step depends on the steps above, and no step requires a recovery branch. Every service whose admin password lives in the Bastion Vault starts together with the Bastion Vault, and `./governance vault init` verifies that each service still accepts its factory default password, hence a fresh Bastion Vault always meets a fresh service state.

1. Run the first menu item `[Host] Apply All Workstation Prerequisites`, or `./governance host apply-all`. The item prompts for the become password once and applies the SELinux file contexts of Section 3 Item B, the libvirt host prerequisites and `vault/vault.hcl` of Section 4 Item C, the local CA under `vault/tls` when the directory holds none, and the operator Vault Proxies of Section 6 Item F.
2. Start all container services with `podman compose up -d`. The bind mount sources under `sonarqube/` and `vault/` are created by `podman-compose` and inherit `container_file_t` from the repository root.
3. Run `./governance vault init`. The command waits until every service of `service_admin_passwords` answers, refuses when a service rejects its factory default password, and initializes and unseals the Bastion Vault otherwise. Section 4 Item D describes the rebuild of a retained service state.
4. Run `./governance vault enable-kv`.
5. Run `eval "$(vault-proxy-env root)"` in the shell, then write the state backend token and the platform trust facts as described in Section 6 Item C Step 1 to Step 3.
6. Apply `foundation-vault-bastion` with the root token in the same shell, as described in Section 6 Item C Step 4. The apply creates `operator-cert` and the cert roles, after which each background Vault Proxy logs in.
7. Run `[Credentials] Rotate Service Admin Passwords` or `./governance credentials rotate sonarqube-admin-password`, which moves each service admin password into the Bastion Vault through the rotation Vault Proxy as described in Section 4 Item D Step 3.
8. Run `direnv allow` once in `terraform/` and once in `terraform/layers/meta-gitlab-project`, as described in Section 6 Item A.
9. Apply the downstream Terraform layers in the order of Section 6 Item C Step 5 onwards: `group-foundation`, `meta-gitlab-project`, `group-topology`, `group-gitlab-runner`, `group-sonarqube`, and `group-governance`.
10. Restart the runner with `podman compose restart gitlab-runner` after `group-gitlab-runner` renders the runner configuration.
11. Run `[Vault] Revoke Root Token After Bootstrap`, or `./governance vault revoke-root`, which ends the bootstrap as described in Section 6 Item G.

## Section 2. Host Prerequisites

### Item A. Development Machine Reference

The following specification is recorded for reference alone. Clauses in this document do not depend on the listed hardware.

- **Chipset:** Intel® HM770
- **CPU:** Intel® Core™ i7-14700HX
- **RAM:** Micron Crucial Pro 64 GB (32 GB × 2) DDR5-5600
- **SSD:** WD PC SN560 1 TB

### Item B. Required Host Tools

Three binaries MUST resolve on `PATH` before any Terraform layer is applied: `terraform`, `vault`, and `ansible`. The CLI reports the presence of each binary.

```bash
./governance host verify
```

Rootless Podman MUST be running under the operator account, because the Podman API socket beneath `/run/user/<uid>/podman/` is the transport used by the GitLab runner.

### Item C. Optional Host Tools

The Anthropic CLI `ant`, Google Cloud CLI `gcloud`, and Azure CLI `az` are host tools used when managing Workload Identity Federation across AI and cloud providers. The `./governance host verify` command does not validate the presence of these tools.

The operator can install these CLIs using the supported Ansible role `workstation_cloud_cli`:

```bash
cd ansible && ansible-playbook playbooks/workstation_cloud_cli.yaml --ask-become-pass && cd -
```

Authentication is an interactive manual step. The operator account MUST hold the admin, owner, or primary owner role in the Anthropic organization. Prior to running `terraform apply` across `group-federation-anthropic` or `meta-gitlab-project`, the operator MUST log in, extract the temporary access token, and record the credential into Bastion Vault at `parent-group-governance/ai-provider-console/anthropic`.

```bash
ant auth login --profile <profile> --scope "org:admin"
export ANTHROPIC_AUTH_TOKEN="$(ant auth print-credentials --profile <profile> --access-token)"
vault kv put -mount=secret parent-group-governance/ai-provider-console/anthropic \
    anthropic_admin_api_key="$ANTHROPIC_AUTH_TOKEN"
```

The profile defaults to `issuer-gitlab-saas`. Because the exported token expires within minutes, the operator MUST refresh the token and re-commit the value to Bastion Vault prior to each apply.

### Item D. Anthropic WIF Multi-Tenancy Architecture

The platform architecture implements a multi-tenant Workload Identity Federation pattern to govern AI provider access across consumer projects:

1. **Global Governance Layer (`group-federation-anthropic`)**:
    - Manages the single OIDC Issuer (`issuer-gitlab-saas` pointing to `https://gitlab.com`) at the Anthropic organization level.
    - Publishes the root trust contract (`organization` and `issuers`) via Terraform Remote State Outputs.
    - Remains strictly decoupled from individual downstream workspaces and projects.

2. **Downstream Multi-Tenant Projects (`provisioner-workload-identity-federation`)**:
    - Each consuming project (e.g., `gitlab-ci-with-code-reviewer`) invokes the provisioner module with its project code and path.
    - The module automatically provisions a dedicated project workspace (`ws-<project_code>`), a project service account (`sa-project-<project_code>`), and a matching federation rule (`rule-project-<project_code>`).
    - Guarantees strict multi-tenant isolation:
        - **Cost and Usage Isolation**: Monthly inference costs and token usage are isolated to the project workspace.
        - **Rate Limit Separation**: Request (RPM) and token (TPM) limits are partitioned per project.
        - **Safe Lifecycle & Pruning**: Downstream projects can be instantiated, modified, or destroyed (pruned) without modifying or disrupting the root organization federation.

## Section 3. SELinux Configuration

Every service declared in `compose.yml` runs under rootless Podman on a host with SELinux in enforcing mode. Each bind mount originates from a path beneath the user home directory, whose policy default type is `user_home_t`. A process confined as `container_t` does not hold access to `user_home_t`, which makes an explicit `container_file_t` label mandatory on every mount source.

### Item A. Standing Conventions

Four conventions MUST hold for every service declared in `compose.yml`.

1. A volume declaration MUST NOT carry a relabel flag. Neither `:z` nor `:Z` MUST appear on any volume line. Item G states the failure mode produced by a relabel flag.
2. The setting `security_opt: label=disable` MUST NOT appear on a service which runs continuously. Disabling label separation removes confinement rather than resolving the underlying label mismatch.
3. Every mount source path MUST be registered through `semanage fcontext`. The registration establishes `container_file_t` as the policy default instead of a manually applied label.
4. A service which accesses the rootless Podman socket MUST declare `label=type:container_engine_t`. The policy module described in Item C supplies the permissions required by the named type.

### Item B. Applying the Workstation Role

Registration of file contexts requires root privileges. The playbook `ansible/playbooks/workstation_selinux.yaml` is the single operator path, and the CLI is the supported invocation.

```bash
ansible-galaxy collection install -r ansible/requirements.yaml
./governance host apply-selinux
```

The CLI injects `workstation_selinux_home` from the operator home directory, because `become: true` gathers facts as root and resolves `ansible_facts.user_dir` to `/root`. The role asserts the injected value before any task runs. The role then executes three stages.

1. Stage A installs the local policy module described in Item C. Compilation is skipped when the module is already present at the current version.
2. Stage B registers every anchored file context specification, then restores drifted labels. A dry run of `restorecon -RFnv` is executed first on each target, and `restorecon -RFv` is applied only where the dry run reports a difference. A third block restores the label of every user session Podman API socket directory. A fourth block restores the targeted policy default on `/etc/fstab` without directory recursion.
3. Stage C removes unanchored specifications. An unanchored specification such as `vault(/.*)?` matches every basename on the filesystem during a full relabel, which labels unrelated directories as `container_file_t`.

The `-F` flag is mandatory, because the type `container_file_t` appears in `/etc/selinux/targeted/contexts/customizable_types`, whose entries `restorecon` leaves untouched without the flag. Omitting the flag produces `not reset as customized by admin` for each path.

A correct label reads as `container_file_t:s0` without a category suffix. An empty category set is dominated by every possible container category, which keeps a bare `container_file_t:s0` label readable by every service regardless of the category assigned at container startup.

### Item C. The Policy Module

The default policy does not grant any `connectto` permission on the container runtime socket. The module source resides at `ansible/roles/workstation_selinux/files/workstation_nnp_container_runtime.te` and carries three grant groups.

- A parent process with `NoNewPrivs=1` requires `process2 nnp_transition` on each domain transition. The module grants the transition from `unconfined_t` to `container_runtime_t`, and the transition from `container_runtime_t` to `iptables_t`.
- The rootless network backend `pasta_t` inherits the parent PTY when Podman starts from a graphical terminal. The module grants PTY read and write to `pasta_t`, plus an append permission on `config_home_t`. The netavark helper running as `iptables_t` inherits the same PTY and receives the same PTY grant.
- The GitLab runner creates `podman.sock` beneath a `user_tmp_t` parent directory. The module grants socket and directory writes to `container_engine_t` on `user_tmp_t`.

The module operates at the SELinux type level and stays independent of the MCS category handling described in Item B. Installing or removing the module does not affect category drift.

### Item D. Registered File Contexts

The authoritative registry is `workstation_selinux_fcontext_present` in `ansible/roles/workstation_selinux/defaults/main.yaml`. The table below summarizes the current registry. Every pattern is anchored beneath the operator `GitLab` directory unless the row states a system wide scope.

| Repository                              | Registered Path Pattern                                                                                          | Consumed By                                |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| `parent-group-governance`               | `(vault\|sonarqube)(/.*)?`, `.git(/.*)?`, and `.gitleaks.toml`                                                   | Bastion Vault, SonarQube, the commit hooks |
| `platform-foundation`                   | `(vault\|sonarqube\|runner-config)(/.*)?` and `.git(/.*)?`                                                       | Downstream platform services and hooks     |
| `generic-agent-criteria-source`         | `.git(/.*)?`                                                                                                     | The commit hooks                           |
| `terraform-provider-sshclient`          | `.git(/.*)?`                                                                                                     | The commit hooks                           |
| `on-premise-agent`                      | `(vault\|ollama_data\|open-webui_data\|searxng_data\|pipelines\|openclaw\|openclaw_data)(/.*)?` and `.git(/.*)?` | Local service bind mounts and hooks        |
| `on-premise-gitlab-deployment`          | The full repository tree                                                                                         | Arbitrary IaC bind mounts                  |
| `personal/second-brain`                 | `(postgres-data\|db/migrations)(/.*)?` and `.git(/.*)?`                                                          | Postgres bind mounts and hooks             |
| `personal/app-content-matter`           | `.git(/.*)?`                                                                                                     | The commit hooks                           |
| `personal/LaTeX_Documents`              | `.git(/.*)?`                                                                                                     | The commit hooks                           |
| `personal/monte-carlo-portfolio-trader` | `.git(/.*)?`                                                                                                     | The commit hooks                           |
| `template/template-project`             | `.git(/.*)?`                                                                                                     | The commit hooks                           |
| `template/template-project-fullstack`   | `.git(/.*)?`                                                                                                     | The commit hooks                           |
| `gitlab-ci-with-code-reviewer`          | `runner-config(/.*)?` and `.git(/.*)?`                                                                           | A GitLab runner and the commit hooks       |
| System wide                             | `/run/user/[0-9]+/podman(/.*)?`                                                                                  | The rootless Podman API socket             |

A repository without a `compose.yml` file registers `.git(/.*)?` alone, which limits container execution scope to the short lived Git lifecycle hooks.

The list `workstation_selinux_system_restorecon_paths` restores `/etc/fstab` to the targeted policy default `etc_t`. A custom file context specification is not registered for `/etc/fstab`.

The service `iac-runner` inside `on-premise-gitlab-deployment` is exempt from the conventions in Item A. Arbitrary Infrastructure as Code execution requires a bind mount of the entire project root, which makes a path restricted registration unworkable. The named service retains `security_opt: label=disable`.

### Item E. Verification

1. Each container MUST report a non-empty process label. An empty value indicates disabled label separation.

    ```bash
    for c in parent-group-governance-vault-bastion parent-group-governance-sonarqube-postgres \
            parent-group-governance-sonarqube parent-group-governance-gitlab-runner; do
        printf '%s\t' "$c"
        podman inspect "$c" --format '{{.ProcessLabel}}'
    done
    ```

2. The following command reports the distinct label set carried by every file beneath the registered mount sources. The reported set MUST contain the single entry `container_file_t:s0` without a category suffix.

    ```bash
    ls -RZ .gitleaks.toml vault sonarqube | grep -o 'container_file_t:s0[^ ]*' | sort -u
    ```

3. The runner MUST establish a connection to the Podman socket. The following request confirms access through an HTTP status of 200.

    ```bash
    podman exec parent-group-governance-gitlab-runner \
        curl -s -o /dev/null -w '%{http_code}\n' \
        --unix-socket /run/podman/podman.sock http://d/v1.41/_ping
    ```

4. The policy default of any path is retrieved through `matchpathcon`, which MUST report `container_file_t:s0` for every registered mount source.

    ```bash
    matchpathcon .gitleaks.toml vault/data sonarqube/data
    ```

5. The file `/etc/fstab` MUST carry `etc_t:s0`. The command `ls -Z /etc/fstab` reports the label.

    ```bash
    ls -Z /etc/fstab
    ```

### Item F. Diagnosing a Denial

1. Attribution requires the audit log, because an access failure surfaces inside the container as an ordinary permission error. The following command isolates denials raised by confined container processes.

    ```bash
    sudo ausearch -m avc -ts recent | grep 'scontext=system_u:system_r:container'
    ```

2. A denial raised by `pasta_t` against `config_home_t` or `data_home_t` is unrelated to the services declared here. Such a denial originates from a file descriptor inherited by the rootless network backend from the process launching Podman.

3. A denial whose `tcontext` carries a non-empty MCS category on a registered mount source indicates category drift. Item B restores the baseline, and Item G identifies the class of tooling causing the drift.

4. A denial whose `tcontext` names `container_runtime_t` with class `unix_stream_socket` and permission `connectto` indicates an absent policy module, or a service declaration missing the `container_engine_t` type.

5. A denial whose `tcontext` names `unlabeled_t` on `/etc/fstab` indicates a missing system label. Stage B restores the policy default `etc_t`. A local allow module MUST NOT be generated for the `getattr` denial.

### Item G. Recursive Relabeling from Local Tooling

The Podman relabel flags `:z` and `:Z` each rewrite the MCS category of every file beneath the mounted path at container start. A tool mounting the repository root therefore rewrites `vault/` and `sonarqube/` as a side effect, even where the tool does not relate to the services declared in `compose.yml`. The resulting category matches neither the short lived container nor any running service. A denial on the raft storage path can fail a Vault write, which panics the process and loses the unseal state.

Both hooks under `.githooks/` read the repository without writing to the repository. The hook `.githooks/pre-commit` mounts `.git` and `.gitleaks.toml` read only without a relabel flag. The hook `.githooks/commit-msg` mounts `.git` read only without a relabel flag. Any future local tool mounting the repository root, or mounting any ancestor of `vault/` and `sonarqube/`, MUST avoid `:z` and `:Z` for the same reason.

### Item H. Relabeling After Repository Relocation

The registration in Item B binds `container_file_t` to a literal path pattern rather than to the repository as a logical entity. Moving or renaming the repository directory leaves the registered rule pointing at an absent path, while the new path falls back to the parent directory default type `user_home_t` at the next `restorecon` invocation. The policy module installed in Item C is unaffected by relocation, because the module grants a permission to an SELinux type rather than to a filesystem path.

1. Confirm the current registration before removal, because the deletion in the next step requires an exact match of the registered string.

    ```bash
    sudo semanage fcontext -l | grep <PREVIOUS_PATH>
    ```

2. Update `workstation_selinux_fcontext_present` and `workstation_selinux_fcontext_absent` in the role defaults to name the current path, then apply the role again.

    ```bash
    ./governance host apply-selinux
    ```

3. An intra-filesystem move operation preserves the security context of each affected inode. A container running at the time of relocation therefore continues execution without interruption. Relabeling MUST be performed prior to any subsequent container recreation, manual `restorecon` invocation, or system wide relabel event.

## Section 4. Container Services

### Item A. Service Inventory

| Service         | Image                                  | Network                                  | Notes                                                                 |
| --------------- | -------------------------------------- | ---------------------------------------- | --------------------------------------------------------------------- |
| `vault-server`  | `hashicorp/vault:2.0`                  | Host namespace                           | Runs as `HOST_UID:HOST_GID` with `IPC_LOCK` and raft storage          |
| `gitlab-runner` | `gitlab/gitlab-runner:v19.0.1`         | Host namespace                           | Declares `label=type:container_engine_t` and mounts the Podman socket |
| `sonarqube`     | `sonarqube:26.7.0.124771-community`    | `sonarqube-internal`, `sonarqube-ci-net` | Published on `127.0.0.1:9000` alone                                   |
| `sonarqube-db`  | `postgres:18-alpine3.24`               | `sonarqube-internal`                     | Credentials injected from `SONARQUBE_DB_PASSWORD`                     |
| `commitlint`    | The reviewer image of the CI component | Default                                  | Short lived, invoked by `.githooks/commit-msg`                        |
| `gitleaks`      | `zricethezav/gitleaks:v8.30.1`         | Default                                  | Short lived, invoked by `.githooks/pre-commit`                        |

The bridge network `sonarqube-ci-net` carries a literal name, because the `[runners.docker]` section of the runner configuration references the same name as its `network_mode`. A CI job container therefore reaches SonarQube by service name without any published host port.

### Item B. The Vault Listener Startup Guard

The role `workstation_libvirt` renders `vault/vault.hcl` from `templates/vault.hcl.j2`, and Git ignores the rendered file. The role variables declare every listener address and port once, which the firewalld policy of Item C reuses. The first listener binds the loopback address with `workstation_libvirt_vault_port` for the local operator, Terraform, and the CLI. The second listener binds `workstation_libvirt_publish_network_address` with the same port for guest virtual machines connecting to the host over the hypervisor publish network. The third listener binds the publish address with `workstation_libvirt_vault_metrics_port` and `unauthenticated_metrics_access`, which serves `/v1/sys/metrics` to the observability scrapers without a token, while every other API path of the listener still requires a token. The container reads the file at start, hence a changed listener takes effect after the next restart of `vault-server`.

Vault exits when any declared TCP listener fails to bind. The host network namespace can present the address `172.16.0.1` later than the start of PID 1, which makes an unconditional start unreliable. The entrypoint therefore polls the host namespace for the address at 0.2 second intervals up to 150 attempts before executing the server.

### Item C. Host Prerequisites of the Vault Container

A host prerequisite is a host setting which the Vault container requires before the container starts. The role `workstation_libvirt` declares five host prerequisites.

1. The libvirt network `vault-bastion-publish` provides the address `172.16.0.1` on the bridge of the network.
2. The unit `virtnetworkd.service` is enabled, and a drop-in starts the unit after firewalld reports the running state.
3. The firewalld policy `libvirt-to-host` admits DHCP, DNS, ICMP, and TCP port 8200 from `172.16.0.0/12` to `172.16.0.1` for routed guests, and the scrape ports from each observability scraper segment alone, to any host address, since a scraper reaches the host through the gateway of its own segment.
4. The firewalld zone `libvirt` admits DHCP, DNS, and ICMP for NAT guests.
5. The memlock limits of the operator user are unlimited, because Vault locks memory under rootless Podman.

The unit `virtnetworkd.service` MUST be enabled. A host which enables only `virtnetworkd.socket` never starts the daemon at boot. The daemon executes the autostart of every libvirt network at startup alone. The network `vault-bastion-publish` therefore does not exist until a client connects to the socket.

The unit MUST start after firewalld reports the running state. libvirt adds each bridge to a zone when the network starts, and libvirt repeats the step on a firewalld reload but not on the first start of firewalld. A bridge created earlier stays outside every zone, and the default zone rejects the DHCP requests of the guests on that bridge.

The policy `libvirt-to-host` carries priority -1 and target REJECT. The policy decides routed guest traffic to the host before any rule of the zone `libvirt-routed`, hence the rule for port 8200 resides in the policy. The policy and the zone `libvirt` omit `ssh` and `tftp`, which the shipped files admit, since no guest of this host logs in to the host or fetches files from the host. The role overrides both shipped files under `/etc/firewalld`, hence a later libvirt package does not change the overrides.

The zone `trusted` MUST NOT bind an interface or a source. A binding in that zone accepts every port of the host and bypasses the policy and the zone `libvirt`. The role asserts the permanent zone `trusted` holds no binding.

The entrypoint of Item B exits after the polling attempts are exhausted. The restart policy `restart: always` then starts the container again. A missing prerequisite consequently produces a restart loop instead of a single failure.

```bash
ansible-galaxy collection install -r ansible/requirements.yaml
./governance host apply-libvirt
```

The CLI injects `workstation_libvirt_operator_user` from the operator account, because `become: true` gathers facts as root. The CLI also injects `workstation_libvirt_vault_config_path`, the path of `vault/vault.hcl` in the repository. The inventory `ansible/inventory/localhost.yaml` declares `workstation_libvirt_scraper_source_cidrs`, the observability scraper segments, and `workstation_libvirt_host_exporter_ports`, the node_exporter and the libvirt exporter which `hypervisor_baseline` of `platform-foundation` installs on the host. The scrape ports are the Bastion Vault metrics port and the declared host exporter ports. An empty segment list keeps every scrape port closed. The role asserts the injected value before any task runs. The firewalld rule relies on the sysctl parameters `rp_filter=2` and `ip_forward=1`, which the role `hypervisor_baseline` of `platform-foundation` declares.

### Item D. SonarQube Bootstrap

SonarQube holds the analysis token which `group-sonarqube` mints, and the token feeds the group variable `SONAR_TOKEN`. The administrator password lives in the Bastion Vault at `secret/parent-group-governance/sonarqube/admin-account`, field `sonarqube_admin_password`, and `./governance` is the only writer. `group-sonarqube` reads the password through an ephemeral read and authenticates as `admin` against `http://127.0.0.1:9000`.

1. All container services start together at Section 1 Item C Step 2. `SONARQUBE_DB_PASSWORD` comes from `.env`, which Section 5 Item C generates at the first bootstrap. `podman-compose` automatically creates the missing bind mount directories under `sonarqube/` on the host, which inherit `container_file_t` from the repository root.
2. `./governance vault init` waits until `/api/authentication/validate` answers and verifies the factory default `admin` before the initialization.
3. Run `[Credentials] Rotate Service Admin Passwords` or `./governance credentials rotate sonarqube-admin-password` after `foundation-vault-bastion` creates the cert roles. The rotation verifies the Vault value and the factory default `admin` through `/api/authentication/validate`, changes the password with the verified candidate, and writes the new value into the Bastion Vault.

    Interactive operator login to `http://127.0.0.1:9000` requires the rotated administrator password. The password MUST NOT be printed to standard output. The operator MUST pipe the retrieved secret directly to the clipboard with `xclip`:

    ```bash
    eval "$(vault-proxy-env parent-group-governance)"
    vault kv get -mount=secret -field=sonarqube_admin_password parent-group-governance/sonarqube/admin-account | tr -d '\n' | xclip -selection clipboard
    ```

4. Apply `group-sonarqube`, which writes the analysis token into `secret/parent-group-governance/sonarqube/ci-analysis-bot`, field `sonarqube_ci_token`.
5. Apply `group-governance`, which publishes `SONAR_TOKEN` as a masked group variable.

The administrator password exists in two places alone: the Bastion Vault and the hash inside `sonarqube/postgres-data`. A rebuilt Bastion Vault therefore orphans a retained database, whose password no tool can recover. `./governance vault init` refuses while SonarQube rejects the factory default password, hence a rebuild of the Bastion Vault rebuilds SonarQube before Section 1 Item C Step 3.

```bash
podman compose stop sonarqube sonarqube-db
podman unshare find sonarqube/data sonarqube/postgres-data -mindepth 1 -delete
```

The rebuild empties the two directories and keeps the directories, hence the bind mount sources and the registered labels survive. `podman unshare` is required, since the database files belong to a subordinate UID of the rootless container. The rebuild discards the analysis history and every token of the earlier instance, hence `group-sonarqube` mints a new analysis token on the next apply. The provider `jdamata/sonarqube` 0.16.21 fails the refresh of a token which the rebuilt instance lacks, instead of planning a replacement. The rebuild therefore ends with `terraform state rm sonarqube_user_token.ci_analysis` inside `terraform/layers/group-sonarqube`. SonarQube starts again at Section 1 Item C Step 2.

## Section 5. The Governance CLI

The `governance` binary is built from `tools/governance`. The full design of the rotation state machine resides in `tools/governance/README.md`. This section covers the operator surface alone.

```bash
cd tools/governance && go build -o ../../governance ./cmd/governance
```

### Item A. Dual Interface

The CLI exposes the same operations through two interfaces. Invocation without arguments opens the interactive menu, which suits manual operation. Invocation with a subcommand path runs one operation without prompting for a selection, which suits scripted use. Both interfaces dispatch into the same operation functions.

### Item B. Operation Inventory

| Menu Entry                                                                 | Subcommand                               | Effect                                                                     |
| -------------------------------------------------------------------------- | ---------------------------------------- | -------------------------------------------------------------------------- |
| `[Host] Apply All Workstation Prerequisites`                               | `host apply-all`                         | Runs the SELinux, libvirt, local CA, and Vault Proxy steps with one prompt |
| `[Host] Verify Host IaC Tools`                                             | `host verify`                            | Reports the presence of Terraform, Vault, and Ansible on `PATH`            |
| `[Host] Apply Workstation SELinux Policy and File Contexts`                | `host apply-selinux`                     | Runs the playbook described in Section 3 Item B                            |
| `[Host] Apply Workstation Libvirt Network and Bastion Vault Prerequisites` | `host apply-libvirt`                     | Runs the playbook described in Section 4 Item C                            |
| `[Host] Apply Workstation Vault Proxies`                                   | `host apply-vault-proxy`                 | Runs the playbook described in Section 6 Item F                            |
| `[Vault] Set up TLS for Bastion Vault`                                     | `vault generate-tls`                     | Clears `vault/tls` and issues a fresh CA with a server certificate         |
| `[Vault] Initialize Bastion Vault`                                         | `vault init`                             | Verifies the factory default of each service, then initializes and unseals |
| `[Vault] Enable KV-v2 Engine`                                              | `vault enable-kv`                        | Mounts the KV version 2 engine at the path `secret`                        |
| `[Vault] Unseal Bastion Vault`                                             | `vault unseal`                           | Submits the recorded unseal key                                            |
| `[Vault] Revoke Root Token After Bootstrap`                                | `vault revoke-root`                      | Revokes the root token once the foundation Vault Proxy logs in             |
| `[Vault] Generate Root Token for Break-Glass`                              | `vault generate-root`                    | Produces a root token from the stored unseal keys into `~/.vault-token`    |
| `[Credentials] Rotate Service Admin Passwords`                             | `credentials rotate <credential-key>`    | Generates a password, deploys the password, and commits the value to Vault |
| `[Credentials] Reconcile Service Admin Passwords with the Live Service`    | `credentials reconcile <credential-key>` | Pushes the value held by Vault out to a drifted live service               |
| `[Terraform] Audit State Secrets`                                          | `terraform audit-state [--history]`      | Lists state locations holding a secret, see tools/governance Section 11    |

Each key listed under `service_admin_passwords` of `workstation-topology.yaml` becomes one subcommand under `vault`, and one more under `vault reconcile`. The menu presents the same keys as a multiple selection prompt, annotated with whether Vault already holds a value for the given key. The interactive banner reports the Bastion Vault state as stopped, uninitialized, sealed, or unsealed before any prompt appears. The CLI reads the Bastion Vault endpoint and the listener addresses of the TLS material from `bastion_vault` of the same file.

### Item C. Environment File Lifecycle

Every subcommand other than the bare root command bootstraps `.env` before running. The bootstrap populates host identity and the SonarQube database password, and the file is rewritten through a temporary file with an atomic rename. Six keys are managed. The file carries neither the Bastion Vault address, which `workstation-topology.yaml` declares, nor a Vault token.

| Key                     | Source                                                                     |
| ----------------------- | -------------------------------------------------------------------------- |
| `PROJECT_ROOT`          | The directory holding the `.git` entry nearest above the working directory |
| `HOST_UID`, `HOST_GID`  | The operator account identifiers, consumed by `compose.yml`                |
| `UNAME`, `UHOME`        | The operator user name and home directory                                  |
| `SONARQUBE_DB_PASSWORD` | Generated once from `crypto/rand` at first bootstrap                       |

The file `.env` is the only copy of `SONARQUBE_DB_PASSWORD`, while `sonarqube/postgres-data` keeps the password of the first initialization. A deleted `.env` therefore generates a password which the existing database rejects, and the recovery is a rebuild of `sonarqube/postgres-data` and `sonarqube/data`.

### Item D. Credential Rotation

The list `service_admin_passwords` of `workstation-topology.yaml` declares every rotatable service admin account. A declaration names the Vault mount, the Vault path, the generated length, and the service mechanism performing the remote password change. The current declaration covers the SonarQube administrator account alone.

Every rotation and every reconciliation first verifies the live credential through `service.verify_endpoint`, a read only request, and changes nothing when no known credential is live. Rotation applies a write ahead staging protocol across the Vault document and the external service, guarded by a Check and Set advisory lock. The protocol, the recovery paths, and the boundary conditions are documented in `tools/governance/README.md`.

## Section 6. Terraform Layers

### Item A. State Backend and Authentication

Every layer stores state in the GitLab HTTP backend under the project hosting this repository, with one state name per layer. Before planning or applying any layer, the shell environment MUST be initialized with `eval "$(vault-proxy-env <role>)"`. The value of `<role>` MUST match the Vault Proxy Role column of Item B.

- `terraform/.envrc` loads the identity `parent-group-governance` by default.
- The first apply of `foundation-vault-bastion` MUST run with `eval "$(vault-proxy-env root)"` in the shell. The identity `root` routes `VAULT_ADDR` to `https://127.0.0.1:8200` and authenticates through `~/.vault-token`.
- `terraform/layers/meta-gitlab-project/.envrc` loads `governance` via `eval "$(vault-proxy-env governance)"`.
- All environments export `TF_HTTP_USERNAME` and `TF_HTTP_PASSWORD` from `secret/parent-group-governance/terraform/state-backend`. The identity `root` reads the secret with the root token, and every other identity reads the secret through the governance Proxy.
- The GitLab provider reads a token from the same secret through an ephemeral read, which keeps the token out of the persisted state of the consuming layer.

### Item B. Layer Inventory

| Layer                        | Responsibility                                                                           | Vault Proxy Role (`<role>`)                           | Upstream State                                   |
| :--------------------------- | :--------------------------------------------------------------------------------------- | :---------------------------------------------------- | :----------------------------------------------- |
| `foundation-vault-bastion`   | The PKI hierarchy, operator cert roles, tenant ACLs, the registry, transit unseal, audit | `root` (bootstrap), `parent-group-governance` (day-2) | None                                             |
| `group-foundation`           | The top level group `Personal Lab` at path `csning1998-lab`                              | `parent-group-governance`                             | None                                             |
| `meta-gitlab-project`        | The GitLab project hosting this repository and every Terraform state                     | `governance`                                          | `group-foundation`, `group-federation-anthropic` |
| `group-topology`             | Every subgroup and nested subgroup beneath the top level group                           | `parent-group-governance`                             | `group-foundation`                               |
| `group-governance`           | Group labels and the group CI variables sourced from Vault                               | `parent-group-governance`                             | `group-topology`                                 |
| `group-gitlab-runner`        | The group runner registration and the rendered `gitlab-runner-configs/config.toml`       | `parent-group-governance`                             | `group-topology`                                 |
| `group-sonarqube`            | The SonarQube global analysis token, written into Vault                                  | `parent-group-governance`                             | None                                             |
| `group-federation-anthropic` | The Anthropic Workload Identity Federation issuer trusting `https://gitlab.com`          | `parent-group-governance`                             | None                                             |
| `group-federation-gcp`       | The Google Cloud Workload Identity Federation pool and provider                          | `parent-group-governance`                             | None                                             |
| `group-federation-azure`     | The Azure Entra ID application and federated identity credentials                        | `parent-group-governance`                             | None                                             |

The layer `foundation-vault-bastion` issues the credentials consumed by every later layer. The PKI hierarchy comprises a Root CA signing the Bootstrap Issuing Intermediate alone, and the intermediate issues every leaf certificate. The Root CA certificate resource declares `prevent_destroy`, because destruction invalidates every downstream certificate without a rotation handler.

The layer `group-governance` publishes the masked group variable `SONAR_TOKEN` read out of Vault. Reviewer bot credentials have migrated to the project layer (`meta-gitlab-project`) via `provisioner-code-reviewer`.

The layer `group-sonarqube` writes the path `sonarqube/ci-analysis-bot`. The `./governance` rotation of `sonarqube-admin-password` writes the path `sonarqube/admin-account`. The separation keeps one writer per Vault path.

### Item C. Apply Order

The order follows the upstream state column of Item B. The Bastion Vault instance MUST be unsealed with the KV version 2 engine mounted before the first layer is applied. The platform trust facts MUST reside at `secret/parent-group-governance/platform-trust` before `foundation-vault-bastion` is planned. Step 1 to Step 4 run with the root token, which `eval "$(vault-proxy-env root)"` selects, and every later step runs in the layer directory with the `.envrc` of Item A.

1. Write the shared GitLab token into the field `token` as listed below. Any path modification MUST be reflected across consuming Terraform layers.

    ```bash
    cd $HOME/GitLab/csning1998-lab/parent-group-governance

    vault kv put \
        secret/parent-group-governance/platform-trust \
        @terraform/layers/foundation-vault-bastion/platform-trust.json

    vault kv put \
        secret/parent-group-governance/terraform/state-backend \
        token='glpat-replace-corresponding-placeholder-token'

    vault kv put \
        secret/parent-group-governance/ai-provider-console/anthropic \
        anthropic_admin_api_key='sk-ant-replace-corresponding-placeholder-api-key'

    vault kv put \
        secret/parent-group-governance/github/publication \
        deploy_token='ghp_replace-corresponding-placeholder-token'

    vault kv put \
        secret/gitlab-ci-with-code-reviewer/terraform/state-backend \
        token='glpat-replace-corresponding-placeholder-token'

    vault kv put \
        secret/gitlab-ci-with-code-reviewer/integration/code-reviewer-bot \
        token='glpat-replace-corresponding-placeholder-token'

    vault kv put \
        secret/gitlab-ci-with-code-reviewer/integration/auto-version-tag-bot \
        token='glpat-replace-corresponding-placeholder-token'
    ```

2. Copy `terraform/layers/foundation-vault-bastion/platform-trust.example.json` to `platform-trust.json` in the same directory, and replace every example value with the value of the deployment. Git ignores `platform-trust.json`.
3. Write the facts: `vault kv put secret/parent-group-governance/platform-trust @terraform/layers/foundation-vault-bastion/platform-trust.json`.
4. Apply `foundation-vault-bastion` with the root token. The apply creates the cert auth mount `operator-cert` and one cert role per identity of `workstation-topology.yaml`, after which every Vault Proxy logs in, and every later apply of the layer runs as `parent-group-governance`.
5. Apply `group-foundation`.
6. Apply `group-federation-*` (for example `group-federation-anthropic`), provided the operator holds the required provider admin credentials recorded into Vault.
7. Apply `meta-gitlab-project`, whose `.envrc` loads the governance identity, and apply `group-topology` in either order.
8. Apply `group-gitlab-runner`. Restart the runner container with `podman compose restart gitlab-runner` afterwards.
9. Apply `group-sonarqube` after Section 1 Item C Step 7 writes the administrator password into the Bastion Vault.
10. Apply `group-governance`, which reads the token written by `group-sonarqube`.

The platform trust facts hold four fields. Every field is a string, because KV version 2 stores flat string values.

| Field                  | Content                                                                    | Example            |
| ---------------------- | -------------------------------------------------------------------------- | ------------------ |
| `domain_suffix`        | The DNS domain of the platform                                             | `example.internal` |
| `stages`               | A JSON list of DNS labels, one SPIRE trust domain per stage                | `["production"]`   |
| `network_cidr`         | The IPv4 network of the platform                                           | `10.20.0.0/16`     |
| `bastion_publish_cidr` | The IPv4 network on which the Bastion Vault listens, inside `network_cidr` | `10.20.0.0/24`     |

A precondition of `foundation-vault-bastion` stops the plan when a field is missing or malformed. The Name Constraints of the constrained intermediate CAs derive from these fields, and a changed value therefore reissues the constrained intermediate CAs on the next apply. Neither a tfvars file nor `TF_VAR_` overrides the facts. `documentation/architecture/bastion-vault-privilege-convergence.md` Section 4 Item A records the rationale.

### Item D. Shared Modules

- `provisioner-gitlab-project` creates one GitLab project with a fixed merge policy, branch protection on `main`, and generic `extra_variables`. The caller supplies every environment specific value.
- `provisioner-vault-credential` generates a set of random passwords and writes one KV version 2 secret. The module is the single generation point for the secrets under its control.

### Item E. Known Operational Risks of the State

`./governance terraform audit-state` reports the locations below, since each value enters the state through a provider attribute without a write-only form. Each location is a known operational risk, and the ignore file MUST NOT exempt the location, because the value is confidential. The convergence model is a CI job which reads Vault at run time through a GitLab `id_tokens` login, which removes the CI variable itself.

| Layer                    | Address                                                                      | Value                                                                    |
| ------------------------ | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `meta-gitlab-project`    | `module.code_reviewer`                                                       | The reviewer and tag bot tokens, read and published as project variables |
| `group-governance`       | `data.vault_kv_secret_v2.sonar_token`, `gitlab_group_variable.review_secret` | The SonarQube analysis token, read and published as a group variable     |
| `group-sonarqube`        | `sonarqube_user_token.ci_analysis`, `vault_kv_secret_v2.sonar_token`         | The SonarQube analysis token, minted by the provider                     |
| `group-gitlab-runner`    | `gitlab_user_runner.shared`, `local_sensitive_file.runner_config`            | The runner authentication token                                          |
| `group-federation-azure` | `azurerm_cognitive_account.openai`                                           | The account access keys, inert while `local_auth_enabled = false`        |

The historical state versions of every layer still hold values which a later change removed. A purge of the history and a rotation of each exposed value close the record.

### Item F. Governance Layers of the Group

The governance layer of every repository in the group, such as `meta-gitlab-project` or `governance-gitlab-project`, MUST run through the governance Vault Proxy, which the `.envrc` of the layer loads with `eval "$(vault-proxy-env governance)"`. The tenant registry of the Bastion Vault lists platforms alone, hence a governance layer does not hold a tenant identity.

1. The role `workstation_vault_proxy` runs one Vault Proxy per identity of `operator_proxy.identities` as a systemd user unit. Each Proxy listens on `127.0.0.1` at the port of the identity, requires a client certificate signed by the local CA of `vault/tls`, and overwrites the token of every request with the token of its own login.
2. Each Proxy logs in through the cert auth mount `operator-cert` with a client certificate of CN `operator-<identity>`, and the cert role of the identity admits that CN alone. The private key of the client certificate is the long lived credential, and the file carries mode `0600` below `~/.config/vault-proxy/<identity>`.
3. The role issues each certificate for 365 days, and every run of the role reissues a certificate within 30 days of expiry or after a CA change. The Proxy reloads the certificate without a restart. Each Proxy retries a failed login at most every `workstation_vault_proxy_login_retry_seconds` seconds, hence a Proxy which starts before the cert roles exist logs in within that bound after the apply of `foundation-vault-bastion`, and `vault-proxy-env` waits as long before reporting the failure.
4. Each identity declares one access. The access `governance` reads `parent-group-governance/terraform/state-backend` and the paths of `reads`, and writes nothing. The access `tenant` holds the tenant ACL of the platform and the registry reader. The access `foundation` manages every object of `foundation-vault-bastion`. The access `rotation` reads and writes the paths of `service_admin_passwords` alone, which `./governance` uses for the rotation and the reconciliation.
5. The token of each login is bound to `127.0.0.1/32`, lives one hour, and renews to four hours at most. A caller holds the placeholder token `proxy-supplied` alone, hence a leaked shell environment exposes no Vault token.
6. `vault-proxy-env <identity>` prints the environment of the identity, including `VAULT_CLIENT_CERT` and `VAULT_CLIENT_KEY`, which the Vault CLI, the Vault provider, and Ansible present to the mTLS listener. The identity `root` prints the loopback listener of the Bastion Vault and the token helper instead.
7. The group keys stay group wide, since GitLab.com Free offers neither project nor group access tokens. A Premium subscription replaces the shared tokens with a project access token per repository, without a change of the Proxies or the governance layers.
8. The Bastion Vault Web UI is served at `https://127.0.0.1:8200/ui`. Operator tokens issued by `operator-cert` declare `token_bound_cidrs = ["127.0.0.1/32"]`. Connections to the publish address `https://172.16.0.1:8200/ui` are rejected with `permission denied`. The foundation operator token is obtained via `vault login -address="https://127.0.0.1:8200" -method=cert -client-cert="$HOME/.config/vault-proxy/parent-group-governance/client.pem" -client-key="$HOME/.config/vault-proxy/parent-group-governance/client-key.pem" -ca-cert=vault/tls/ca.pem -path=operator-cert name=operator-parent-group-governance` and submitted under Method `Token`.

### Item G. Root Token Lifecycle

The root token serves the bootstrap alone: `vault init`, `vault enable-kv`, the first writes of Section 6 Item C Step 1 to Step 3, and the first apply of `foundation-vault-bastion`.

1. `./governance vault init` writes the root token to `vault/keys/init-output.json` and the token helper file `~/.vault-token`. An unseal never restores the token, and `.env` never holds the token.
2. `./governance vault revoke-root` revokes the token once the foundation identity logs in through its Proxy with its policy, and refuses otherwise, since the revocation would leave the Bastion Vault without an administrator. The command removes `~/.vault-token` and empties `root_token` of `init-output.json`.
3. `./governance vault generate-root` produces a root token for break-glass from the unseal keys of `vault/keys/unseal.key`, and writes the token to `~/.vault-token`. The break-glass work ends with `revoke-root` again.
4. Vault 2 authenticates the generate-root endpoints by default. `vault.hcl` therefore declares `enable_unauthenticated_access = ["generate-root"]`, hence the break-glass needs the unseal key quorum alone and no identity which might be broken. An unauthenticated caller can cancel an attempt, and cannot finish one without the quorum.
5. The interactive banner warns while `~/.vault-token` holds a token.

## Section 7. Continuous Integration

The pipeline includes five components published by the `gitlab-ci-with-code-reviewer` project at version 1.7.3.

- The `core` component runs the AI merge request reviewer and the SonarQube analysis.
- The `iac-terraform` component runs Checkov across the Terraform tree. Four checks are skipped: three GitLab checks require a paid subscription tier, and `CKV_TF_1` demands commit pinned Git URLs, which conflicts with the immutable semantic versions already used from the GitLab Terraform Registry.
- The `iac-ansible` component lints every file beneath `ansible/`.
- The `lang-go` component builds, vets, and tests the module under `tools/governance`.
- The `auto-tag` component tags the default branch on push, treating the repository as a single module per `.gitlab/versioning.yml`.

Two local hooks run before a commit reaches the remote. The hook `.githooks/pre-commit` runs gitleaks against the staged changes. The hook `.githooks/commit-msg` runs commitlint against the message. Activation requires one command.

```bash
git config core.hooksPath .githooks
```
