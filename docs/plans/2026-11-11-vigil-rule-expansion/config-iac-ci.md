# Config, IaC and CI rule expansion — candidates

Scope: deterministic rules only (line/regex + bounded block helpers, path globs). No LLM,
no network, no taint/dataflow. Every candidate below is checked against
`current-rules.md` (163 rules on 0.5.4) and is **not** a duplicate.

ID allocation: current maxima are `VGL-CFG-029` and `VGL-CI-017`. `VGL-CFG-022` is an
unused gap in the published list; new config rules start at `VGL-CFG-030` so a removed
rule ID is never recycled. New CI rules start at `VGL-CI-018`.

Result: **21 candidates** — 12 P0/P1, 9 P2.

Reference conventions: CWE links are `https://cwe.mitre.org/data/definitions/<id>.html`;
OWASP Top 10 links are `https://owasp.org/Top10/`; OWASP CI/CD Top 10 links are
`https://owasp.org/www-project-top-10-ci-cd-security-risks/`; OWASP Docker Top 10 links are
`https://owasp.org/www-project-docker-top-10/`.

## Summary

| ID | Title | Severity | Priority |
|---|---|---|---|
| VGL-CFG-030 | Docker CLI shares a host network, PID, IPC or UTS namespace | high | P1 |
| VGL-CFG-031 | Docker Compose shares host PID, IPC or UTS namespace | high | P2 |
| VGL-CFG-032 | Container disables seccomp or AppArmor confinement | high | P1 |
| VGL-CFG-033 | Container grants a dangerous Linux capability | high | P1 |
| VGL-CFG-034 | Container mounts a raw host device | high | P2 |
| VGL-CFG-035 | Container mounts the host root filesystem | high | P2 |
| VGL-CFG-036 | Docker CLI runs a container privileged | high | P0 |
| VGL-CFG-037 | Compose publishes a datastore or admin port on all interfaces | medium | P2 |
| VGL-CFG-038 | Kubernetes RBAC grants wildcard access to secrets | high | P2 |
| VGL-CFG-039 | Kubernetes container unmasks /proc | medium | P2 |
| VGL-CFG-040 | IAM policy grants full administrative access | critical | P0 |
| VGL-CFG-041 | Security group allows all traffic from the internet | high | P0 |
| VGL-CFG-042 | S3 public access block is explicitly disabled | high | P0 |
| VGL-CFG-043 | CloudTrail logging is explicitly disabled | high | P2 |
| VGL-CFG-044 | EC2 instance metadata allows IMDSv1 | high | P0 |
| VGL-CFG-045 | nginx disables upstream TLS certificate verification | high | P1 |
| VGL-CI-018 | Privileged workflow checks out untrusted PR code | critical | P0 |
| VGL-CI-019 | Untrusted event data interpolated into actions/github-script | high | P1 |
| VGL-CI-020 | CI job container uses privileged Docker options | high | P2 |
| VGL-CI-021 | GitLab Runner runs jobs in privileged mode | high | P1 |
| VGL-CI-022 | GitLab CI disables Docker-in-Docker TLS | high | P2 |

## Coverage map — requested candidates already covered

These were deliberately **not** proposed as new IDs:

| Requested pattern | Existing rule |
|---|---|
| Docker/Compose `privileged` | `VGL-CFG-007` (Compose) |
| Docker socket mount | `VGL-CFG-009` |
| `--cap-add SYS_ADMIN` / `capabilities.add: SYS_ADMIN` | `VGL-CFG-010` |
| Compose `network_mode: host` | `VGL-CFG-008` |
| Secret in Docker `ARG`/`ENV` | `VGL-CFG-005` |
| Docker `ADD http(s)://` | `VGL-CFG-004` |
| `curl \| sh` in Dockerfile / CI | `VGL-CFG-006`, `VGL-CI-006`, `VGL-CI-016` |
| K8s `privileged`, `hostPath`, `hostNetwork`, `hostPID`, `hostIPC`, `allowPrivilegeEscalation`, `runAsUser: 0` | `VGL-CFG-012` |
| K8s `runAsNonRoot: false` | `VGL-CFG-018` |
| K8s literal secret in `env` | `VGL-CFG-020` |
| K8s `cluster-admin` binding | `VGL-CFG-029` |
| Terraform public S3 ACL | `VGL-CFG-014` |
| Terraform RDS `publicly_accessible` | `VGL-CFG-023` |
| Terraform SG `0.0.0.0/0` on SSH/RDP/DB/Redis/Mongo ports | `VGL-CFG-013`, `VGL-CFG-027` |
| Terraform EBS / storage encryption disabled | `VGL-CFG-015`, `VGL-CFG-024` |
| nginx `autoindex on` | `VGL-CFG-016` |
| nginx `ssl_protocols TLSv1/TLSv1.1` | `VGL-CFG-028` |
| GitHub `pull_request_target` + PR-head checkout | `VGL-CI-002` |
| GitHub unpinned action | `VGL-CI-001` |
| GitHub `permissions: write-all` | `VGL-CI-004` |
| GitHub `${{ github.event.* }}` in `run:` | `VGL-CI-003` |
| GitHub secret echoed to logs | `VGL-CI-007` |
| GitLab `CI_DEBUG_TRACE` | `VGL-CI-015` |
| GitLab `allow_failure` on security job | `VGL-CI-010` |

## Open-source rule-pack review

| Pack | What it covers that is relevant here | How this proposal uses it |
|---|---|---|
| hadolint | Dockerfile-only checks: `sudo` (DL3004), unpinned packages (DL3008/DL3013), `ADD` vs `COPY` (DL3020), pipefail (DL4006). It does not inspect `docker run` or Compose runtime flags. | We avoid duplicating Dockerfile hygiene and fill the runtime gap with CFG-030/031/033/034/035/036. https://github.com/hadolint/hadolint/wiki |
| Checkov | Dockerfile, Kubernetes, Terraform and CloudFormation policies, including S3 Block Public Access (CKV_AWS_53–56), IMDS, IAM and security groups. | CFG-040–044 align with the high-signal Checkov controls; CFG-030/031/036 cover runtime flags Checkov does not scan. https://www.checkov.io/5.Policy%20Index/terraform.html |
| tfsec | AWS IAM wildcards, S3 public-access blocks, IMDSv1, excessive security-group ports, ECR immutability, KMS rotation. | CFG-040–044 use the same controls and cite the exact tfsec check pages; ECR/KMS were cut as lower-value P2. https://aquasecurity.github.io/tfsec/latest/checks/aws/ |
| KICS | Broad multi-IaC queries, including Docker Compose and Terraform. | Confirms the Compose port/host-namespace and Terraform IAM/S3/SG checks. https://docs.kics.io/latest/queries/ |
| Terrascan | OPA-based IaC policies for AWS, Kubernetes and Docker. | Confirms the IAM/S3/SG control set; no additional high-signal deterministic rule was found. https://runterrascan.io/docs/policies/ |
| kube-linter | `access-to-secrets`, `wildcard-in-rules`, `unsafe-proc-mount`, `host-ipc`/`host-pid`/`host-network`, `privileged-container`, `privilege-escalation-container`, `docker-sock`. | CFG-038/039 add the two gaps not already covered by CFG-012/018/029; the rest are intentionally not duplicated. https://github.com/stackrox/kube-linter/blob/main/docs/generated/checks.md |
| kubesec | Risk scoring for Kubernetes manifests: privileged, host namespaces, hostPath, capabilities, runAsNonRoot, allowPrivilegeEscalation. | Confirms the existing CFG-012/018 coverage and motivates the NET_ADMIN/ALL capability rule (CFG-033). https://kubesec.io/ |
| dockle | CIS Docker image checks: non-root user, latest tag, secrets in image, healthcheck. | Mostly image-build concerns already covered by CFG-001/002/005; not duplicated. https://github.com/goodwithtech/dockle |
| zizmor | GitHub Actions audits: `dangerous-triggers`, `template-injection`, `unpinned-uses`, `excessive-permissions`, `artipacked`, `dangerous-checkout`. | CI-018/019 add `workflow_run` and `github-script`, which CI-002/003 do not cover; CI-001/004 already cover pinning/permissions. https://docs.zizmor.sh/audits/ |
| GitLab Runner security docs | Privileged-mode risks, host PID namespace, dind TLS, `tls_verify`. | CI-021/022 implement the two explicit, high-signal findings; `tls_verify = false` is left for a later config.toml wave. https://docs.gitlab.com/runner/security/ |

---

## Docker and Compose

### VGL-CFG-030 — Docker CLI shares a host network, PID, IPC or UTS namespace

- Severity: high
- Languages/files: `*.sh`, `*.bash`, `Makefile`, `Taskfile.yml`, `justfile`, CI YAML, any
  file containing a `docker run` / `docker create` / `docker compose run` / `podman run`
  invocation.
- Detection: join backslash-continued lines into a logical command (up to 20 lines). If the
  command starts with `docker run`, `docker create`, `docker container run`,
  `docker compose run`, `podman run` or `podman create`, flag any flag matching
  `--network[= ]host`, `--net[= ]host`, `--pid[= ]host`, `--ipc[= ]host` or
  `--uts[= ]host`. Emit one finding per distinct flag, evidence = the flag and command.
- Why high-signal: each flag removes one namespace boundary. `--network host` exposes every
  host port and bypasses Docker's port publishing and host-firewall interaction;
  `--pid host` lets the container see and signal host processes; `--ipc host` shares
  SysV/POSIX IPC; `--uts host` shares hostname/domain. These are explicit runtime flags,
  not defaults, and are called out by CIS Docker 5.10 and 5.16–5.18.
- False-positive guard: only executable contexts (shell/Makefile/CI/`other` scripts); skip
  `docs/`, `*.md`, `examples/` and comment lines; require an actual `docker`/`podman`
  invocation; skip `docker build` (no runtime namespace); skip Compose files
  (`network_mode: host` is `VGL-CFG-008`); skip `--pid=container:...` and
  `--network=container:...` (not host).
- Vulnerable fixture:
  ```sh
  docker run --rm --pid=host --network=host alpine ps aux
  ```
- Safe fixture:
  ```sh
  docker run --rm --pid=container:sidecar --network=app-net alpine ps aux
  ```
- CWE/OWASP: CWE-250, CWE-668; OWASP A05:2021; OWASP Docker Top 10 D04/D09.
- Sources: https://docs.docker.com/reference/cli/docker/container/run/ ·
  https://www.cisecurity.org/benchmark/docker (5.10, 5.16–5.18) ·
  https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
- Priority: P1

### VGL-CFG-031 — Docker Compose shares host PID, IPC or UTS namespace

- Severity: high
- Languages/files: `docker-compose*.yml`, `compose*.yml`, `compose*.yaml` (reuse
  `pbIsCompose`).
- Detection: in a Compose file, flag a line matching
  `^\s*(pid|ipc|uts)\s*:\s*["']?host["']?\s*(?:#.*)?$`. Do not include `network_mode` here;
  `VGL-CFG-008` owns Compose host networking.
- Why high-signal: Compose long syntax is explicit and has no legitimate default use in an
  application stack. Sharing the host PID namespace exposes every host process; sharing IPC
  exposes shared memory/queues; sharing UTS lets the container change the hostname.
- False-positive guard: skip comments and docs; require `pbIsCompose`; skip
  `pid: "service:foo"`, `ipc: "service:foo"`, `pid: "container:foo"`; skip `network_mode`.
- Vulnerable fixture:
  ```yaml
  services:
    app:
      image: alpine
      pid: host
      ipc: host
  ```
- Safe fixture:
  ```yaml
  services:
    app:
      image: alpine
      pid: "service:sidecar"
  ```
- CWE/OWASP: CWE-250, CWE-668; OWASP A05:2021.
- Sources: https://docs.docker.com/reference/compose-file/services/ ·
  https://www.cisecurity.org/benchmark/docker (5.16–5.18)
- Priority: P2

### VGL-CFG-032 — Container disables seccomp or AppArmor confinement

- Severity: high
- Languages/files: Compose, shell/Makefile, Kubernetes YAML.
- Detection:
  - Compose: `security_opt:` item equal to `seccomp:unconfined`, `seccomp=unconfined`,
    `apparmor:unconfined` or `apparmor=unconfined`.
  - CLI: `--security-opt[= ]seccomp=unconfined` or
    `--security-opt[= ]apparmor=unconfined`.
  - Kubernetes: `seccompProfile:` with `type: Unconfined` (next line or inline map), or
    `appArmorProfile:` with `type: Unconfined`.
- Why high-signal: seccomp and AppArmor are the runtime's last confinement layers. The
  literal `unconfined` value explicitly turns them off, which is a deliberate weakening and
  a prerequisite for many container escapes. CIS Docker 5.1/5.2/5.28/5.29 and the
  Kubernetes Restricted Pod Security Standard require a default/runtime profile.
- False-positive guard: skip comments/docs; require the literal `unconfined` value; do not
  flag `seccompProfile: RuntimeDefault`, `Localhost`, `appArmorProfile: RuntimeDefault`, or
  `security_opt: no-new-privileges` (that is hardening); only Kubernetes manifests for the
  `seccompProfile`/`appArmorProfile` branch.
- Vulnerable fixture:
  ```yaml
  services:
    app:
      image: alpine
      security_opt:
        - seccomp:unconfined
  ```
  ```yaml
  securityContext:
    seccompProfile:
      type: Unconfined
  ```
- Safe fixture:
  ```yaml
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  ```
- CWE/OWASP: CWE-693, CWE-250; OWASP A05:2021.
- Sources: https://docs.docker.com/engine/security/seccomp/ ·
  https://docs.docker.com/engine/security/apparmor/ ·
  https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Priority: P1

### VGL-CFG-033 — Container grants a dangerous Linux capability

- Severity: high
- Languages/files: Compose, shell/Makefile, Kubernetes YAML.
- Detection: flag an **add/grant** context (`cap_add`, `capabilities.add`, `--cap-add`)
  whose value is one of `ALL`, `NET_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`,
  `DAC_READ_SEARCH`, `SYS_RAWIO`, `SYS_BOOT`, `BPF`, `PERFMON` (case-insensitive,
  optional `CAP_` prefix). Accept list and scalar forms:
  `cap_add: [NET_ADMIN]`, `- NET_ADMIN`, `--cap-add=NET_ADMIN`,
  `--cap-add NET_ADMIN`, `capabilities: { add: ["NET_ADMIN"] }`.
- Why high-signal: these capabilities are explicit privilege grants with well-known escape
  primitives — `NET_ADMIN` manipulates interfaces/firewall/ARP, `SYS_PTRACE` injects into
  processes, `SYS_MODULE` loads kernel modules, `DAC_READ_SEARCH` bypasses file permission
  checks, `SYS_RAWIO` performs raw I/O, `ALL` grants everything. `SYS_ADMIN` is deliberately
  excluded because `VGL-CFG-010` already owns it.
- False-positive guard: skip comments/docs; require an add/grant context, never a
  `cap_drop`/`drop:` list; do not flag `NET_BIND_SERVICE`, `CHOWN`, `SETUID`, `SETGID`
  (common and low-risk); exclude `SYS_ADMIN` (duplicate of `VGL-CFG-010`); skip
  `--cap-add` in documentation examples.
- Vulnerable fixture:
  ```yaml
  cap_add:
    - NET_ADMIN
  ```
- Safe fixture:
  ```yaml
  cap_drop:
    - ALL
  cap_add:
    - NET_BIND_SERVICE
  ```
- CWE/OWASP: CWE-250, CWE-269; OWASP A05:2021.
- Sources: https://docs.docker.com/reference/cli/docker/container/run/#runtime-privilege-and-linux-capabilities ·
  https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html (Rule #3) ·
  https://www.cisecurity.org/benchmark/docker (5.3–5.4)
- Priority: P1

### VGL-CFG-034 — Container mounts a raw host device

- Severity: high
- Languages/files: Compose, shell/Makefile.
- Detection: in a `devices:` list or a `--device[= ]` flag, flag a host device matching
  `/dev/sd*`, `/dev/nvme*`, `/dev/vd*`, `/dev/xvd*`, `/dev/mmcblk*`, `/dev/dm-*`,
  `/dev/mem`, `/dev/kmem`, `/dev/port`, `/dev/kmsg`. Handle `host:container[:perms]`.
- Why high-signal: a raw block device lets the container read and write host disks
  (`/dev/sda`, `/dev/nvme0n1`); `/dev/mem` and `/dev/kmem` expose physical/kernel memory;
  `/dev/port` allows arbitrary I/O port access. This is a direct host escape, not a normal
  application requirement. CIS Docker 5.21 explicitly says host devices should not be
  shared.
- False-positive guard: skip comments/docs; allow common hardware passthrough that is not a
  host escape: `/dev/dri`, `/dev/fuse`, `/dev/snd`, `/dev/video*`, `/dev/tty*`,
  `/dev/bus/usb` (still privileged but not the high-signal disk/memory set); require a
  `devices:`/`--device` context; skip `--device-cgroup-rule` (different control).
- Vulnerable fixture:
  ```yaml
  services:
    app:
      devices:
        - "/dev/sda:/dev/sda"
  ```
- Safe fixture:
  ```yaml
  services:
    app:
      devices:
        - "/dev/dri:/dev/dri"
  ```
- CWE/OWASP: CWE-250, CWE-668; OWASP A05:2021.
- Sources: https://www.cisecurity.org/benchmark/docker (5.21) ·
  https://docs.docker.com/reference/cli/docker/container/run/#device ·
  https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
- Priority: P2

### VGL-CFG-035 — Container mounts the host root filesystem

- Severity: high
- Languages/files: Compose, shell/Makefile.
- Detection: flag a bind mount whose host source is exactly `/`:
  - Compose short syntax: `- "/:/host"`, `- "/:/host:ro"`, `- /:/data`.
  - Compose long syntax: `source: /` inside a `volumes:` entry.
  - CLI: `-v /:/host`, `--volume /:/host`, `--volume=/:/host`,
    `--mount type=bind,source=/,target=/host`.
- Why high-signal: mounting `/` gives the container the entire host filesystem, including
  `/etc/shadow`, SSH keys, application secrets and the Docker socket. It is a one-line host
  takeover and has no place in an application compose file.
- False-positive guard: require the source to be exactly `/` (not `/home`, `/srv`,
  `/var/run`); skip comments/docs; skip `- /var/run/docker.sock` (owned by `VGL-CFG-009`);
  read-only root mounts are still flagged because they expose secrets; skip `tmpfs`.
- Vulnerable fixture:
  ```yaml
  volumes:
    - "/:/host"
  ```
- Safe fixture:
  ```yaml
  volumes:
    - "/srv/app:/app:ro"
  ```
- CWE/OWASP: CWE-250, CWE-668; OWASP A05:2021.
- Sources: https://www.cisecurity.org/benchmark/docker (5.6) ·
  https://docs.docker.com/engine/storage/bind-mounts/ ·
  https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html (Rule #8)
- Priority: P2

### VGL-CFG-036 — Docker CLI runs a container privileged

- Severity: high
- Languages/files: `*.sh`, `*.bash`, `Makefile`, `Taskfile.yml`, `justfile`, CI YAML.
- Detection: join backslash-continued lines; if a logical command starts with
  `docker run`, `docker create`, `docker container run`, `docker compose run`,
  `podman run` or `podman create`, flag a `--privileged` flag (`--privileged` or
  `--privileged=true`). Exclude Compose file `privileged: true` (`VGL-CFG-007`).
- Why high-signal: `--privileged` gives the container all Linux capabilities, access to all
  host devices, and a nearly unconfined LSM profile — Docker's own docs say it gives nearly
  the same host access as a process outside a container. It is a deliberate flag and a
  well-known escape primitive.
- False-positive guard: only executable contexts; skip `docs/`, `*.md`, `examples/`;
  skip comment lines; require a runtime invocation (`docker build` has no
  `--privileged`); do not flag Compose YAML; do not flag `--privileged` inside a quoted
  `echo`/documentation string.
- Vulnerable fixture:
  ```sh
  docker run --privileged -v /:/host alpine
  ```
- Safe fixture:
  ```sh
  docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE alpine
  ```
- CWE/OWASP: CWE-250; OWASP A05:2021.
- Sources: https://docs.docker.com/reference/cli/docker/container/run/#privileged ·
  https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html (Rule #3) ·
  https://www.cisecurity.org/benchmark/docker (5.5)
- Priority: P0

### VGL-CFG-037 — Compose publishes a datastore or admin port on all interfaces

- Severity: medium
- Languages/files: Compose.
- Detection: parse a `ports:` short-syntax entry as
  `[host_ip:]host_port:container_port`. Flag when the container port is in
  `{22, 2375, 2376, 3306, 5432, 6379, 9200, 9300, 11211, 27017, 27018, 8500, 8200}` and
  the host IP is absent or `0.0.0.0`/`::`. Also flag long syntax with
  `published: <port>` when `host_ip` is absent or `0.0.0.0`. Skip `expose:`.
- Why high-signal: Docker publishes on all interfaces by default and inserts iptables
  rules ahead of host firewall rules, so `"5432:5432"` can expose a database to the network
  even when UFW is enabled. Binding to `127.0.0.1` is the documented mitigation. This is a
  concrete, fixable exposure, not a generic "open port" complaint.
- False-positive guard: skip `127.0.0.1`, `::1`, `localhost` host IPs; skip ports outside
  the datastore/admin set; skip `expose:`; skip `isTestPath` and `pbDocsPath`; require a
  literal numeric mapping (do not flag variables).
- Vulnerable fixture:
  ```yaml
  services:
    db:
      image: postgres:16
      ports:
        - "5432:5432"
  ```
- Safe fixture:
  ```yaml
  services:
    db:
      image: postgres:16
      ports:
        - "127.0.0.1:5432:5432"
  ```
- CWE/OWASP: CWE-284, CWE-668; OWASP A05:2021.
- Sources: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
  (Rule #5a) · https://www.cisecurity.org/benchmark/docker (5.14) ·
  https://docs.docker.com/engine/network/packet-filtering-firewalls/
- Priority: P2

---

## Kubernetes

### VGL-CFG-038 — Kubernetes RBAC grants wildcard access to secrets

- Severity: high
- Languages/files: Kubernetes YAML with `kind: Role` or `kind: ClusterRole`.
- Detection: bounded block parse. Inside a `rules:` item, if `resources:` contains
  `secrets` or `*`, and `verbs:` contains `*` or any of `get`, `list`, `watch`, `create`,
  `update`, `patch`, `delete`, flag the `verbs:` line (or the `resources:` line when
  `verbs` is inline). If the same item has a non-empty `resourceNames:` list, skip.
  Pseudo-code: for each `kind: Role`/`ClusterRole` document, split `rules:` into list
  items at the same indent; for each item collect `resources`, `verbs` and `resourceNames`;
  flag when resources contain `secrets` or `*`, verbs contain `*` or `get`/`list`/`watch`/
  `create`/`update`/`patch`/`delete`, and `resourceNames` is empty.
- Why high-signal: read access to every secret in a namespace/cluster exposes database
  passwords, API keys and service-account tokens; write access allows creating a token for
  a more privileged service account. CIS Kubernetes 5.1.2/5.1.3 and kube-linter
  `access-to-secrets`/`wildcard-in-rules` treat this as a direct privilege-escalation path.
- False-positive guard: require `kind: Role`/`ClusterRole`; skip comments/docs; skip
  `resourceNames`-scoped rules (e.g. `get` on one named secret); skip `verbs: ["get"]` with
  a specific `resourceNames`; do not flag a `RoleBinding`/`ClusterRoleBinding` (different
  object; `VGL-CFG-029` handles `cluster-admin`).
- Vulnerable fixture:
  ```yaml
  kind: ClusterRole
  rules:
    - apiGroups: [""]
      resources: ["secrets"]
      verbs: ["*"]
  ```
- Safe fixture:
  ```yaml
  kind: Role
  rules:
    - apiGroups: [""]
      resources: ["secrets"]
      resourceNames: ["app-db"]
      verbs: ["get"]
  ```
- CWE/OWASP: CWE-269, CWE-732; OWASP A01:2021.
- Sources: https://kubernetes.io/docs/concepts/security/rbac-good-practices/ ·
  https://github.com/stackrox/kube-linter/blob/main/docs/generated/checks.md
  (`access-to-secrets`, `wildcard-in-rules`) ·
  https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html ·
  https://www.cisecurity.org/benchmark/kubernetes (5.1.2–5.1.3)
- Priority: P2

### VGL-CFG-039 — Kubernetes container unmasks /proc

- Severity: medium
- Languages/files: Kubernetes YAML.
- Detection: flag `procMount: Unmasked` (case-insensitive key, value exactly `Unmasked`)
  inside a `securityContext`.
- Why high-signal: the default `/proc` mask hides kernel pointers and sensitive host
  information; `Unmasked` removes that protection and is a known container-hardening
  bypass. The Kubernetes Baseline Pod Security Standard forbids it, and kube-linter has a
  dedicated `unsafe-proc-mount` check.
- False-positive guard: skip comments/docs; only Kubernetes manifests; `procMount: Default`
  is safe; absence is safe (do not flag missing `procMount`).
- Vulnerable fixture:
  ```yaml
  securityContext:
    procMount: Unmasked
  ```
- Safe fixture:
  ```yaml
  securityContext:
    procMount: Default
  ```
- CWE/OWASP: CWE-668, CWE-250; OWASP A05:2021.
- Sources: https://github.com/stackrox/kube-linter/blob/main/docs/generated/checks.md
  (`unsafe-proc-mount`) ·
  https://kubernetes.io/docs/concepts/security/pod-security-standards/ ·
  https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
- Priority: P2

---

## Terraform and CloudFormation

### VGL-CFG-040 — IAM policy grants full administrative access

- Severity: critical
- Languages/files: Terraform `.tf`/`.tfvars`, CloudFormation YAML/JSON.
- Detection:
  - Terraform: file contains one of `aws_iam_policy`, `aws_iam_role_policy`,
    `aws_iam_user_policy`, `aws_iam_group_policy`, `aws_iam_policy_document`. Within a
    `statement { ... }` block (or a ±15-line window when the policy is a `jsonencode`
    object), require both an action wildcard (`Action = "*"`, `actions = ["*"]`,
    `"Action": "*"`, `"actions": ["*"]`) and a resource wildcard (`Resource = "*"`,
    `resources = ["*"]`, `"Resource": "*"`, `"resources": ["*"]`). Flag the action line.
  - CloudFormation: file contains `AWS::IAM::Policy`, `AWS::IAM::ManagedPolicy`,
    `AWS::IAM::Role` or `AWS::IAM::User`/`AWS::IAM::Group` with an inline policy. Within a
    `PolicyDocument`/`Statement` item (±15 lines), require `Action: "*"` (or `["*"]`) and
    `Resource: "*"` (or `["*"]`). Flag the action line.
- Why high-signal: `Action: "*"` plus `Resource: "*"` is full administrator access — every
  API action on every resource, including IAM policy changes, S3 reads, and CloudTrail
  deletion. There is no least-privilege use for an unconditional full-admin policy in an
  application stack; break-glass admin belongs in a separate, audited role.
- False-positive guard: skip `Effect: "Deny"` / `effect = "Deny"` statements (deny-admin is
  safe); skip `NotAction`/`NotResource` (different semantics); skip a policy used as a
  `permissions_boundary` (a permissive boundary does not grant access — skip only when the
  document is referenced by `permissions_boundary` and is not attached to a principal);
  require both wildcards in the same statement; skip comments/docs; skip `count = 0`.
- Vulnerable fixture:
  ```hcl
  resource "aws_iam_policy" "admin" {
    policy = jsonencode({
      Statement = [{
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }]
    })
  }
  ```
- Safe fixture:
  ```hcl
  resource "aws_iam_policy" "read" {
    policy = jsonencode({
      Statement = [{
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "arn:aws:s3:::app-bucket/*"
      }]
    })
  }
  ```
- CWE/OWASP: CWE-269, CWE-732; OWASP A01:2021.
- Sources: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege ·
  https://aquasecurity.github.io/tfsec/latest/checks/aws/iam/no-policy-wildcards/ ·
  https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html ·
  https://www.checkov.io/5.Policy%20Index/terraform.html
- Priority: P0

### VGL-CFG-041 — Security group allows all traffic from the internet

- Severity: high
- Languages/files: Terraform, CloudFormation.
- Detection:
  - Terraform: in an ingress block of `aws_security_group`, or in
    `aws_vpc_security_group_ingress_rule`, require a literal public CIDR
    (`0.0.0.0/0` or `::/0`) and either `protocol = "-1"`/`ip_protocol = "-1"` (all
    protocols) or `from_port = 0` with `to_port = 65535` (all TCP/UDP ports). Flag the CIDR
    line.
  - CloudFormation: in `AWS::EC2::SecurityGroup` `SecurityGroupIngress` or
    `AWS::EC2::SecurityGroupIngress`, require `CidrIp: 0.0.0.0/0` or `CidrIpv6: ::/0`
    and either `IpProtocol: -1` or `FromPort: 0` with `ToPort: 65535`.
- Why high-signal: opening every protocol/port to the internet exposes SSH, RDP, databases
  and internal admin services at once. `VGL-CFG-013`/`VGL-CFG-027` only catch specific
  sensitive ports; this closes the "all traffic" gap.
- False-positive guard: only ingress (skip `type = "egress"` and
  `AWS::EC2::SecurityGroupEgress`); require a literal public CIDR (skip `var.`/`data.`);
  skip `protocol = "-1"` with a private CIDR; skip a normal 80/443 TCP rule; skip a
  non-`-1` protocol unless the port range is 0–65535; skip comments/docs.
- Vulnerable fixture:
  ```hcl
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ```
- Safe fixture:
  ```hcl
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ```
- CWE/OWASP: CWE-284, CWE-668; OWASP A01:2021.
- Sources: https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html ·
  https://aquasecurity.github.io/tfsec/latest/checks/aws/vpc/no-excessive-port-access/ ·
  https://aquasecurity.github.io/tfsec/latest/checks/aws/ec2/no-public-ingress-sgr/
- Priority: P0

### VGL-CFG-042 — S3 public access block is explicitly disabled

- Severity: high
- Languages/files: Terraform, CloudFormation.
- Detection:
  - Terraform: in `aws_s3_bucket_public_access_block` or
    `aws_s3_account_public_access_block`, flag each of `block_public_acls = false`,
    `block_public_policy = false`, `ignore_public_acls = false`,
    `restrict_public_buckets = false`. Skip the resource when `count = 0`.
  - CloudFormation: in `AWS::S3::Bucket` `PublicAccessBlockConfiguration`, flag each of
    `BlockPublicAcls: false`, `BlockPublicPolicy: false`, `IgnorePublicAcls: false`,
    `RestrictPublicBuckets: false`. (There is no account-level
    `AWS::S3::AccountPublicAccessBlock` CloudFormation resource; account-level BPA is
    configured outside CloudFormation.)
- Why high-signal: Block Public Access is the account/bucket guardrail that overrides
  public ACLs and bucket policies. Setting any of the four flags to `false` re-opens a
  public path that the ACL-only `VGL-CFG-014` check does not see. AWS recommends all four
  settings enabled for every bucket.
- False-positive guard: only explicit `false`; do not flag a missing block (account-level
  settings may apply and absence is noisy); skip `count = 0`; skip `true`; skip
  comments/docs.
- Vulnerable fixture:
  ```hcl
  resource "aws_s3_bucket_public_access_block" "b" {
    block_public_acls   = false
    block_public_policy = true
  }
  ```
- Safe fixture:
  ```hcl
  resource "aws_s3_bucket_public_access_block" "b" {
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
  ```
- CWE/OWASP: CWE-284, CWE-732; OWASP A01:2021.
- Sources: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html ·
  https://aquasecurity.github.io/tfsec/latest/checks/aws/s3/block-public-acls/ ·
  https://www.checkov.io/5.Policy%20Index/terraform.html (CKV_AWS_53–56)
- Priority: P0

### VGL-CFG-043 — CloudTrail logging is explicitly disabled

- Severity: high
- Languages/files: Terraform, CloudFormation.
- Detection:
  - Terraform: `aws_cloudtrail` with `enable_logging = false`; skip `count = 0`.
  - CloudFormation: `AWS::CloudTrail::Trail` with `EnableLogging: false`.
- Why high-signal: CloudTrail is the AWS API audit log. Disabling it removes the record of
  who created/deleted resources and accessed secrets, defeating incident response and
  forensic reconstruction. CIS AWS Foundations 3.1 requires CloudTrail enabled.
- False-positive guard: only explicit `false`; do not flag a missing `enable_logging`
  (default is true); skip `count = 0`; skip comments/docs; do not flag
  `is_multi_region_trail = false` (that is a separate, noisier decision).
- Vulnerable fixture:
  ```hcl
  resource "aws_cloudtrail" "trail" {
    enable_logging = false
  }
  ```
- Safe fixture:
  ```hcl
  resource "aws_cloudtrail" "trail" {
    enable_logging = true
  }
  ```
- CWE/OWASP: CWE-778, CWE-693; OWASP A09:2021.
- Sources: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html ·
  https://www.cisecurity.org/benchmark/amazon_web_services (3.1) ·
  https://www.checkov.io/5.Policy%20Index/terraform.html
- Priority: P2

### VGL-CFG-044 — EC2 instance metadata allows IMDSv1

- Severity: high
- Languages/files: Terraform, CloudFormation.
- Detection:
  - Terraform: `aws_instance`, `aws_launch_template` or `aws_launch_configuration` with
    `metadata_options { http_tokens = "optional" }`. Skip when `http_endpoint = "disabled"`
    is in the same block.
  - CloudFormation: `AWS::EC2::Instance` `MetadataOptions.HttpTokens: optional`, or
    `AWS::EC2::LaunchTemplate` `LaunchTemplateData.MetadataOptions.HttpTokens: optional`.
- Why high-signal: IMDSv1 accepts unauthenticated GET requests, so any SSRF, open proxy or
  misconfigured workload on the instance can read the instance role's temporary
  credentials from `169.254.169.254`. IMDSv2 requires a PUT session token and is the
  standard mitigation; tfsec has a dedicated `aws-ec2-enforce-http-token-imds` check.
- False-positive guard: only explicit `optional`; do not flag a missing `metadata_options`
  (the default is optional, but flagging absence is noisy and account defaults vary); skip
  `http_endpoint = "disabled"`; skip comments/docs.
- Vulnerable fixture:
  ```hcl
  metadata_options {
    http_tokens = "optional"
  }
  ```
- Safe fixture:
  ```hcl
  metadata_options {
    http_tokens = "required"
  }
  ```
- CWE/OWASP: CWE-918, CWE-522; OWASP A10:2021/A07:2021.
- Sources: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html ·
  https://aquasecurity.github.io/tfsec/latest/checks/aws/ec2/enforce-http-token-imds/ ·
  https://www.cisecurity.org/benchmark/amazon_web_services
- Priority: P0

---

## nginx

### VGL-CFG-045 — nginx disables upstream TLS certificate verification

- Severity: high
- Languages/files: `nginx.conf`, `*.conf` under `nginx/` or `sites-available/`, and any
  `.conf` containing nginx markers (`server {`, `http {`, `location `, `proxy_pass`).
- Detection: flag `^\s*proxy_ssl_verify\s+off\s*;\s*(?:#.*)?$` (case-insensitive, optional
  quotes).
- Why high-signal: `proxy_ssl_verify off` makes nginx accept any certificate from the
  upstream, so a MITM between nginx and the backend can terminate TLS and read or modify
  proxied traffic. The directive default is already `off`, but an explicit `off` is a
  deliberate downgrade and an actionable finding; absence is not flagged to avoid noise on
  internal HTTP upstreams.
- False-positive guard: skip comments/docs; skip `proxy_ssl_verify on;`; only nginx
  configuration files (reuse `pcIsNginxConf`); do not flag the string in a `map`, comment
  or documentation block.
- Vulnerable fixture:
  ```nginx
  location /api/ {
      proxy_pass https://backend;
      proxy_ssl_verify off;
  }
  ```
- Safe fixture:
  ```nginx
  location /api/ {
      proxy_pass https://backend;
      proxy_ssl_verify on;
      proxy_ssl_trusted_certificate /etc/ssl/certs/ca.pem;
  }
  ```
- CWE/OWASP: CWE-295, CWE-319; OWASP A02:2021.
- Sources: https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_verify ·
  https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
- Priority: P1

---

## GitHub Actions

### VGL-CI-018 — Privileged workflow checks out untrusted PR code

- Severity: critical
- Languages/files: `.github/workflows/*.yml`, `.github/workflows/*.yaml`.
- Detection:
  - If `workflow_run` is in the `on:` block, flag a checkout step whose `ref:` or
    `repository:` contains one of: `github.event.workflow_run.head_sha`, `head_branch`,
    `github.event.workflow_run.head_repository`,
    `github.event.workflow_run.pull_requests[0].head.sha`,
    `github.event.workflow_run.pull_requests[0].head.ref`.
  - If `workflow_run` or `pull_request_target` is in the `on:` block, flag
    `allow-unsafe-pr-checkout: true` on any checkout step (high confidence).
- Why high-signal: `workflow_run` runs in the base repository and can run with a
  write-scoped `GITHUB_TOKEN` and access to repository secrets. Checking out the triggering
  run's head (which can be a fork PR) and then running any build/test step executes attacker
  code in that privileged context. GitHub's own `pull_request_target` guide explicitly says
  a `workflow_run` workflow that fetches and runs a fork's PR code is vulnerable in the same
  way; zizmor's `dangerous-triggers` audit lists `workflow_run` as a dangerous trigger.
- False-positive guard: skip workflows without `actions/checkout`; skip a literal SHA
  (`ref: 0123...`); skip a plain `actions/checkout` with no `ref`/`repository` (defaults to
  the base repo); skip artifact-only workflows that never check out. Note: `actions/checkout`
  v7+ blocks fork-originated PR checkouts by default unless
  `allow-unsafe-pr-checkout: true`; report that opt-in with high confidence, and report
  other PR-head refs with medium confidence when the checkout version is unknown (the
  engine cannot resolve a SHA pin to a version).
- Vulnerable fixture:
  ```yaml
  on:
    workflow_run:
      workflows: [CI]
      types: [completed]
  jobs:
    build:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
          with:
            ref: ${{ github.event.workflow_run.head_sha }}
        - run: npm ci && npm test
  ```
- Safe fixture:
  ```yaml
  on:
    workflow_run:
      workflows: [CI]
      types: [completed]
  jobs:
    report:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4   # base repo, default ref
        - run: echo "read the report as data only"
  ```
- CWE/OWASP: CWE-829, CWE-94; OWASP A08:2021; OWASP CICD-SEC-4 (PPE).
- Sources: https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target ·
  https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions ·
  https://docs.zizmor.sh/audits/ (`dangerous-triggers`) ·
  https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html ·
  https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html
- Priority: P0

### VGL-CI-019 — Untrusted event data interpolated into actions/github-script

- Severity: high
- Languages/files: `.github/workflows/*.yml|yaml`, composite `action.yml`/`action.yaml`.
- Detection: require `uses: actions/github-script@`. Inside its `script:` block (inline or
  `|`/`>`), flag a line containing `${{ ... }}` with any of
  `github.event.pull_request.(title|body|head.ref|head.label|user.login)`,
  `github.event.issue.(title|body|user.login)`,
  `github.event.comment.body`,
  `github.event.discussion.(title|body)`,
  `github.event.review.body`, `github.head_ref`, or
  `github.event.workflow_run.head_branch`.
- Why high-signal: GitHub expands `${{ }}` in the workflow file **before** the JavaScript
  engine runs, so a PR title like `";require('child_process').execSync('...')//` becomes
  executable JS with the workflow's token and any secrets available to the step.
  `VGL-CI-003` only covers `run:`; `github-script` is a separate code-execution sink and is
  not detected today.
- False-positive guard: only the `script:` block of `actions/github-script`; skip
  `context.payload.*` / `github.context.payload.*` (runtime values, not source
  interpolation); skip values passed through `env:` and read as `process.env.*`; skip
  comments; do not flag `${{ secrets.* }}` or `${{ github.repository }}` (trusted values).
- Vulnerable fixture:
  ```yaml
  - uses: actions/github-script@v7
    with:
      script: |
        const title = "${{ github.event.pull_request.title }}";
        core.info(title);
  ```
- Safe fixture:
  ```yaml
  - uses: actions/github-script@v7
    env:
      TITLE: ${{ github.event.pull_request.title }}
    with:
      script: |
        const title = process.env.TITLE;
        core.info(title);
  ```
- CWE/OWASP: CWE-94, CWE-78; OWASP A03:2021; OWASP CICD-SEC-4.
- Sources: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions ·
  https://docs.zizmor.sh/audits/ (`template-injection`) ·
  https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html
- Priority: P1

### VGL-CI-020 — CI job container uses privileged Docker options

- Severity: high
- Languages/files: `.github/workflows/*.yml|yaml`.
- Detection: within `jobs.<id>.container.options` or
  `jobs.<id>.services.<id>.options`, flag a string containing `--privileged`,
  `--network[= ]host`, `--pid[= ]host`, or `--ipc[= ]host`.
- Why high-signal: these options run the job's container with host privileges or
  namespaces, so any code in the job — including code checked out from a PR — can escape
  the container. `VGL-CFG-007` only covers Compose, `VGL-CFG-036` covers `docker run`, and
  this is the GitHub Actions `container.options` sink that neither catches.
- False-positive guard: only `container.options`/`services.*.options`; skip `docker run` in
  `run:` (owned by `VGL-CFG-030`/`VGL-CFG-036`); skip `--cap-add` flags entirely (owned by
  `VGL-CFG-010`/`VGL-CFG-033`) and `-v /var/run/docker.sock` (owned by `VGL-CFG-009`);
  skip comments.
- Vulnerable fixture:
  ```yaml
  jobs:
    build:
      runs-on: ubuntu-latest
      container:
        image: node:20
        options: --privileged
  ```
- Safe fixture:
  ```yaml
  jobs:
    build:
      runs-on: ubuntu-latest
      container:
        image: node:20
        options: --cap-drop=ALL --security-opt=no-new-privileges
  ```
- CWE/OWASP: CWE-250, CWE-668; OWASP A05:2021; OWASP CICD-SEC-7.
- Sources: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions ·
  https://docs.docker.com/reference/cli/docker/container/run/#privileged ·
  https://owasp.org/www-project-top-10-ci-cd-security-risks/
- Priority: P2

---

## GitLab CI

### VGL-CI-021 — GitLab Runner runs jobs in privileged mode

- Severity: high
- Languages/files: GitLab Runner `config.toml`, and any `*.toml` containing `[[runners]]`.
- Detection: require `[[runners]]` and a `[runners.docker]` or `[runners.kubernetes]`
  section; flag `privileged = true` (case-insensitive, optional whitespace).
- Why high-signal: privileged mode gives every CI job all host capabilities and device
  access. Any user who can push a branch can run a job that mounts the host disk, loads a
  kernel module, or escapes the container and compromises the runner host. GitLab's own
  runner security guide says it is **not advised** to run containers in privileged mode.
- False-positive guard: skip `privileged = false`; skip comments/docs; require a
  `[[runners]]` config file; do not flag a `values.yaml` or a generic TOML file; skip a
  commented `# privileged = true`.
- Vulnerable fixture:
  ```toml
  [[runners]]
    [runners.docker]
      privileged = true
  ```
- Safe fixture:
  ```toml
  [[runners]]
    [runners.docker]
      privileged = false
  ```
- CWE/OWASP: CWE-250; OWASP A05:2021; OWASP CICD-SEC-7.
- Sources: https://docs.gitlab.com/runner/security/ ·
  https://docs.gitlab.com/ci/docker/using_docker_build/ ·
  https://owasp.org/www-project-top-10-ci-cd-security-risks/
- Priority: P1

### VGL-CI-022 — GitLab CI disables Docker-in-Docker TLS

- Severity: high
- Languages/files: `.gitlab-ci.yml`.
- Detection: require a `docker:dind` service or a `DOCKER_HOST` variable. Flag any of:
  - `DOCKER_TLS_CERTDIR: ""` / `''` (empty value disables TLS);
  - `DOCKER_HOST: tcp://...:2375` (plain TCP port);
  - `DOCKER_TLS_VERIFY: ""` or `"0"`;
  - a `docker:dind` service with `command: ["--tls=false"]`.
- Why high-signal: TCP 2375 is the unauthenticated Docker API. Any process on the CI
  network can create privileged containers, mount host paths, or read the daemon's
  credentials. GitLab enables dind TLS by default; explicitly clearing
  `DOCKER_TLS_CERTDIR` or using port 2375 turns that protection off.
- False-positive guard: skip `:2376` (TLS port); skip `DOCKER_TLS_CERTDIR: "/certs"`;
  skip comments; require a dind/`DOCKER_HOST` context so a generic variable in an
  unrelated job is not flagged; only `.gitlab-ci.yml`.
- Vulnerable fixture:
  ```yaml
  variables:
    DOCKER_HOST: tcp://docker:2375
    DOCKER_TLS_CERTDIR: ""
  services:
    - docker:dind
  ```
- Safe fixture:
  ```yaml
  variables:
    DOCKER_HOST: tcp://docker:2376
    DOCKER_TLS_CERTDIR: "/certs"
    DOCKER_TLS_VERIFY: "1"
  services:
    - docker:dind
  ```
- CWE/OWASP: CWE-319, CWE-306; OWASP A02:2021/A07:2021; OWASP CICD-SEC-7.
- Sources: https://docs.gitlab.com/ci/docker/docker_in_docker/ ·
  https://docs.gitlab.com/ci/variables/ ·
  https://owasp.org/www-project-top-10-ci-cd-security-risks/
- Priority: P2

---

## Rejected

Rules considered but not proposed, with the reason:

| Candidate | Reason |
|---|---|
| Dockerfile runs as root | Already `VGL-CFG-001`; generic root-user findings are noisy and the brief rejects them. |
| Docker base image uses `:latest` | Already `VGL-CFG-002`/`011`/`019`; generic latest-tag checks are noisy. |
| Dockerfile `EXPOSE 22` | SSH inside a container can be intentional (sidecar/bastion images); low signal. |
| Dockerfile uses `sudo` | Style/build smell; root execution is already covered by `VGL-CFG-001`. |
| Dockerfile package versions unpinned | Reproducibility, not a security vulnerability; noisy. |
| Compose `read_only: false` | Low impact and usually explicit for a reason; noisy. |
| Compose missing `no-new-privileges` | Absence-based rule; would flag most existing stacks. `allowPrivilegeEscalation` is covered for K8s. |
| K8s `runAsNonRoot` missing | Absence-based rule; `VGL-CFG-018` covers the explicit `false` case. |
| K8s `readOnlyRootFilesystem: false` | Low impact and noisy; not a clear vulnerability by itself. |
| K8s `automountServiceAccountToken` | Defaults to true and is often required; noisy without workload context. |
| K8s `hostPort` | Often required for DaemonSets/ingress controllers; controversial. |
| K8s `imagePullPolicy: Always` | Not a security issue. |
| Terraform `publicly_accessible` | Already `VGL-CFG-023`. |
| Terraform SG sensitive ports | Already `VGL-CFG-013`/`VGL-CFG-027`. |
| Terraform public S3 ACL | Already `VGL-CFG-014`. |
| Terraform EBS/storage encryption | Already `VGL-CFG-015`/`VGL-CFG-024`. |
| Terraform `associate_public_ip_address = true` | Public IPs are often intentional; noisy. |
| Terraform S3 bucket missing encryption | SSE-S3 is the default and the check is noisy. |
| Terraform CloudTrail missing multi-region | Depends on organization/region design; controversial. |
| Terraform KMS key rotation disabled | Medium/niche; cut for this wave. |
| Terraform ECR mutable image tags | Common and sometimes intentional; controversial. |
| CloudFormation duplicate public-bucket/SG/RDS checks | Better implemented by extending the existing Terraform rules to CloudFormation than by adding duplicate IDs. |
| nginx weak `ssl_ciphers` | Overlaps the crypto pack (`VGL-CRY-002`) in spirit; add later only if config-specific coverage is needed. |
| nginx `server_tokens on` | Low signal. |
| nginx `proxy_pass http://` | Internal HTTP upstreams are common; controversial. |
| nginx missing security headers | Explicitly rejected by the brief. |
| GitHub Actions `permissions` absent | Default depends on repository/organization settings; not deterministic. |
| GitHub Actions `runs-on: ubuntu-latest` | Mutable runner image; low signal. |
| GitHub Actions `persist-credentials` default | Noisy without artifact context; zizmor's `artipacked` needs cross-step analysis. |
| GitHub Actions `ACTIONS_STEP_DEBUG: true` | Debug logging is often temporary; low signal. |
| GitHub Actions `pull_request_target` + `repository: head.repo` | Variant of `VGL-CI-002`; extend that rule instead of adding a near-duplicate. |
| GitHub Actions `allow-unsafe-pr-checkout: true` | Covered as a high-confidence variant in `VGL-CI-018`; a separate ID would duplicate the pwn-request family. |
| GitHub Actions cache poisoning | Requires cross-workflow state and trigger analysis; not deterministic with the current engine. |
| GitHub Actions artifact poisoning | Requires cross-workflow dataflow; reject. |
| GitLab CI `image: latest` | Explicitly rejected by the brief; low signal and noisy. |
| GitLab CI `include:project` without `ref` | Tracking the default branch is a legitimate choice for internal templates; controversial. |
| GitLab Runner `tls_verify = false` | Real issue but niche; candidate for a later `config.toml` wave. |
| Jenkins shell injection | Already `VGL-CI-011`. |
| CircleCI mutable image | Already `VGL-CI-012`. |

---

## Implementation notes

1. **Shared helpers.** `VGL-CFG-030`/`036` need a small logical-command joiner for
   backslash continuations (cap at 20 lines). `VGL-CFG-038`/`040`/`041`/`042` need a
   bounded YAML/HCL block walker; reuse the existing `pbLineIndent` and
   `pbInsideYAMLVolumesBlock` patterns rather than a full parser.
2. **File scoping.** Reuse `pbIsCompose`, `pbIsKubernetes`, `pbIsTerraform`,
   `pbIsDockerfile`, `pbIsGitHubWorkflow`, `pbIsGitLabCI` and `pcIsNginxConf`. Add
   `pbIsDockerRuntimeScript` (shell/Makefile/CI/`other`) and `pbIsGitLabRunnerConfig`
   (`config.toml` or `*.toml` with `[[runners]]`). CloudFormation detection should require
   `AWSTemplateFormatVersion` or `Resources:` plus `Type: AWS::` to avoid matching generic
   YAML.
3. **Severity and confidence.** Use `pbSev` so docs/tests are downgraded by the existing
   `SeverityForLanguage` cap. `VGL-CI-018` is the only rule that needs variable confidence:
   high for `allow-unsafe-pr-checkout: true`, medium for a PR-head ref when the checkout
   version cannot be resolved. Everything else is high confidence.
4. **No duplicate emissions.** `VGL-CFG-033` must exclude `SYS_ADMIN`; `VGL-CFG-030` must
   exclude Compose `network_mode`; `VGL-CI-020` must exclude all `--cap-add` flags and the
   Docker socket; `VGL-CFG-040` must exclude `permissions_boundary` documents;
   `VGL-CFG-041` must exclude egress. These exclusions are part of the rule, not an
   afterthought.
5. **Fixtures.** Add each vulnerable/safe pair to the rule-pack tests and keep them
   one-file, one-purpose snippets so the line numbers in assertions stay stable.
6. **Docs.** If implemented, update `docs/rules.md`, the `vigil rules --json` snapshot, and
   the rule-count claim in the README/CHANGELOG in the same change.
