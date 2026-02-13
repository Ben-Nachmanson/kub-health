# kub-health

**AI-powered Kubernetes cluster investigation engine that thinks like an SRE.**

Most Kubernetes health tools produce a flat list of findings. `kub-health` goes further -- it builds a dependency graph of your cluster, correlates findings across resource types, identifies root causes, and optionally sends the structured investigation to an LLM for SRE-quality analysis.

```
$ kub-health investigate

╭──────────── Kubernetes Cluster Investigation ────────────╮
│ Cluster: prod-us-east  |  Context: admin@prod  |  CRITICAL │
╰──────────────── 2026-02-12 18:30:45 UTC ─────────────────╯

╭── Summary ──╮
│ Nodes          4  │  Critical     3  │
│ Pods          47  │  Warnings     8  │
│ Namespaces     6  │  Root Causes  2  │
╰─────────────────╯

── Root Cause Analysis ──

╭ Issue #1 [CRITICAL] Node 'node-3' NotReady affecting 12 pods ───────╮
│ Root Cause: Node/node-3 - NotReady for 15m (KubeletDown)            │
│   Fix: Check kubelet logs on node-3, verify disk/memory pressure    │
│ Symptoms (12):                                                       │
│   CRIT Pod/api-7b8f9-xk2lp  - CrashLoopBackOff (8 restarts)       │
│   CRIT Pod/web-6c4d5-mn3qr  - CrashLoopBackOff (5 restarts)       │
│   WARN Pod/worker-9a1b2-pq4  - not Ready for 12m                   │
│   ... and 9 more                                                     │
│ Blast radius: 14 resources affected                                  │
╰──────────────────────────────────────────────────────────────────────╯
```

## Why kub-health?

Existing tools (k8sgpt, Popeye, Kubescape) are scanners -- they check individual resources against rules and produce flat finding lists. When a node goes down and 15 pods crash, they report 16 separate issues. A human SRE would immediately see this as one incident.

`kub-health` replicates the SRE investigation workflow:

1. **Snapshot** the entire cluster state in a single pass (30+ resource types)
2. **Check** 8 categories of health issues against the snapshot
3. **Build a dependency graph** mapping every resource relationship (Pod->Node, Deployment->RS->Pod, Service->Pod, Pod->PVC/ConfigMap/Secret, Ingress->Service, HPA->workload, NetworkPolicy->Pod, RBAC bindings)
4. **Correlate** findings using 5 strategies to identify root causes and group symptoms
5. **Analyze** the structured report with an LLM (optional) for actionable remediation

The result: "You have 2 root causes, not 23 separate problems."

## Installation

```bash
pip install -e .

# With dev tools (pytest, ruff, mypy)
pip install -e ".[dev]"
```

Requires Python 3.10+ and a valid kubeconfig or in-cluster service account.

## Usage

```bash
# Investigate your current kubeconfig context
kub-health investigate

# Without AI analysis (no API key needed, still runs all checks + correlation)
kub-health investigate --no-ai

# Target a specific namespace
kub-health investigate --namespace production

# Use a specific kubeconfig context
kub-health investigate --context staging-cluster

# Use a specific AI provider
kub-health investigate --provider openai
kub-health investigate --provider anthropic
kub-health investigate --provider ollama --model llama3
```

## Safety

**This tool is completely read-only.** Every K8s API call is a `list` operation (GET). There are zero write, patch, delete, or exec calls. It is safe to run against production clusters -- the API load is equivalent to running `kubectl get <resource> -A` for each resource type once.

## What It Checks

| Category | What it detects |
|----------|----------------|
| **Pod Health** | CrashLoopBackOff, OOMKilled, ImagePullBackOff, stuck pending, unready pods, init container failures, high restart counts |
| **Node Health** | NotReady, MemoryPressure, DiskPressure, PIDPressure, NoExecute taints, allocation ratios, actual usage via metrics-server |
| **Resources** | Missing requests/limits, ResourceQuota near exhaustion, LimitRange violations, large request/limit gaps, actual vs requested usage |
| **Deployments** | Failed rollouts, replica mismatches, stuck rollouts, StatefulSet/DaemonSet issues, stale ReplicaSets |
| **Events** | High-frequency warnings, FailedScheduling, FailedMount, OOMKilling, Eviction patterns, critical event clustering |
| **Networking** | Services with no endpoints, selector/label mismatches, port mismatches, Ingress pointing to missing services, TLS secret issues, NetworkPolicy default-deny analysis |
| **Storage** | Unbound PVCs, missing StorageClasses, Lost/Released PVs, pods referencing non-existent PVCs, ConfigMaps, or Secrets |
| **RBAC & Security** | cluster-admin bindings, wildcard verb/resource roles, privileged containers, hostNetwork/hostPID, dangerous capabilities (SYS_ADMIN, NET_RAW), default ServiceAccount usage |

## Correlation Engine

The correlation engine is the core differentiator. It takes raw findings, the dependency graph, and the event timeline, then groups related findings into root-cause groups.

Five strategies run in priority order (broader blast radius first):

| Strategy | Logic |
|----------|-------|
| **Node cascade** | Node has CRITICAL/WARNING findings -> all pod findings on that node become symptoms of the node issue |
| **Deployment grouping** | Deployment finding -> traces Deployment->ReplicaSet->Pod chain, groups all pod findings as symptoms |
| **Storage cascade** | PVC issue (unbound, lost) -> all pods mounting that PVC are symptoms |
| **Service/endpoint** | Service has no endpoints + pods are failing -> the pod failure is the root cause (reversed causality), service issue is the symptom |
| **Missing config** | 2+ pods referencing the same missing ConfigMap/Secret -> creates a synthetic root cause for the missing resource |

Order matters: a pod on a bad node gets claimed by the node-cascade strategy before the deployment strategy can claim it. This prevents narrow groupings when a broader incident is the real cause.

## AI Providers

AI analysis is optional (`--no-ai` to skip). When enabled, the structured investigation report is sent to an LLM with an SRE-focused system prompt that produces root cause reasoning, blast radius assessment, and specific `kubectl` remediation commands.

| Provider | Configuration | Default Model |
|----------|--------------|---------------|
| **OpenAI** | `OPENAI_API_KEY` env var or `--provider openai` | gpt-4o |
| **Anthropic** | `ANTHROPIC_API_KEY` env var or `--provider anthropic` | claude-sonnet-4-20250514 |
| **Ollama** | `OLLAMA_HOST` env var or `--provider ollama` | llama3.1 (local, air-gapped) |

### Configuration File

Config can be set in `~/.kub-health.yaml`, `$CWD/.kub-health.yaml`, or `~/.config/kub-health/config.yaml`:

```yaml
ai:
  provider: ollama
  model: llama3
  base_url: http://localhost:11434

namespace: production

skip_checks:
  - rbac
  - events

skip_namespaces:
  - kube-system
  - kube-public
```

Precedence: CLI flags > environment variables > config file > defaults.

## Architecture

```
┌──────────┐    ┌───────────┐    ┌──────────┐    ┌────────────┐    ┌──────────┐
│  Connect  │──>│  Collect   │──>│  Check   │──>│ Correlate   │──>│ Analyze   │
│ (K8s API) │   │ (Snapshot) │   │ (8 mods) │   │ (5 strats)  │   │ (LLM opt) │
└──────────┘    └───────────┘    └──────────┘    └────────────┘    └──────────┘
                    30+ APIs          │               │
                    one pass          │               │
                       │              ▼               ▼
                       │        ┌──────────┐   ┌──────────────┐
                       └───────>│ Dep Graph │   │ Root Cause   │
                                │ (12 maps)│   │   Groups     │
                                └──────────┘   └──────────────┘
```

- **Snapshot-first**: All K8s API calls happen once during collection. Every check and the correlation engine read from the in-memory `ClusterSnapshot`. No repeated API calls.
- **Dependency graph**: Directed graph with 12 mapping functions covering Pod->Node, Deployment->RS->Pod, Service->Pod, Pod->PVC/ConfigMap/Secret, Ingress->Service, HPA->workload, NetworkPolicy->Pod, and RBAC bindings. Supports `impact_radius()` (what breaks if X fails) and `dependency_chain()` (what does X depend on).
- **Graceful degradation**: If an API group is unavailable (metrics-server not installed, RBAC restricting access), the tool skips it and continues. Uses `_safe_list()` to swallow 403/404 errors.

## Project Structure

```
kub_health/
├── cli.py                         # Click CLI: investigate, status, init commands
├── config.py                      # YAML config + env var + CLI flag precedence
├── k8s_client.py                  # K8s API wrapper (kubeconfig + in-cluster auth)
├── models.py                      # Core data models (ClusterSnapshot, Finding,
│                                  #   DependencyGraph, CorrelationGroup, Report)
├── output.py                      # Rich terminal renderer (panels, trees, tables)
├── ai/
│   └── analyzer.py                # LLM providers: OpenAI, Anthropic, Ollama
├── checks/
│   ├── pods.py                    # Pod health (CrashLoop, OOM, ImagePull, pending)
│   ├── nodes.py                   # Node health (NotReady, pressure, taints)
│   ├── resources.py               # Resource requests/limits/quotas
│   ├── deployments.py             # Rollout status, replica mismatches
│   ├── events.py                  # Warning event patterns
│   ├── networking.py              # Service endpoints, selectors, NetworkPolicy
│   ├── storage.py                 # PVC/PV state, missing references
│   └── rbac.py                    # RBAC audit, security posture
├── collector/
│   └── snapshot.py                # Single-pass cluster state collector (30+ APIs)
└── correlator/
    ├── dependency_graph.py        # Resource relationship graph (12 mapping fns)
    ├── timeline.py                # Chronological event reconstruction
    └── engine.py                  # 5-strategy correlation engine
```

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests (57 tests, ~0.1s)
pytest tests/ -v

# Lint
ruff check kub_health/

# Type check
mypy kub_health/
```

## License

MIT
