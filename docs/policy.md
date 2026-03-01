# Policy Engine

The policy engine controls which operations agents are allowed to perform. It uses a three-layer model with specificity-based conflict resolution, resource-level filtering, and role presets.

## Three-Layer Model

```
┌─────────────────────────┐
│     Global Rules        │  Apply to all profiles
├─────────────────────────┤
│  Role Preset Rules      │  Expanded from the profile's role
├─────────────────────────┤
│  Profile Override Rules │  Custom per-profile rules
└─────────────────────────┘
         │
         ▼
   Effective Policy        Merged, ready to evaluate
```

1. **Global rules** apply to every agent regardless of profile
2. **Role preset rules** are generated from the profile's role (ReadOnly, Operator, Admin, Custom)
3. **Profile rules** are custom overrides defined per profile

Rules are evaluated in order: global first, then role preset, then profile overrides. When multiple rules match, the most specific one wins (see [Evaluation Algorithm](#evaluation-algorithm)).

## TOML Configuration

Policy is configured via a TOML file, passed to the CLI with `--config`:

```toml
[global]
default_profile = "operator"     # Fallback when agent profile is unknown
dry_run = false                  # Force dry-run mode globally

[[global.rules]]
action = "allow"                 # "allow" or "deny"
target = "all"                   # Target specifier (see below)

[[global.rules]]
action = "deny"
target = { capability = "probe_manage" }
reason = "eBPF probes disabled globally by default"

[[global.rules]]
action = "deny"
target = { tool = "tuning_set" }
filter = { tunable_prefixes = ["kernel."] }
reason = "Kernel namespace tunables are dangerous"

[profiles.my-agent]
role = "operator"                # Role preset
dry_run = false                  # Per-profile dry-run

[[profiles.my-agent.rules]]
action = "allow"
target = { tool = "service_action" }
filter = { service_names = ["nginx", "postgresql"] }

[[profiles.my-agent.rules]]
action = "deny"
target = { tool = "service_action" }
reason = "Only nginx and postgresql allowed"
```

## Rule Targets

Every rule has a `target` that determines what it applies to.

| Target | TOML Syntax | Specificity | Description |
|--------|------------|-------------|-------------|
| All | `"all"` | 0 | Matches every tool |
| Capability | `{ capability = "..." }` | 1 | Matches tools in a capability group |
| Category | `{ category = "..." }` | 2 | Matches tools by prefix (e.g., `"process"` matches `process_list`, `process_kill`) |
| Tool | `{ tool = "..." }` | 3 | Matches a single tool by exact name |

Tool categories are derived from the tool name -- everything before the first underscore. For example, `process_kill` has category `process`.

### Filtered Rules

Any rule with a `filter` gets a **+4 specificity bonus**. This means a filtered `All` rule (specificity 4) beats an unfiltered `Tool` rule (specificity 3).

| Target | Unfiltered | Filtered |
|--------|-----------|----------|
| All | 0 | 4 |
| Capability | 1 | 5 |
| Category | 2 | 6 |
| Tool | 3 | 7 |

## Resource Filters

Filters narrow a rule to specific resources. If a filter is present but the resource context doesn't match, the rule is skipped entirely.

| Filter | TOML Syntax | Matches When |
|--------|------------|--------------|
| ServiceNames | `{ service_names = ["nginx", "redis"] }` | `service_name` is in the list |
| TunablePrefixes | `{ tunable_prefixes = ["kernel.", "net."] }` | `tunable_key` starts with any prefix |
| ProcessOwners | `{ process_owners = ["root", "www-data"] }` | `process_owner` is in the list |
| PidRange | `{ pid_range = { min = 1, max = 1000 } }` | `pid` is within the range (inclusive) |
| InterfaceNames | `{ interface_names = ["eth0", "lo"] }` | `interface_name` is in the list |
| LogSources | `{ log_sources = ["sshd", "kernel"] }` | `log_source` is in the list |

### ResourceContext

The caller provides a `ResourceContext` with the relevant fields populated. Unpopulated fields cause filter checks against those fields to fail (the rule is skipped).

```rust
pub struct ResourceContext {
    pub service_name: Option<String>,
    pub tunable_key: Option<String>,
    pub pid: Option<u32>,
    pub process_owner: Option<String>,
    pub interface_name: Option<String>,
    pub log_source: Option<String>,
}
```

## Role Presets

Roles provide a base set of rules. Profile-specific rules are appended after the preset and can override them.

### ReadOnly

Allows all read operations. Denies all six write capabilities.

| Action | Target |
|--------|--------|
| Allow | All |
| Deny | Capability(ProcessManage) |
| Deny | Capability(KernelTune) |
| Deny | Capability(FirewallManage) |
| Deny | Capability(ServiceManage) |
| Deny | Capability(ProbeManage) |
| Deny | Capability(PolicyManage) |

### Operator

Allows reads plus process and service management. Denies kernel tuning, firewall, probes, and policy management.

| Action | Target |
|--------|--------|
| Allow | All |
| Deny | Capability(KernelTune) |
| Deny | Capability(FirewallManage) |
| Deny | Capability(ProbeManage) |
| Deny | Capability(PolicyManage) |

### Admin

Full access to everything.

| Action | Target |
|--------|--------|
| Allow | All |

### Custom

No preset rules. The profile is entirely defined by its custom rules.

## Capabilities

Capabilities group related write tools together so rules can target them as a unit.

| Capability | TOML Value | Tools |
|------------|-----------|-------|
| ProcessManage | `"process_manage"` | `process_kill` |
| KernelTune | `"kernel_tune"` | `tuning_set` |
| FirewallManage | `"firewall_manage"` | `firewall_add`, `firewall_remove` |
| ServiceManage | `"service_manage"` | `service_action` |
| ProbeManage | `"probe_manage"` | `probe_attach`, `probe_detach` |
| PolicyManage | `"policy_manage"` | `policy_switch_profile` |

## Evaluation Algorithm

Given a tool name and optional resource context:

1. Extract the tool category (everything before the first `_`)
2. Initialize `best_specificity = None`, `best_action = Deny`
3. For each rule in order (global, then role preset, then profile overrides):
   a. Check if the rule's target matches the tool
   b. If the rule has a filter, check it against the resource context. If the filter doesn't match, skip the rule
   c. Calculate specificity = `base_specificity + filter_bonus`
   d. If `specificity < best_specificity`, skip (less specific rule cannot override)
   e. At equal or higher specificity, update `best_action` and `best_specificity` (last match wins)
4. Return `PolicyDecision { allowed: best_action == Allow, dry_run, reason }`

Key properties:
- **More specific rules always win** -- a Tool-level rule beats a Category-level rule regardless of order
- **Last match wins at equal specificity** -- profile rules come after global rules, so they can override
- **Filtered rules beat unfiltered** -- the +4 bonus ensures resource-specific rules take priority
- **Default is Deny** -- if no rules match at all, the operation is denied
- **Dry-run is OR'd** -- `global.dry_run || profile.dry_run`

### Walkthrough Example

Given this policy:

```toml
[[global.rules]]
action = "allow"
target = "all"                            # specificity 0

[[global.rules]]
action = "deny"
target = { capability = "probe_manage" }  # specificity 1

[profiles.my-agent]
role = "custom"

[[profiles.my-agent.rules]]
action = "allow"
target = { tool = "probe_attach" }        # specificity 3
```

Evaluating `probe_attach`:

1. Global `allow all` matches (specificity 0, action = Allow)
2. Global `deny probe_manage` matches (specificity 1 > 0, action = Deny)
3. Profile `allow probe_attach` matches (specificity 3 > 1, action = Allow)

Result: **Allowed** -- the tool-level allow (3) beats the capability-level deny (1).

## Agent Identification

In MCP mode, agents are identified by the `--agent` flag passed to `mycelium-mcp`. The server matches this name against profile names to select the appropriate policy.

```bash
mycelium-mcp --config policy.toml --agent deploy-bot
```

If no profile matches the agent name, the `default_profile` from `[global]` is used. If the default profile also doesn't exist, no profile rules apply (only global rules).

See [mcp-server.md](mcp-server.md) for full MCP server documentation.

## Common Recipes

### Read-Only Monitoring Bot

```toml
[profiles.monitor-bot]
role = "read-only"
dry_run = true
```

### Restricted Operator (specific services only)

```toml
[profiles.deploy-bot]
role = "operator"

[[profiles.deploy-bot.rules]]
action = "allow"
target = { tool = "service_action" }
filter = { service_names = ["nginx", "postgresql", "redis"] }

[[profiles.deploy-bot.rules]]
action = "deny"
target = { tool = "service_action" }
reason = "Deploy bot can only manage nginx, postgresql, redis"
```

### Full Admin with Probe Access

```toml
[profiles.claude-code]
role = "admin"

[[profiles.claude-code.rules]]
action = "allow"
target = { capability = "probe_manage" }
```

### Deny Dangerous Tunables Globally

```toml
[[global.rules]]
action = "deny"
target = { tool = "tuning_set" }
filter = { tunable_prefixes = ["kernel."] }
reason = "Kernel namespace tunables require manual approval"
```

## CLI Policy Commands

```bash
# Show effective policy for a profile
mycelium --config policy.toml policy show --profile my-agent

# List all defined profiles
mycelium --config policy.toml policy list

# Validate a TOML config file
mycelium policy validate path/to/policy.toml
```

See [cli.md](cli.md) for full CLI reference.
