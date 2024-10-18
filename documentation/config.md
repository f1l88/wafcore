# Aegis Configuration Reference

This document provides an overview of the configuration options for the Aegis firewall and explains how to create a valid configuration file in YAML format.

## Overview

The configuration is represented by the `AegisConfig` struct, which defines settings for the Aegis server, Redis connection, upstream, firewall rules, and more. To configure Aegis, you will need to provide a YAML file with the following fields. By default, aegis looks for a file called `aegis.yaml` in the current directory. But you can specify a custom path with the `--config-file` flag.

### Example Configuration (YAML)

```yaml
server:
  address: "0.0.0.0"        # Address the Aegis server will listen on
  port: 4000                # Port for the server
  log_level: "INFO"          # Logging level: INFO, ERROR, WARN, DEBUG, TRACE

upstream: "https://example.com"  # The upstream server URL

metrics:
  enabled: true # Enable or disable metric collection. Must be enabled for the Count action
  export_endpoint: "http://localhost:4317", # otel collector endpoint
  export_interval: 15 # Interval (in seconds) to export metrics

redis:
  enabled: true              # Enable or disable Redis connection
  url: "redis://127.0.0.1/"   # Redis connection URL

default_action: "Allow"       # Default action for requests: Allow, Block
rules:                       # List of firewall rules
  - type: "Regular"           # Type of the rule: Regular or RateBased
    action: "Block"           # Action to take: Allow, Block, or Count
    condition: "All"          # Rule condition: One, All, or None
    statements:               # Rule statements for matching requests
      - inspect: 
          Header:             # Inspect request headers
            key: "User-Agent" # Header key to inspect
        match_type: "Contains"  # Type of matching: StartsWith, EndsWith, Contains, Exact, Regex
        match_string: "curl"   # String to match
  - type: "RateBased"          # Rate-based rule
    limit: 1000                # Request limit per evaluation window
    evaluation_window_seconds: 60  # Time window in seconds
    key: "SourceIp"            # Key to rate-limit by (e.g., SourceIp)
```

### Field Descriptions

1. **`server`** (`AegisServer`)
    - **`address`**: The IP address the server listens on.
      - Default: `"0.0.0.0"`
    - **`port`**: The port number to run the Aegis server.
      - Default: `4000`, or uses the `PORT` environment variable if set.
    - **`log_level`**: The logging level for the server.
      - Allowed values: `INFO`, `ERROR`, `WARN`, `DEBUG`, `TRACE`
      - Default: `INFO`

2. **`upstream`** (`String`)
    - **Description**: The URL of the upstream service that Aegis proxies traffic to.
    - Example: `"https://example.com"`
    - **Validation**: This field must contain a valid URL.

3. **`redis`** (`RedisConfig`)
    - **`enabled`**: Whether Redis is enabled.
      - Default: `true`
    - **`url`**: The Redis connection string.
      - Default: `"redis://127.0.0.1/"`

4. **`default_action`** (`RuleAction`)
    - **Description**: The default action to apply to requests that don't match any rule.
    - **Allowed values**: 
      - `Allow`: Permit the request.
      - `Block`: Deny the request.
    - Default: `Allow`
    - **Note**: Only `Allow` and `Block` are supported as default actions.

5. **`rules`** (`Vec<AegisRule>`)
    - A list of rules that define how Aegis processes requests. Please refer to [this document](./rules.md) for more information on rules.

6. **`metrics`** (MetricsConfig)
    - **`enabled`**: Enable or disable metric collection
      - Default: true
    - **`export_endpoint`**: Otel collector endpoint
        - Default: `"http://localhost:4317"`
    - **`export_interval`**: Interval (in seconds) to export metrics
        - Default: `15`