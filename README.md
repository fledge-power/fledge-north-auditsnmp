# JSON Configuration - Fledge SNMP Plugin

## Overview

This document describes the JSON structure used to configure the Fledge SNMP plugin. This configuration allows defining dynamic rules that associate audit events with specific SNMP actions.

## Architecture

The system works on a **trigger/action** principle:
- **Trigger**: Defines conditions to trigger an action
- **Action**: Defines the SNMP action to execute (trap, MIB storage, log)

## JSON Structure

```json
{
  "plugin_configuration": {
    "bind_[id]": {
      "name": "string",
      "enabled": boolean,
      "trigger": {
        "source": string | array,
        "severity": string | array,
        "details": string (regex)
      },
      "action": {
        "oid": "string",
        "payload": {
          "type": "string",
          "data": "string"
        },
        "trapOnEvent": boolean,
        "storeInMIB": boolean,
        "createFledgeLog": "string"
      }
    }
  }
}
```

## Field Descriptions

### `bind_[id]` Block

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | No | Descriptive name for the rule |
| `enabled` | boolean | Yes | Enable/disable the rule |

### `trigger` Block

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source` | string \| array | Yes | Event type(s) to monitor |
| `severity` | string \| array | Yes | Severity level(s) |
| `details` | string | Yes | Regex pattern to filter details |

### `action` Block

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `oid` | string | Yes | Target SNMP OID |
| `payload.type` | string | Yes | SNMP data type |
| `payload.data` | string | Yes | Data to send (supports templates) |
| `trapOnEvent` | boolean | Yes | Send SNMP trap |
| `storeInMIB` | boolean | Yes | Store in MIB |
| `createFledgeLog` | string | Yes | Fledge log level or "None" |

## Supported SNMP Types

| Type | Description | Example |
|------|-------------|---------|
| `string` | OCTET STRING | Messages, descriptions |
| `integer` | INTEGER | Error codes, counters |
| `counter` | Counter32 | Incrementing counters |
| `gauge` | Gauge32 | Fluctuating values |
| `timeticks` | TimeTicks | Durations, time |
| `oid` | OBJECT IDENTIFIER | OID references |

## Template Variables

The following variables can be used in the `payload.data` field:

| Variable | Description | Example |
|----------|-------------|---------|
| `${source}` | Event type | SRVFL, START, CONCH |
| `${details}` | Event details | Free text |
| `${timestamp}` | Event timestamp | 2024-01-15T10:30:00Z |
| `${severity}` | Severity level | critical, high, low |

### Template Usage Example

```json
"payload": {
  "type": "string",
  "data": "Service ${source} failed: ${details} at ${timestamp} (${severity})"
}
```

## Matching Logic

### Lists (OR logic)
```json
"source": ["SRVFL", "SRVUN", "START"]
```
→ Triggers if `source` = SRVFL **OR** SRVUN **OR** START

### Regex Patterns
```json
"details": ".*error.*"     // Contains "error"
"details": "*"             // Equivalent to ".*" (everything)
"severity": "critical?"    // "critical" or "critica"
"source": "srv+"           // "srv", "srvv", "srvvv", etc.
```

## Fledge Log Levels

| Value | Description |
|-------|-------------|
| `"DEBUG"` | Debug logs |
| `"INFO"` | Informational logs |
| `"WARNING"` | Warning logs |
| `"ERROR"` | Error logs |
| `"None"` | No logging |

## Concrete Examples

### 1. Critical Service Alert

```json
{
  "plugin_configuration": {
    "bind_service_failure": {
      "name": "Service Failure Alert",
      "enabled": true,
      "trigger": {
        "source": ["SRVFL", "SRVUN"],
        "severity": ["critical", "high"],
        "details": ".*"
      },
      "action": {
        "oid": ".1.3.6.1.4.1.2906.1.4",
        "payload": {
          "type": "string",
          "data": "CRITICAL: Service ${source} failed - ${details}"
        },
        "trapOnEvent": true,
        "storeInMIB": false,
        "createFledgeLog": "ERROR"
      }
    }
  }
}
```

### 2. Startup Counter

```json
{
  "plugin_configuration": {
    "bind_startup_counter": {
      "name": "Startup Counter",
      "enabled": true,
      "trigger": {
        "source": "START",
        "severity": "*",
        "details": "*"
      },
      "action": {
        "oid": ".1.3.6.1.4.1.2906.1.1",
        "payload": {
          "type": "integer",
          "data": "1"
        },
        "trapOnEvent": true,
        "storeInMIB": true,
        "createFledgeLog": "INFO"
      }
    }
  }
}
```

### 3. Authentication Error Filter

```json
{
  "plugin_configuration": {
    "bind_auth_errors": {
      "name": "Authentication Errors",
      "enabled": true,
      "trigger": {
        "source": "*",
        "severity": ["high", "critical"],
        "details": ".*(auth|login|credential).*fail.*"
      },
      "action": {
        "oid": ".1.3.6.1.4.1.2906.1.5",
        "payload": {
          "type": "string",
          "data": "AUTH_FAIL: ${details} (${timestamp})"
        },
        "trapOnEvent": true,
        "storeInMIB": false,
        "createFledgeLog": "WARNING"
      }
    }
  }
}
```

## Best Practices

### Rule Naming
- Use explicit identifiers: `bind_service_failure` rather than `bind_1`
- Name clearly: `"name": "Service Failure Alert"`

### Performance
- Place most frequent rules first
- Use efficient regex patterns
- Avoid overly complex regex on `details`

### Security
- Validate OIDs before use
- Limit payload sizes
- Use templates to prevent injection

## File Format

The configuration file must be in valid JSON format, typically named `snmp_config.json` and placed in the Fledge plugin configuration through the API Endpoint.

```bash
# JSON validation
cat snmp_config.json | python -m json.tool
``` 