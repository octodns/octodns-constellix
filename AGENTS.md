# Developer Agent Guide for octoDNS Constellix Provider

This repository contains the Constellix provider for octoDNS. It enables planning, syncing, and applying DNS record states directly to Constellix DNS API v4, with built-in support for DNS pools and Sonar active monitoring.

> [!IMPORTANT]
> **Core Workflow and Guidelines**
>
> All agents working on this repository must read and follow the general instructions and workflow guidelines defined in the core octoDNS `AGENTS.md` file.
> - **Local check**: Look for the file at `../octodns/AGENTS.md`.
> - **Remote check**: If the local file is not available, fetch it from GitHub: [octoDNS Core AGENTS.md](https://github.com/octodns/octodns/raw/refs/heads/main/AGENTS.md).
>
> You must align your code structure, style, pull request guidelines, and overall development workflows with the instructions specified there.

## Repository & Module Information

### Key Components

- **Provider Class**: [ConstellixProvider](file:///home/ross/octodns/octodns-constellix/octodns_constellix/__init__.py#L415-L1139) (defined in [octodns_constellix/__init__.py](file:///home/ross/octodns/octodns-constellix/octodns_constellix/__init__.py)). This is the primary provider orchestrating resource mappings and sync operations.
- **DNS Client Class**: [ConstellixClient](file:///home/ross/octodns/octodns-constellix/octodns_constellix/__init__.py#L106-L325) wraps API operations for Constellix LiveDNS REST endpoints, managing zone lists, record configurations, pools, and geofilters.
- **Sonar Client Class**: [SonarClient](file:///home/ross/octodns/octodns-constellix/octodns_constellix/__init__.py#L326-L414) integrates with the Constellix Sonar service to manage system checking agents and TCP/HTTP health checks.
- **Authentication & Security**: The base class [ConstellixAPI](file:///home/ross/octodns/octodns-constellix/octodns_constellix/__init__.py#L45-L105) handles standard security signature header generation (`x-cns-security-token` or `Authorization`) using SHA-1 HMAC hashes signed with a millisecond timestamp and API secret key.

### Key Workflows & Features

1. **Supported Record Types**: `A`, `AAAA`, `ALIAS` (mapped to Constellix `ANAME`), `CAA`, `CNAME`, `MX`, `NS`, `PTR`, `SRV`, `TXT`.
2. **DNS Pools**: Supports routing dynamic DNS queries via pools (`A`, `AAAA`, and `CNAME` pools). The provider parses target weight details and automatically configures fallback behaviors.
3. **Sonar Active Health Checks**: Connects dynamic DNS pools to active Sonar monitors.
4. **Geographic Routing Filter**: Integrates custom geofilters to configure continent-based and region-based routing logic.
5. **Dynamic Routing Support**: Supported (`SUPPORTS_DYNAMIC=True`, `SUPPORTS_GEO=False` inside octoDNS core geocoding namespace, routing is handled natively via Constellix geofilters).
6. **Dynamic Subnets**: Not supported (`SUPPORTS_DYNAMIC_SUBNETS=False`).
7. **Pool Value Status**: Not supported (`SUPPORTS_POOL_VALUE_STATUS=False`).

## Development & Testing

- **Setup Script**: Run `./script/bootstrap` to create a virtual environment, install dependencies (including `black`, `isort`, `pyflakes`, `pycountry_convert`, and `pytest`), and configure pre-commit hooks.
- **Test Suite**: Run unit tests using `pytest` via `./script/test` (or `pytest tests/`). Test files are located in [tests/](file:///home/ross/octodns/octodns-constellix/tests).
- **Code Coverage**: Verify code coverage using `./script/coverage`.

## Key Constraints & Behaviors

- **Python Version**: Targets Python `>=3.9`.
- **Formatting**: Code formatting is enforced via `black` (version `>=26.0.0,<27.0.0`) and `isort`.
