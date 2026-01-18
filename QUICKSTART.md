# Quick Start Guide

Get up and running with the TEE HPC tutorial in 5 minutes.

## Prerequisites

- Python 3.8+
- Azure Attestation Service instance
- SEV VM and TDX VM (or use localhost for testing)

## Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

## Configuration

Create `.env` file:

```bash
# Azure Attestation Service (only endpoint needed - no authentication required)
AZURE_ATTESTATION_ENDPOINT=https://your-instance.attest.azure.net

# Server URLs
SEV_VM_URL=http://sev-vm-ip:8080
TDX_VM_URL=http://tdx-vm-ip:8080

# Node selection (optional): TDX, SEV, or SEV,TDX (default: SEV,TDX)
# To test with TDX only:
ENABLED_NODES=TDX
```

## Running the Tutorial

### 1. Start SEV Server (on SEV VM)

```bash
export TEE_TYPE=SEV
python -m src.server.tee_server
```

### 2. Start TDX Server (on TDX VM)

```bash
export TEE_TYPE=TDX
python -m src.server.tee_server
```

### 3. Run Client (from Desktop)

```bash
python scripts/run_client.py
```

## What Happens

1. **Attestation**: Client verifies enabled VMs are running in trusted environments
2. **Mutual Attestation**: VMs verify each other's attestation (if multiple nodes enabled)
3. **Job Submission**: HPC job is distributed to enabled VMs
4. **Execution**: VMs process data and synchronize at each iteration (if multiple nodes)
5. **Results**: Client collects and displays results from all enabled nodes

## Testing with Single Node

To test with TDX only (useful for initial testing):

```bash
# In .env file:
ENABLED_NODES=TDX

# Or when running client:
python -c "from src.client.desktop_client import TEEHPCClient; client = TEEHPCClient(enabled_nodes=['TDX'])"
```

## Testing Setup

```bash
python scripts/test_setup.py
```

## Troubleshooting

- **Connection errors**: Check server URLs and network connectivity
- **Attestation fails**: Verify Azure endpoint URL and network connectivity
- **Import errors**: Run `pip install -r requirements.txt`

For detailed setup, see [SETUP.md](SETUP.md)
