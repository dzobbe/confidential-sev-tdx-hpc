# Confidential SEV-TDX HPC Framework

A secure distributed High Performance Computing (HPC) framework that runs jobs on Trusted Execution Environment (TEE) virtual machines using AMD SEV and Intel TDX technologies, with attestation verification through Azure Attestation Service and mutual attestation between nodes.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Architecture Details](#architecture-details)
- [Security Model](#security-model)
- [API Reference](#api-reference)
- [Troubleshooting](#troubleshooting)
- [Project Structure](#project-structure)
- [References](#references)

## Overview

This project implements a secure distributed HPC system where:

1. **Desktop Client** launches HPC jobs on remote TEE VMs
2. **Attestation Verification** ensures jobs only run on verified TEE environments
3. **Mutual Attestation** secures communication between TEE VMs during job execution
4. **Synchronized Processing** allows distributed computation with secure inter-node communication

### System Flow

```
┌─────────────────┐
│ Desktop Client  │
│  (Your Machine) │
└────────┬────────┘
         │
         │ 1. Request Attestation Quotes
         │ 2. Verify with Azure Attestation Service
         │ 3. Submit Job (only if verified)
         │
    ┌────┴────┐
    │         │
┌───▼───┐ ┌──▼────┐
│ SEV   │ │ TDX   │
│  VM   │ │  VM   │
└───┬───┘ └──┬────┘
    │        │
    │ 4. Mutual Attestation
    │ 5. Synchronized HPC Job Execution
    │
    └────────┘
```

## Features

- ✅ **Multi-TEE Support**: Works with both AMD SEV and Intel TDX
- ✅ **Azure Attestation Integration**: Verifies TEE quotes using Azure Attestation Service
- ✅ **Mutual Attestation**: Secure peer-to-peer verification between TEE VMs
- ✅ **Encrypted Communication**: All inter-node sync data is encrypted
- ✅ **Distributed Processing**: Split workloads across multiple TEE nodes
- ✅ **Flexible Node Selection**: Run on SEV only, TDX only, or both
- ✅ **Job Monitoring**: Real-time status tracking and result collection

## Architecture

### Components

#### 1. Desktop Client (`src/client/desktop_client.py`)

**Responsibilities:**
- Initiates HPC job execution
- Verifies attestation quotes from TEE VMs using Azure Attestation Service
- Submits job data to verified VMs
- Monitors job execution across all nodes
- Collects and aggregates results

**Key Methods:**
- `verify_server_attestation()`: Requests and verifies quotes
- `submit_hpc_job()`: Orchestrates job submission
- `monitor_job()`: Tracks job progress

#### 2. TEE Server (`src/server/tee_server.py`)

**Responsibilities:**
- Runs on SEV/TDX VMs
- Generates attestation quotes
- Executes HPC jobs
- Handles mutual attestation with peer nodes
- Synchronizes during job execution

**Key Endpoints:**
- `/attestation/quote`: Generate attestation quote
- `/job/submit`: Accept job submission
- `/mutual-attestation/verify`: Verify peer attestation
- `/sync`: Synchronize during job execution

#### 3. Attestation Module (`src/attestation/`)

**Azure Attestation (`azure_attestation.py`):**
- Integrates with Azure Attestation Service REST API
- Verifies attestation quotes
- Generates nonces for quote requests
- Supports both SEV and TDX quote verification

**Mutual Attestation (`mutual_attestation.py`):**
- Establishes secure sessions between TEE VMs
- Derives session keys from attestation quotes
- Encrypts inter-VM communications
- Manages attestation session lifecycle

#### 4. HPC Job Module (`src/hpc_job/job.py`)

**Responsibilities:**
- Implements distributed computation
- Manages job state and lifecycle
- Handles synchronization points between nodes
- Processes data chunks iteratively
- Establishes mutual attestation during first sync

**Job Lifecycle:**
1. `PENDING` → Job created
2. `RUNNING` → Processing iterations
3. `SYNCING` → Synchronizing with peer (with mutual attestation)
4. `COMPLETED` → Job finished
5. `FAILED` → Error occurred

## Quick Start

### Prerequisites

- Python 3.8+
- Azure Attestation Service instance
- SEV VM and/or TDX VM (or use localhost for testing)

### Installation

```bash
# Clone the repository
git clone https://github.com/dzobbe/confidential-sev-tdx-hpc.git
cd confidential-sev-tdx-hpc

# Install dependencies
pip install -r requirements.txt
```

### Configuration

Create `.env` file in the project root:

```bash
# Azure Attestation Service (only endpoint needed - no authentication required)
AZURE_ATTESTATION_ENDPOINT=https://your-instance.attest.azure.net

# Server URLs
SEV_VM_URL=http://sev-vm-ip:8080
TDX_VM_URL=http://tdx-vm-ip:8080

# Node selection (optional): TDX, SEV, or SEV,TDX (default: SEV,TDX)
ENABLED_NODES=SEV,TDX
```

### Running

**1. Start SEV Server (on SEV VM):**
```bash
export TEE_TYPE=SEV
python -m src.server.tee_server
```

**2. Start TDX Server (on TDX VM):**
```bash
export TEE_TYPE=TDX
python -m src.server.tee_server
```

**3. Run Client (from Desktop):**
```bash
python scripts/run_client.py
```

## Installation

### Step 1: Azure Attestation Service Setup

1. Log into Azure Portal
2. Navigate to "Create a resource"
3. Search for "Attestation"
4. Create a new Attestation instance
5. Note the endpoint URL (format: `https://<name>.attest.azure.net`)

**Note**: Attestation endpoints are public and do not require authentication. Credentials are only needed if you want to manage attestation policies programmatically.

### Step 2: Desktop Client Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Create .env file
cat > .env << EOF
AZURE_ATTESTATION_ENDPOINT=https://your-instance.attest.azure.net
SEV_VM_URL=http://sev-vm-ip:8080
TDX_VM_URL=http://tdx-vm-ip:8080
EOF
```

### Step 3: SEV VM Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Create .env file
cat > .env << EOF
TEE_TYPE=SEV
PORT=8080
SERVER_ID=sev-node-1
AZURE_ATTESTATION_ENDPOINT=https://your-instance.attest.azure.net
EOF

# Verify SEV support
dmesg | grep -i sev

# Start server
./scripts/start_sev_server.sh
```

### Step 4: TDX VM Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Create .env file
cat > .env << EOF
TEE_TYPE=TDX
PORT=8080
SERVER_ID=tdx-node-1
AZURE_ATTESTATION_ENDPOINT=https://your-instance.attest.azure.net
EOF

# Verify TDX support
dmesg | grep -i tdx

# Start server
./scripts/start_tdx_server.sh
```

## Configuration

### Environment Variables

#### Desktop Client

```bash
# Required
AZURE_ATTESTATION_ENDPOINT=https://your-instance.attest.azure.net
SEV_VM_URL=http://sev-vm-ip:8080
TDX_VM_URL=http://tdx-vm-ip:8080

# Optional
ENABLED_NODES=SEV,TDX  # Options: SEV, TDX, or SEV,TDX (default: SEV,TDX)
```

#### TEE Servers (SEV/TDX)

```bash
# Required
TEE_TYPE=SEV  # or TDX
AZURE_ATTESTATION_ENDPOINT=https://your-instance.attest.azure.net

# Optional
PORT=8080
SERVER_ID=node-1
LOG_LEVEL=INFO
```

### Testing with Single Node

To test with TDX only (useful for initial testing):

```bash
# In .env file:
ENABLED_NODES=TDX

# Or programmatically:
from src.client.desktop_client import TEEHPCClient
client = TEEHPCClient(enabled_nodes=['TDX'])
```

## Usage

### Basic Usage

```python
from src.client.desktop_client import TEEHPCClient

# Initialize client
client = TEEHPCClient()

# Submit job
result = client.submit_hpc_job(
    data=[{'value': i} for i in range(100)],
    parameters={'algorithm': 'distributed_sum'},
    max_iterations=50
)

# Monitor execution
if result.get('success'):
    job_id = result['job_id']
    final_status = client.monitor_job(job_id)
    
    if final_status.get('success'):
        print("Job completed successfully!")
        print(f"Results: {final_status.get('results')}")
```

### Using Scripts

```bash
# Run example client
python scripts/run_client.py

# Test setup
python scripts/test_setup.py
```

### Workflow

#### Phase 1: Attestation Verification

```
Desktop Client                    SEV VM              TDX VM              Azure
     |                              |                  |                   |
     |--[1] Request Quote---------->|                  |                   |
     |<--[2] Return Quote-----------|                  |                   |
     |                              |                  |                   |
     |--[3] Verify Quote----------------------------------------------->|
     |<--[4] Verification Result---------------------------------------|
     |                              |                  |                   |
     |--[5] Request Quote------------------------------>|                 |
     |<--[6] Return Quote-------------------------------|                 |
     |                              |                  |                   |
     |--[7] Verify Quote----------------------------------------------->|
     |<--[8] Verification Result---------------------------------------|
```

#### Phase 2: Job Submission and Mutual Attestation

```
Desktop Client                    SEV VM              TDX VM
     |                              |                  |
     |--[1] Submit Job------------->|                  |
     |   (data chunk 1)             |                  |
     |                              |                  |
     |--[2] Submit Job------------------------------->|
     |   (data chunk 2)             |                  |
     |                              |                  |
     |                              |--[3] First Sync->|
     |                              |  (establishes    |
     |                              |   mutual         |
     |                              |   attestation)   |
     |                              |<--[4] Sync-------|
```

#### Phase 3: Job Execution with Synchronization

```
SEV VM                            TDX VM
  |                                 |
  |--[Loop Start]                   |
  |  Process data                    |
  |                                 |
  |--[1] Sync (encrypted)---------->|
  |  (local state)                  |
  |                                 |--[2] Process
  |                                 |  Update state
  |<--[3] Sync (encrypted)----------|
  |  (peer state)                   |
  |                                 |
  |--[Loop End]                     |
```

## Architecture Details

### Data Flow

#### Attestation Verification Phase

1. Client requests attestation quote from each enabled VM (with nonce)
2. VMs generate quotes based on their TEE type (SEV or TDX)
3. Client verifies quotes with Azure Attestation Service
4. Only verified VMs receive job submissions

#### Mutual Attestation Phase (During First Sync)

1. Job on Node A initiates sync → establishes mutual attestation
2. Node A generates local quote and sends to Node B
3. Node B verifies Node A's quote with Azure
4. Node B generates its quote and sends to Node A
5. Node A verifies Node B's quote with Azure
6. Both nodes derive session key from both quotes
7. All subsequent sync data is encrypted with session key

#### Job Execution Phase

1. Client distributes data chunks to enabled VMs
2. Each VM processes its chunk iteratively
3. At each iteration, VMs synchronize (encrypted if mutual attestation established)
4. VMs combine states and continue processing
5. Client monitors and collects final results

### Synchronization Protocol

**Sync Point Structure:**
```python
{
    'job_id': 'uuid',
    'iteration': 42,
    'local_state': {...},
    'local_full_state': {...}
}
```

**Sync Flow:**
1. **Local Processing**: Each VM processes its data chunk
2. **Sync Request**: VM sends local state to peer (encrypted if mutual attestation established)
3. **Peer Processing**: Peer processes and responds
4. **State Update**: Both VMs update their state
5. **Continue**: Proceed to next iteration

## Security Model

### Attestation Chain

1. **Hardware Attestation**: TEE generates quote with hardware measurements
2. **Azure Verification**: Azure Attestation Service validates quote
3. **Client Verification**: Client verifies Azure's validation
4. **Mutual Attestation**: VMs verify each other's quotes during first sync
5. **Encrypted Communication**: All sync data encrypted with session key

### Trust Boundaries

```
┌─────────────────────────────────────────┐
│  Desktop Client (Trusted Initiator)     │
└─────────────────────────────────────────┘
              │
              │ Verified Attestation
              ▼
┌─────────────────────────────────────────┐
│  Azure Attestation Service (Trusted)    │
└─────────────────────────────────────────┘
              │
              │ Validates Quotes
              ▼
┌─────────────────────────────────────────┐
│  SEV/TDX VMs (Trusted Execution)        │
│  - Attestation verified                  │
│  - Mutual attestation established        │
│  - Encrypted communication               │
└─────────────────────────────────────────┘
```

### Security Considerations

#### Important Notes

1. **Mock Attestation Quotes**: The current implementation uses mock quote generation. In production:
   - Use AMD SEV SDK for SEV quotes
   - Use Intel TDX SDK for TDX quotes
   - Implement proper quote format and validation

2. **Azure Attestation API**: The implementation uses REST API calls to Azure Attestation Service:
   - Makes direct HTTP POST requests to attestation endpoints
   - No authentication required - endpoints are public
   - Uses official Azure API endpoints:
     - SEV: `/attest/SevSnpVm?api-version=2022-08-01`
     - TDX: `/attest/TdxVm?api-version=2025-06-01`
   - Reference: https://learn.microsoft.com/en-us/rest/api/attestation/attestation/attest-tdx-vm

3. **Encryption**: The mutual attestation uses simplified encryption. In production:
   - Use authenticated encryption (AES-GCM)
   - Implement proper key derivation
   - Add message authentication codes

4. **Network Security**: Ensure:
   - TLS/HTTPS for all communications
   - Proper firewall rules
   - Network isolation for TEE VMs

## API Reference

### Server Endpoints

#### Health Check
```
GET /health
Response: {
    "status": "healthy",
    "tee_type": "SEV" | "TDX",
    "server_id": "string"
}
```

#### Generate Attestation Quote
```
POST /attestation/quote
Request: {
    "nonce": "<base64_encoded_nonce>"
}
Response: {
    "quote": "<base64_encoded_quote>",
    "tee_type": "SEV" | "TDX",
    "timestamp": "<iso_timestamp>"
}
```

#### Submit HPC Job
```
POST /job/submit
Request: {
    "job_id": "<uuid>",
    "data": [...],
    "parameters": {...},
    "max_iterations": 100,
    "peer_url": "<peer_server_url>"
}
Response: {
    "job_id": "<uuid>",
    "status": "accepted",
    "message": "Job submitted successfully"
}
```

#### Get Job Status
```
GET /job/<job_id>/status
Response: {
    "job_id": "<uuid>",
    "status": "pending" | "running" | "syncing" | "completed" | "failed",
    "current_iteration": 42,
    "max_iterations": 100,
    "results_count": 42,
    "sync_points_count": 42
}
```

#### Get Job Results
```
GET /job/<job_id>/results
Response: {
    "job_id": "<uuid>",
    "results": [...],
    "status": "completed"
}
```

#### Verify Peer Attestation
```
POST /mutual-attestation/verify
Request: {
    "session_id": "<session_id>",
    "tee_type": "SEV" | "TDX",
    "quote": "<base64_encoded_quote>",
    "nonce": "<base64_encoded_nonce>",
    "timestamp": "<iso_timestamp>",
    "action": "attestation_request"
}
Response: {
    "verified": true,
    "session_id": "<session_id>",
    "our_quote": "<base64_encoded_quote>",
    "our_tee_type": "SEV" | "TDX"
}
```

#### Synchronize with Peer
```
POST /sync
Request: {
    "job_id": "<uuid>",
    "iteration": 42,
    "local_state": {...},
    "local_full_state": {...}
}
# OR if encrypted:
{
    "encrypted": "<base64_encoded_encrypted_data>"
}
Response: {
    "success": true,
    "peer_state": {...},
    "combined_result": {...}
}
# OR if encrypted:
{
    "encrypted": "<base64_encoded_encrypted_response>"
}
```

## Troubleshooting

### Attestation Verification Fails

**Symptoms:**
- Client reports "Attestation verification failed"
- Azure API returns error

**Solutions:**
1. Verify Azure Attestation Service endpoint is correct in `.env`
2. Ensure TEE VMs can reach Azure services (network connectivity)
3. Check API version compatibility (currently using 2022-08-01 for SEV, 2025-06-01 for TDX)
4. Verify the attestation endpoint path matches your TEE type
5. Check that the attestation instance is properly configured in Azure Portal
6. Test connectivity: `curl https://your-instance.attest.azure.net`

### Mutual Attestation Fails

**Symptoms:**
- Job hangs during first sync
- Error: "Mutual attestation not established"

**Solutions:**
1. Verify both VMs can reach each other: `ping <peer-ip>`
2. Check firewall rules allow port 8080
3. Ensure both VMs have valid attestation quotes
4. Verify Azure Attestation Service is accessible from both VMs
5. Check server logs for detailed error messages
6. Verify both VMs have correct `peer_url` configuration

### Job Execution Issues

**Symptoms:**
- Job hangs or fails
- Synchronization errors

**Solutions:**
1. Check server logs on both VMs
2. Verify data format matches expected structure
3. Ensure sufficient resources on VMs
4. Check network connectivity between VMs
5. Verify mutual attestation was established (check logs)
6. Review job parameters and max_iterations

### Connection Errors

**Symptoms:**
- Cannot connect to VM
- Connection timeout

**Solutions:**
1. Verify server URLs in `.env` are correct
2. Check servers are running: `curl http://vm-ip:8080/health`
3. Verify network connectivity
4. Check firewall rules
5. Ensure correct port numbers

### Import Errors

**Symptoms:**
- ModuleNotFoundError
- Import errors

**Solutions:**
1. Run `pip install -r requirements.txt`
2. Verify Python version: `python --version` (should be 3.8+)
3. Check virtual environment is activated
4. Verify PYTHONPATH includes project root

## Customization

### Modify HPC Job

Edit `src/hpc_job/job.py` to implement your specific computation:

```python
def _process_iteration(self, iteration: int) -> Dict:
    # Your computation logic here
    result = your_computation(self.data, iteration)
    return result
```

### Adjust Attestation Policy

Modify `src/attestation/azure_attestation.py` to:
- Add specific claim validation
- Check expected measurements
- Verify policy compliance

### Change Synchronization Logic

Edit `_synchronize_with_peer` in `src/hpc_job/job.py` to customize how nodes synchronize.

## Project Structure

```
confidential-sev-tdx-hpc/
├── src/
│   ├── attestation/
│   │   ├── __init__.py
│   │   ├── azure_attestation.py    # Azure Attestation Service integration
│   │   └── mutual_attestation.py   # Mutual attestation protocol
│   ├── client/
│   │   ├── __init__.py
│   │   └── desktop_client.py       # Desktop client application
│   ├── server/
│   │   ├── __init__.py
│   │   └── tee_server.py           # TEE server application
│   └── hpc_job/
│       ├── __init__.py
│       └── job.py                  # HPC job implementation
├── scripts/
│   ├── run_client.py               # Example client script
│   ├── start_sev_server.sh        # SEV server startup script
│   ├── start_tdx_server.sh        # TDX server startup script
│   └── test_setup.py               # Setup verification script
├── .gitignore                      # Git ignore rules
├── config.yaml                     # Configuration file (optional)
├── requirements.txt                # Python dependencies
└── README.md                       # This file
```

## Performance Characteristics

### Latency Components

1. **Attestation**: ~100-500ms per quote verification
2. **Mutual Attestation**: ~200-1000ms (two verifications during first sync)
3. **Job Submission**: ~50-200ms per VM
4. **Synchronization**: ~10-100ms per sync point

### Throughput

- Limited by synchronization frequency
- Network bandwidth between VMs
- Azure Attestation Service rate limits

### Scalability Considerations

**Current Limitations:**
- Two-node configuration (SEV + TDX)
- Synchronous synchronization
- Single job per VM

**Potential Extensions:**
- Multi-node support (N SEV + M TDX nodes)
- Asynchronous synchronization
- Job queuing and scheduling
- Load balancing across nodes

## Production Considerations

### Security Hardening

1. **Use HTTPS/TLS** for all communications
2. **Implement proper authentication** for server endpoints
3. **Use Azure Key Vault** for secrets management
4. **Enable audit logging** for attestation events
5. **Implement rate limiting** on server endpoints

### Performance Optimization

1. **Use connection pooling** for Azure API calls
2. **Implement caching** for attestation results
3. **Optimize synchronization** frequency
4. **Use async/await** for I/O operations

### Monitoring

1. **Set up Azure Monitor** for attestation service
2. **Implement health checks** and alerts
3. **Log all attestation events**
4. **Monitor job execution metrics**

## References

- [Azure Attestation Service Documentation](https://docs.microsoft.com/azure/attestation/)
- [AMD SEV Documentation](https://www.amd.com/en/developer/sev.html)
- [Intel TDX Documentation](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html)
- [Azure Attestation REST API Reference](https://learn.microsoft.com/en-us/rest/api/attestation/)

## License

This project is provided for educational purposes.

## Author

Created for the 2026 Novi Sad Seminar on TEE in HPC.

---

**Repository**: https://github.com/dzobbe/confidential-sev-tdx-hpc
