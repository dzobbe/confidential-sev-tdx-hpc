# TEE HPC Tutorial: Secure Distributed Computing with SEV and TDX

This tutorial demonstrates how to run High Performance Computing (HPC) jobs on Trusted Execution Environment (TEE) virtual machines using AMD SEV and Intel TDX technologies, with attestation verification through Azure Attestation Service.

## Overview

This project implements a secure distributed HPC system where:

1. **Desktop Client** launches HPC jobs on remote TEE VMs
2. **Attestation Verification** ensures jobs only run on verified TEE environments
3. **Mutual Attestation** secures communication between TEE VMs during job execution
4. **Synchronized Processing** allows distributed computation with secure inter-node communication

## Architecture

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

## Components

### 1. Desktop Client (`src/client/desktop_client.py`)
- Verifies attestation quotes from TEE VMs using Azure Attestation Service
- Submits HPC jobs only after successful attestation
- Monitors job execution across both VMs

### 2. TEE Server (`src/server/tee_server.py`)
- Runs on SEV and TDX VMs
- Generates attestation quotes
- Executes HPC jobs
- Handles mutual attestation with peer nodes
- Synchronizes during job execution

### 3. Attestation Module (`src/attestation/`)
- **Azure Attestation Integration**: Verifies quotes against Azure Attestation Service
- **Mutual Attestation Protocol**: Establishes secure sessions between TEE VMs

### 4. HPC Job Module (`src/hpc_job/`)
- Distributed computation job implementation
- Synchronization points between nodes
- State management and result aggregation

## Prerequisites

### Azure Setup
1. **Azure Attestation Service Instance**
   - Create an Azure Attestation instance
   - Note the endpoint URL (format: `https://<name>.attest.azure.net`)
   - Configure attestation policies for SEV and TDX (optional, for policy management)
   
   **Note**: Attestation endpoints are public and do not require authentication.
   Credentials are only needed if you want to manage attestation policies programmatically.

### TEE VMs
- **SEV VM**: AMD SEV-enabled virtual machine
- **TDX VM**: Intel TDX-enabled virtual machine
- Both VMs should have network connectivity to:
  - Azure Attestation Service
  - Each other (for mutual attestation)
  - Your desktop client

### Python Environment
- Python 3.8 or higher
- pip package manager

## Installation

1. **Clone or navigate to the project directory**

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   
   Create a `.env` file in the project root:
   ```bash
   # Azure Attestation Service (only endpoint needed - no authentication required)
   AZURE_ATTESTATION_ENDPOINT=https://your-instance.attest.azure.net
   
   # Server URLs (for client)
   SEV_VM_URL=http://sev-vm.example.com:8080
   TDX_VM_URL=http://tdx-vm.example.com:8080
   
   # Node selection (optional): TDX, SEV, or SEV,TDX (default: SEV,TDX)
   # To test with TDX only:
   ENABLED_NODES=TDX
   ```

4. **On SEV VM**: Create `.env` with:
   ```bash
   TEE_TYPE=SEV
   PORT=8080
   AZURE_ATTESTATION_ENDPOINT=https://your-instance.attest.azure.net
   ```

5. **On TDX VM**: Create `.env` with:
   ```bash
   TEE_TYPE=TDX
   PORT=8080
   AZURE_ATTESTATION_ENDPOINT=https://your-instance.attest.azure.net
   ```

## Usage

### Step 1: Start TEE Servers

**On SEV VM:**
```bash
chmod +x scripts/start_sev_server.sh
./scripts/start_sev_server.sh
```

**On TDX VM:**
```bash
chmod +x scripts/start_tdx_server.sh
./scripts/start_tdx_server.sh
```

Or run directly with Python:
```bash
# SEV VM
export TEE_TYPE=SEV
python -m src.server.tee_server

# TDX VM
export TEE_TYPE=TDX
python -m src.server.tee_server
```

### Step 2: Run Client from Desktop

```bash
python scripts/run_client.py
```

Or use the client programmatically:
```python
from src.client.desktop_client import TEEHPCClient

client = TEEHPCClient()

# Submit job
result = client.submit_hpc_job(
    data=[{'value': i} for i in range(100)],
    parameters={'algorithm': 'distributed_sum'},
    max_iterations=50
)

# Monitor execution
status = client.monitor_job(result['job_id'])
```

## Workflow

### 1. Attestation Verification Phase

```
Client → SEV VM: Request attestation quote (with nonce)
SEV VM → Client: Return attestation quote
Client → Azure: Verify SEV quote
Azure → Client: Verification result

Client → TDX VM: Request attestation quote (with nonce)
TDX VM → Client: Return attestation quote
Client → Azure: Verify TDX quote
Azure → Client: Verification result
```

### 2. Mutual Attestation Phase

```
SEV VM → TDX VM: Attestation request (quote + session_id)
TDX VM → Azure: Verify SEV quote
TDX VM → SEV VM: Attestation response + TDX quote
SEV VM → Azure: Verify TDX quote
SEV VM → TDX VM: Confirmation
[Session key derived from both quotes]
```

### 3. Job Execution Phase

```
Client → SEV VM: Submit job (data chunk 1)
Client → TDX VM: Submit job (data chunk 2)

[For each iteration:]
SEV VM → Process local data
SEV VM → TDX VM: Sync request (encrypted with session key)
TDX VM → Process local data
TDX VM → SEV VM: Sync response (encrypted)
[Both VMs update state]
```

## API Endpoints

### Server Endpoints

- `GET /health` - Health check
- `POST /attestation/quote` - Generate attestation quote
- `POST /job/submit` - Submit HPC job
- `GET /job/<job_id>/status` - Get job status
- `GET /job/<job_id>/results` - Get job results
- `POST /mutual-attestation/initiate` - Initiate mutual attestation
- `POST /mutual-attestation/verify` - Verify peer attestation
- `POST /sync` - Synchronize with peer during job execution

## Security Considerations

### Important Notes

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

Edit the sync callback in `src/server/tee_server.py` to customize how nodes synchronize.

## Troubleshooting

### Attestation Verification Fails

1. Verify Azure Attestation Service endpoint is correct in `.env`
2. Ensure TEE VMs can reach Azure services (network connectivity)
3. Check API version compatibility (currently using 2022-08-01)
4. Verify the attestation endpoint path matches your TEE type (SevSnpVm, Tpm, etc.)
5. Check that the attestation instance is properly configured in Azure Portal

### Mutual Attestation Fails

1. Verify both VMs can reach each other
2. Check firewall rules allow inter-VM communication
3. Ensure both VMs have valid attestation quotes
4. Verify Azure Attestation Service is accessible from both VMs

### Job Execution Issues

1. Check server logs on both VMs
2. Verify data format matches expected structure
3. Ensure sufficient resources on VMs
4. Check network connectivity between VMs

## Project Structure

```
tutorial/
├── src/
│   ├── attestation/
│   │   ├── azure_attestation.py    # Azure Attestation Service integration
│   │   └── mutual_attestation.py   # Mutual attestation protocol
│   ├── client/
│   │   └── desktop_client.py       # Desktop client application
│   ├── server/
│   │   └── tee_server.py           # TEE server application
│   └── hpc_job/
│       └── job.py                  # HPC job implementation
├── scripts/
│   ├── start_sev_server.sh         # SEV server startup script
│   ├── start_tdx_server.sh         # TDX server startup script
│   └── run_client.py               # Example client script
├── config.yaml                     # Configuration file
├── requirements.txt                # Python dependencies
└── README.md                       # This file
```

## References

- [Azure Attestation Service Documentation](https://docs.microsoft.com/azure/attestation/)
- [AMD SEV Documentation](https://www.amd.com/en/developer/sev.html)
- [Intel TDX Documentation](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html)

## License

This tutorial is provided for educational purposes.

## Author

Created for the 2026 Novi Sad Seminar on TEE in HPC.
