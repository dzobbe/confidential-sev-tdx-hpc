# Architecture Overview

## System Components

### 1. Desktop Client (`src/client/desktop_client.py`)

**Responsibilities:**
- Initiates HPC job execution
- Verifies attestation quotes from TEE VMs
- Submits job data to verified VMs
- Monitors job execution
- Collects and aggregates results

**Key Methods:**
- `verify_server_attestation()`: Requests and verifies quotes
- `submit_hpc_job()`: Orchestrates job submission
- `monitor_job()`: Tracks job progress

### 2. TEE Server (`src/server/tee_server.py`)

**Responsibilities:**
- Runs on SEV/TDX VMs
- Generates attestation quotes
- Executes HPC jobs
- Handles mutual attestation
- Synchronizes with peer nodes

**Key Endpoints:**
- `/attestation/quote`: Generate attestation quote
- `/job/submit`: Accept job submission
- `/mutual-attestation/*`: Handle mutual attestation
- `/sync`: Synchronize during job execution

### 3. Attestation Module (`src/attestation/`)

#### Azure Attestation (`azure_attestation.py`)
- Integrates with Azure Attestation Service
- Verifies attestation quotes
- Generates nonces for quote requests

#### Mutual Attestation (`mutual_attestation.py`)
- Establishes secure sessions between TEE VMs
- Derives session keys from attestation quotes
- Encrypts inter-VM communications

### 4. HPC Job Module (`src/hpc_job/job.py`)

**Responsibilities:**
- Implements distributed computation
- Manages job state
- Handles synchronization points
- Processes data chunks

**Job Lifecycle:**
1. PENDING → Job created
2. RUNNING → Processing iterations
3. SYNCING → Synchronizing with peer
4. COMPLETED → Job finished
5. FAILED → Error occurred

## Data Flow

### Phase 1: Attestation Verification

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

### Phase 2: Mutual Attestation

```
SEV VM                            TDX VM              Azure
  |                                 |                   |
  |--[1] Attestation Request------->|                   |
  |   (SEV quote + session_id)      |                   |
  |                                 |--[2] Verify SEV-->|
  |                                 |<--[3] Result------|
  |<--[4] Attestation Response------|                   |
  |   (TDX quote)                   |                   |
  |--[5] Verify TDX------------------------------------>|
  |<--[6] Verification Result---------------------------|
  |                                 |                   |
  |--[7] Confirmation-------------->|                   |
  |   [Session key derived]         |                   |
```

### Phase 3: Job Execution

```
Desktop Client                    SEV VM              TDX VM
     |                              |                  |
     |--[1] Submit Job------------->|                  |
     |   (data chunk 1)             |                  |
     |                              |                  |
     |--[2] Submit Job------------------------------->|
     |   (data chunk 2)             |                  |
     |                              |                  |
     |                              |--[Loop Start]    |
     |                              |  Process data    |
     |                              |                  |
     |                              |--[3] Sync------->|
     |                              |  (encrypted)     |
     |                              |<--[4] Sync-------|
     |                              |  (encrypted)     |
     |                              |                  |
     |<--[5] Status Update----------|                  |
     |<--[6] Status Update----------------------------|
     |                              |                  |
     |                              |--[Loop End]      |
     |                              |                  |
     |--[7] Get Results------------->|                  |
     |--[8] Get Results------------------------------->|
```

## Security Model

### Attestation Chain

1. **Hardware Attestation**: TEE generates quote with hardware measurements
2. **Azure Verification**: Azure Attestation Service validates quote
3. **Client Verification**: Client verifies Azure's validation
4. **Mutual Attestation**: VMs verify each other's quotes

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

## Synchronization Protocol

### Sync Point Structure

```python
{
    'job_id': 'uuid',
    'iteration': 42,
    'local_state': {...},
    'local_full_state': {...}
}
```

### Sync Flow

1. **Local Processing**: Each VM processes its data chunk
2. **Sync Request**: VM sends local state to peer (encrypted)
3. **Peer Processing**: Peer processes and responds
4. **State Update**: Both VMs update their state
5. **Continue**: Proceed to next iteration

## Error Handling

### Attestation Failures
- **Quote Generation Fails**: Server returns error, client rejects
- **Azure Verification Fails**: Client aborts job submission
- **Mutual Attestation Fails**: Job not started

### Job Execution Failures
- **Sync Failure**: Job marked as failed
- **Network Error**: Retry with exponential backoff
- **Processing Error**: Job status updated, error logged

## Scalability Considerations

### Current Limitations
- Two-node configuration (SEV + TDX)
- Synchronous synchronization
- Single job per VM

### Potential Extensions
- Multi-node support (N SEV + M TDX nodes)
- Asynchronous synchronization
- Job queuing and scheduling
- Load balancing across nodes

## Performance Characteristics

### Latency Components
1. **Attestation**: ~100-500ms per quote verification
2. **Mutual Attestation**: ~200-1000ms (two verifications)
3. **Job Submission**: ~50-200ms per VM
4. **Synchronization**: ~10-100ms per sync point

### Throughput
- Limited by synchronization frequency
- Network bandwidth between VMs
- Azure Attestation Service rate limits

## Monitoring Points

1. **Attestation Success Rate**: Track verification failures
2. **Job Completion Time**: Measure end-to-end execution
3. **Sync Latency**: Monitor synchronization overhead
4. **Error Rates**: Track failures by type

## Future Enhancements

1. **Batch Attestation**: Verify multiple quotes in parallel
2. **Attestation Caching**: Cache verified quotes
3. **Adaptive Sync**: Adjust sync frequency based on load
4. **Fault Tolerance**: Handle VM failures gracefully
5. **Performance Metrics**: Detailed telemetry collection
