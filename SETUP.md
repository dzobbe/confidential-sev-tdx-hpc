# Setup Guide for TEE HPC Tutorial

This guide provides step-by-step instructions for setting up the TEE HPC tutorial environment.

## Prerequisites Checklist

- [ ] Azure subscription with access to Attestation Service
- [ ] SEV-enabled VM (AMD EPYC processor)
- [ ] TDX-enabled VM (Intel Xeon processor)
- [ ] Python 3.8+ installed on all machines
- [ ] Network connectivity between:
  - Desktop client ↔ SEV VM
  - Desktop client ↔ TDX VM
  - SEV VM ↔ TDX VM
  - All machines ↔ Azure Attestation Service

## Step 1: Azure Attestation Service Setup

### 1.1 Create Attestation Instance

1. Log into Azure Portal
2. Navigate to "Create a resource"
3. Search for "Attestation"
4. Create a new Attestation instance
5. Note the endpoint URL (format: `https://<name>.attest.azure.net`)

### 1.2 Configure Attestation Policies (Optional)

**Note**: Attestation endpoints are public and do not require authentication.
Service principals are only needed if you want to manage attestation policies programmatically.

If you need to manage policies programmatically, create a service principal:
```bash
az ad sp create-for-rbac --name "tee-hpc-attestation" \
  --role "Attestation Contributor" \
  --scopes /subscriptions/<subscription-id>/resourceGroups/<resource-group>
```

Configure policies for SEV and TDX attestation types in Azure Portal (or via API if you have credentials).

Configure policies for SEV and TDX attestation types in Azure Portal.

## Step 2: Desktop Client Setup

### 2.1 Install Dependencies

```bash
cd tutorial
pip install -r requirements.txt
```

### 2.2 Configure Environment

Create `.env` file:

```bash
# Azure Attestation Service (only endpoint needed - no authentication required)
AZURE_ATTESTATION_ENDPOINT=https://your-instance.attest.azure.net

# TEE VM URLs
SEV_VM_URL=http://sev-vm-ip:8080
TDX_VM_URL=http://tdx-vm-ip:8080
```

### 2.3 Test Connection

```bash
# Test SEV VM connection
curl http://sev-vm-ip:8080/health

# Test TDX VM connection
curl http://tdx-vm-ip:8080/health
```

## Step 3: SEV VM Setup

### 3.1 Install Dependencies

```bash
# On SEV VM
cd tutorial
pip install -r requirements.txt
```

### 3.2 Configure Environment

Create `.env` file:

```bash
TEE_TYPE=SEV
PORT=8080
SERVER_ID=sev-node-1

# Azure Attestation Service (only endpoint needed - no authentication required)
AZURE_ATTESTATION_ENDPOINT=https://your-instance.attest.azure.net
```

### 3.3 Verify SEV Support

```bash
# Check SEV support
dmesg | grep -i sev
# Should show SEV initialization messages
```

### 3.4 Start Server

```bash
./scripts/start_sev_server.sh
```

Or:

```bash
export TEE_TYPE=SEV
python -m src.server.tee_server
```

## Step 4: TDX VM Setup

### 4.1 Install Dependencies

```bash
# On TDX VM
cd tutorial
pip install -r requirements.txt
```

### 4.2 Configure Environment

Create `.env` file:

```bash
TEE_TYPE=TDX
PORT=8080
SERVER_ID=tdx-node-1

# Azure Attestation Service (only endpoint needed - no authentication required)
AZURE_ATTESTATION_ENDPOINT=https://your-instance.attest.azure.net
```

### 4.3 Verify TDX Support

```bash
# Check TDX support
dmesg | grep -i tdx
# Should show TDX initialization messages
```

### 4.4 Start Server

```bash
./scripts/start_tdx_server.sh
```

Or:

```bash
export TEE_TYPE=TDX
python -m src.server.tee_server
```

## Step 5: Verify Setup

### 5.1 Test Attestation Quote Generation

From desktop client:

```python
from src.client.desktop_client import TEEHPCClient

client = TEEHPCClient()

# Test SEV attestation
sev_valid, sev_result = client.verify_server_attestation(
    client.sev_server_url, 'SEV'
)
print(f"SEV Attestation: {sev_valid}")

# Test TDX attestation
tdx_valid, tdx_result = client.verify_server_attestation(
    client.tdx_server_url, 'TDX'
)
print(f"TDX Attestation: {tdx_valid}")
```

### 5.2 Run Example Job

```bash
python scripts/run_client.py
```

## Troubleshooting

### Issue: Cannot connect to Azure Attestation Service

**Solution:**
- Verify network connectivity: `curl https://your-instance.attest.azure.net`
- Check Azure endpoint URL in `.env` is correct
- Verify the attestation instance exists and is running
- Check firewall rules allow outbound HTTPS connections

### Issue: Attestation quote generation fails

**Solution:**
- Ensure TEE is properly initialized on VM
- Check TEE SDK is installed (for production)
- Verify TEE type matches VM hardware
- Review server logs for errors

### Issue: Mutual attestation fails

**Solution:**
- Verify both VMs can reach each other: `ping <peer-ip>`
- Check firewall rules allow port 8080
- Ensure both VMs have valid attestation quotes
- Verify Azure Attestation Service is accessible from both VMs

### Issue: Job execution hangs

**Solution:**
- Check server logs on both VMs
- Verify synchronization endpoint is accessible
- Check network connectivity between VMs
- Review job parameters and data format

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

## Next Steps

1. Review the main [README.md](README.md) for usage instructions
2. Customize the HPC job implementation for your use case
3. Integrate with your existing HPC infrastructure
4. Implement production-grade security measures
