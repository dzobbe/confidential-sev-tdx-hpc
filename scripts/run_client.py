#!/usr/bin/env python3
"""
Example client script to run HPC job on TEE VMs
"""

import sys
import os
import subprocess
from urllib.parse import urlparse

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.client.desktop_client import TEEHPCClient


def extract_hostname_from_url(url: str) -> str:
    """Extract hostname from URL (e.g., http://hostname:8080 -> hostname)"""
    parsed = urlparse(url)
    return parsed.hostname or url.split('://')[1].split(':')[0].split('/')[0]


def start_server_on_remote_node(node_type: str, hostname: str, ssh_user: str = None) -> bool:
    """
    Start server on remote node via SSH
    
    Args:
        node_type: Node type ('SEV' or 'TDX')
        hostname: Remote hostname or IP
        ssh_user: SSH username (optional, defaults to current user or from env)
    
    Returns:
        True if successful, False otherwise
    """
    # Get SSH user from environment or use default
    if ssh_user is None:
        ssh_user = os.getenv(f'{node_type}_VM_SSH_USER') or os.getenv('SSH_USER') or os.getenv('USER')
    
    # Build SSH command
    ssh_target = f"{ssh_user}@{hostname}" if ssh_user else hostname
    
    # Determine which start script to use based on node type
    start_script = "./scripts/start_server.sh"
    
    # Commands to run on remote node:
    # 1. Navigate to directory
    # 2. Pull from main
    # 3. Start server in background
    # We chain cd and git pull, then start server in background
    combined_command = (
        "cd ~/novisad-seminar/confidential-sev-tdx-hpc && "
        "git pull origin main && "
        f"nohup {start_script} > /dev/null 2>&1 &"
    )
    
    print(f"\n[{node_type}] Starting server on remote node {hostname}...")
    print(f"  SSH target: {ssh_target}")
    print(f"  Directory: ~/novisad-seminar/confidential-sev-tdx-hpc")
    print(f"  Commands: cd, git pull origin main, start server in background")
    
    try:
        # Build SSH command
        ssh_command = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",  # Skip host key checking for automation
            "-o", "ConnectTimeout=10",
            ssh_target,
            combined_command
        ]
        
        result = subprocess.run(
            ssh_command,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            print(f"✓ [{node_type}] Server startup command executed successfully")
            return True
        else:
            print(f"✗ [{node_type}] Failed to start server: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"✗ [{node_type}] SSH connection timeout")
        return False
    except Exception as e:
        print(f"✗ [{node_type}] Error starting server: {e}")
        return False


def start_servers_on_enabled_nodes(enabled_nodes: list) -> bool:
    """
    Start servers on all enabled remote nodes
    
    Args:
        enabled_nodes: List of enabled node types (e.g., ['SEV', 'TDX'])
    
    Returns:
        True if all servers started successfully, False otherwise
    """
    sev_url = os.getenv('SEV_VM_URL', 'http://sev-vm.example.com:8080')
    tdx_url = os.getenv('TDX_VM_URL', 'http://tdx-vm.example.com:8080')
    
    results = []
    
    for node_type in enabled_nodes:
        url = sev_url if node_type == 'SEV' else tdx_url
        hostname = extract_hostname_from_url(url)
        
        success = start_server_on_remote_node(node_type, hostname)
        results.append(success)
    
    return all(results)


def main():
    """Run example HPC job"""
    
    # Sample HPC job data
    # In a real scenario, this would be your actual computation data
    sample_data = [
        {'value': i * 10, 'data': f'computation_chunk_{i}', 'metadata': {'index': i}}
        for i in range(200)
    ]
    
    # Job parameters
    parameters = {
        'algorithm': 'distributed_sum',
        'precision': 'float64',
        'sync_mode': 'mutual_attestation'
    }
    
    print("="*70)
    print("TEE HPC Tutorial - Client Example")
    print("="*70)
    print("\nThis example will:")
    print("  1. Verify attestation quotes from SEV and TDX VMs")
    print("  2. Establish mutual attestation between VMs")
    print("  3. Submit HPC job to both VMs")
    print("  4. Monitor job execution")
    print("\n" + "="*70 + "\n")
    
    try:
        # Determine enabled nodes first
        enabled_nodes_env = os.getenv('ENABLED_NODES')
        if enabled_nodes_env:
            enabled_nodes = [n.strip().upper() for n in enabled_nodes_env.split(',')]
        else:
            # Default: use both nodes
            enabled_nodes = ['SEV', 'TDX']
        
        # Validate enabled nodes
        valid_nodes = {'SEV', 'TDX'}
        enabled_nodes = [n.upper() for n in enabled_nodes if n.upper() in valid_nodes]
        
        if not enabled_nodes:
            print("✗ Error: At least one node type must be enabled (SEV or TDX)")
            sys.exit(1)
        
        # Start servers on enabled remote nodes
        print("="*70)
        print("Starting servers on enabled remote nodes...")
        print("="*70)
        
        if not start_servers_on_enabled_nodes(enabled_nodes):
            print("\n⚠ Warning: Some servers may not have started successfully")
            print("  Continuing anyway - servers may already be running...\n")
        else:
            print("\n✓ All servers started successfully\n")
        
        # Wait a moment for servers to initialize
        import time
        print("Waiting for servers to initialize...")
        time.sleep(3)
        print("✓ Ready to proceed\n")
        
        # Initialize client
        # To test with TDX only, set ENABLED_NODES=TDX in .env or pass enabled_nodes=['TDX']
        # Options: ['TDX'], ['SEV'], or ['SEV', 'TDX']
        print("Initializing TEE HPC Client...")
        client = TEEHPCClient(enabled_nodes=enabled_nodes)
        
        print("✓ Client initialized\n")
        
        # Submit job
        print("Submitting HPC job...")
        result = client.submit_hpc_job(
            data=sample_data,
            parameters=parameters,
            max_iterations=20
        )
        
        if not result.get('success'):
            print(f"\n✗ Job submission failed: {result.get('error')}")
            sys.exit(1)
        
        job_id = result['job_id']
        print(f"\n✓ Job submitted successfully!")
        print(f"  Job ID: {job_id}\n")
        
        # Monitor job execution
        print("Monitoring job execution...")
        print("-" * 70)
        final_status = client.monitor_job(job_id, interval=2.0, max_wait=600.0)
        
        if final_status.get('success'):
            print("\n" + "="*70)
            print("Job Execution Completed Successfully!")
            print("="*70)
            
            results = final_status.get('results', {})
            enabled_nodes = client.enabled_nodes
            
            print(f"\nJob ID: {job_id}")
            print(f"Enabled nodes: {', '.join(enabled_nodes)}")
            
            for node_type in enabled_nodes:
                node_results = results.get(node_type, {})
                print(f"\n{node_type} Node:")
                print(f"  Status: {node_results.get('status', 'unknown')}")
                print(f"  Results: {len(node_results.get('results', []))} iterations")
                if node_results.get('results'):
                    last_result = node_results['results'][-1]
                    print(f"  Final iteration: {last_result.get('iteration', 'N/A')}")
            
            print("\n" + "="*70)
            print("✓ Tutorial completed successfully!")
            print("="*70)
            
        else:
            print(f"\n✗ Job execution failed: {final_status.get('error')}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
