#!/usr/bin/env python3
"""
Example client script to run HPC job on TEE VMs
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.client.desktop_client import TEEHPCClient


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
        # Initialize client
        # To test with TDX only, set ENABLED_NODES=TDX in .env or pass enabled_nodes=['TDX']
        # Options: ['TDX'], ['SEV'], or ['SEV', 'TDX']
        print("Initializing TEE HPC Client...")
        
        # Check if ENABLED_NODES is set in environment, otherwise use default
        enabled_nodes_env = os.getenv('ENABLED_NODES')
        if enabled_nodes_env:
            enabled_nodes = [n.strip().upper() for n in enabled_nodes_env.split(',')]
            client = TEEHPCClient(enabled_nodes=enabled_nodes)
        else:
            # Default: use both nodes, but can be overridden
            # For TDX-only testing, uncomment the next line:
            # client = TEEHPCClient(enabled_nodes=['TDX'])
            client = TEEHPCClient()
        
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
