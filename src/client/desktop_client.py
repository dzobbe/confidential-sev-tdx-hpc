"""
Desktop Client Application
Launches HPC jobs on TEE VMs after verifying attestation quotes
"""

import os
import json
import base64
import uuid
import time
import requests
from typing import Dict, List, Optional, Tuple
from dotenv import load_dotenv

from src.attestation.azure_attestation import AzureAttestationVerifier

load_dotenv()


class TEEHPCClient:
    """Desktop client for launching HPC jobs on TEE VMs"""
    
    def __init__(self, enabled_nodes: Optional[List[str]] = None):
        """
        Initialize client with Azure Attestation Service configuration
        
        Args:
            enabled_nodes: List of nodes to use. Options: ['SEV'], ['TDX'], or ['SEV', 'TDX'].
                          If None, reads from ENABLED_NODES env var or defaults to ['SEV', 'TDX']
        """
        azure_endpoint = os.getenv('AZURE_ATTESTATION_ENDPOINT')
        
        if not azure_endpoint:
            raise ValueError("AZURE_ATTESTATION_ENDPOINT not set")
        
        # No authentication required - Azure Attestation Service endpoints are public
        self.verifier = AzureAttestationVerifier(endpoint=azure_endpoint)
        
        self.sev_server_url = os.getenv('SEV_VM_URL', 'http://sev-vm.example.com:8080')
        self.tdx_server_url = os.getenv('TDX_VM_URL', 'http://tdx-vm.example.com:8080')
        
        # Determine which nodes to use
        if enabled_nodes is None:
            env_nodes = os.getenv('ENABLED_NODES', 'SEV,TDX')
            enabled_nodes = [n.strip().upper() for n in env_nodes.split(',') if n.strip()]
        
        # Validate and set enabled nodes
        valid_nodes = {'SEV', 'TDX'}
        enabled_nodes = [n.upper() for n in enabled_nodes if n.upper() in valid_nodes]
        
        if not enabled_nodes:
            raise ValueError("At least one node type must be enabled (SEV or TDX)")
        
        self.enabled_nodes = enabled_nodes
        print(f"Initialized client with enabled nodes: {', '.join(self.enabled_nodes)}")
    
    def verify_server_attestation(self, server_url: str, tee_type: str) -> Tuple[bool, Dict]:
        """
        Request and verify attestation quote from server
        
        Args:
            server_url: Server URL
            tee_type: Expected TEE type ('SEV' or 'TDX')
            
        Returns:
            Tuple of (is_valid, verification_result)
        """
        try:
            # Generate nonce
            nonce = self.verifier.generate_nonce()
            
            # Request quote from server
            response = requests.post(
                f"{server_url}/attestation/quote",
                json={'nonce': base64.b64encode(nonce).decode()},
                timeout=30
            )
            
            if response.status_code != 200:
                return False, {'error': f'Server returned status {response.status_code}'}
            
            quote_data = response.json()
            quote_b64 = quote_data.get('quote')
            server_tee_type = quote_data.get('tee_type')
            
            if not quote_b64:
                return False, {'error': 'No quote in server response'}
            
            if server_tee_type != tee_type:
                return False, {'error': f'TEE type mismatch: expected {tee_type}, got {server_tee_type}'}
            
            # Decode and verify quote
            quote = base64.b64decode(quote_b64)
            is_valid, result = self.verifier.verify_quote(quote, tee_type, nonce)
            
            return is_valid, result
            
        except Exception as e:
            return False, {'error': str(e)}
    
    def submit_hpc_job(self, data: List[Dict], parameters: Dict, 
                      max_iterations: int = 100) -> Dict:
        """
        Submit HPC job to enabled TEE VMs after verifying attestation
        
        Args:
            data: Job data (will be split between enabled nodes)
            parameters: Job parameters
            max_iterations: Maximum iterations
            
        Returns:
            Job submission result
        """
        job_id = str(uuid.uuid4())
        
        print(f"Submitting HPC job {job_id}...")
        print(f"Enabled nodes: {', '.join(self.enabled_nodes)}")
        
        # Step 1: Verify attestation for enabled servers
        print("\n[Step 1] Verifying attestation quotes...")
        
        sev_valid = True
        tdx_valid = True
        sev_result = {}
        tdx_result = {}
        
        if 'SEV' in self.enabled_nodes:
            sev_valid, sev_result = self.verify_server_attestation(self.sev_server_url, 'SEV')
            if not sev_valid:
                return {
                    'success': False,
                    'error': f'SEV attestation verification failed: {sev_result.get("error")}',
                    'job_id': job_id
                }
            print("✓ SEV attestation verified")
        
        if 'TDX' in self.enabled_nodes:
            tdx_valid, tdx_result = self.verify_server_attestation(self.tdx_server_url, 'TDX')
            if not tdx_valid:
                return {
                    'success': False,
                    'error': f'TDX attestation verification failed: {tdx_result.get("error")}',
                    'job_id': job_id
                }
            print("✓ TDX attestation verified")
        
        # Step 2: Split data between enabled nodes
        print("\n[Step 2] Distributing data to nodes...")
        node_data = {}
        
        if len(self.enabled_nodes) == 1:
            # Single node - use all data
            node_data[self.enabled_nodes[0]] = data
            print(f"  {self.enabled_nodes[0]} node: {len(data)} chunks (all data)")
        else:
            # Multiple nodes - split data
            chunks_per_node = len(data) // len(self.enabled_nodes)
            start_idx = 0
            
            for i, node_type in enumerate(self.enabled_nodes):
                if i == len(self.enabled_nodes) - 1:
                    # Last node gets remaining data
                    node_data[node_type] = data[start_idx:]
                else:
                    node_data[node_type] = data[start_idx:start_idx + chunks_per_node]
                    start_idx += chunks_per_node
                print(f"  {node_type} node: {len(node_data[node_type])} chunks")
        
        # Step 3: Submit jobs to enabled servers
        print("\n[Step 3] Submitting jobs to TEE VMs...")
        
        job_results = {}
        
        # Submit to each enabled node
        for node_type in self.enabled_nodes:
            server_url = self.sev_server_url if node_type == 'SEV' else self.tdx_server_url
            
            job_result = self._submit_to_server(
                server_url,
                job_id,
                node_data[node_type],
                parameters,
                max_iterations
            )
            
            job_results[node_type] = job_result
            
            if not job_result.get('success'):
                return {
                    'success': False,
                    'error': f'Failed to submit job to {node_type} server',
                    'job_results': job_results,
                    'job_id': job_id
                }
            
            print(f"✓ {node_type} job submitted successfully")
        
        return {
            'success': True,
            'job_id': job_id,
            'job_results': job_results,
            'enabled_nodes': self.enabled_nodes,
            'message': f'HPC job submitted and running on {len(self.enabled_nodes)} TEE VM(s)'
        }
    
    def _submit_to_server(self, server_url: str, job_id: str, data: List[Dict],
                          parameters: Dict, max_iterations: int) -> Dict:
        """
        Submit job to a specific server
        
        Args:
            server_url: Server URL
            job_id: Job identifier
            data: Job data
            parameters: Job parameters
            max_iterations: Maximum iterations
            
        Returns:
            Submission result
        """
        try:
            response = requests.post(
                f"{server_url}/job/submit",
                json={
                    'job_id': job_id,
                    'data': data,
                    'parameters': parameters,
                    'max_iterations': max_iterations
                },
                timeout=30
            )
            
            if response.status_code == 200:
                return {'success': True, 'result': response.json()}
            else:
                return {'success': False, 'error': f'Status {response.status_code}: {response.text}'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def monitor_job(self, job_id: str, interval: float = 2.0, max_wait: float = 300.0) -> Dict:
        """
        Monitor job execution on enabled servers
        
        Args:
            job_id: Job identifier
            interval: Polling interval in seconds
            max_wait: Maximum wait time in seconds
            
        Returns:
            Final job status
        """
        start_time = time.time()
        
        print(f"\nMonitoring job {job_id}...")
        print(f"Enabled nodes: {', '.join(self.enabled_nodes)}")
        
        while time.time() - start_time < max_wait:
            node_statuses = {}
            
            # Check each enabled node
            for node_type in self.enabled_nodes:
                server_url = self.sev_server_url if node_type == 'SEV' else self.tdx_server_url
                try:
                    response = requests.get(
                        f"{server_url}/job/{job_id}/status",
                        timeout=10
                    )
                    node_statuses[node_type] = response.json() if response.status_code == 200 else None
                except:
                    node_statuses[node_type] = None
            
            # Display status for all enabled nodes
            all_statuses_valid = all(node_statuses.values())
            if all_statuses_valid:
                status_lines = []
                all_completed = True
                any_failed = False
                
                for node_type in self.enabled_nodes:
                    status = node_statuses[node_type]
                    job_status = status.get('status')
                    current_iter = status.get('current_iteration', 0)
                    max_iter = status.get('max_iterations', 0)
                    status_lines.append(f"  {node_type}: {job_status} (iter {current_iter}/{max_iter})")
                    
                    if job_status != 'completed':
                        all_completed = False
                    if job_status == 'failed':
                        any_failed = True
                
                print('\n'.join(status_lines))
                
                # Check if all completed
                if all_completed:
                    print(f"\n✓ Job completed on all {len(self.enabled_nodes)} node(s)!")
                    
                    # Get results from all nodes
                    results = {}
                    for node_type in self.enabled_nodes:
                        server_url = self.sev_server_url if node_type == 'SEV' else self.tdx_server_url
                        results[node_type] = self._get_job_results(server_url, job_id)
                    
                    return {
                        'success': True,
                        'job_id': job_id,
                        'node_statuses': node_statuses,
                        'results': results,
                        'enabled_nodes': self.enabled_nodes
                    }
                
                # Check if any failed
                if any_failed:
                    return {
                        'success': False,
                        'error': 'Job failed on one or more nodes',
                        'node_statuses': node_statuses,
                        'enabled_nodes': self.enabled_nodes
                    }
            
            time.sleep(interval)
        
        return {
            'success': False,
            'error': 'Monitoring timeout',
            'job_id': job_id,
            'enabled_nodes': self.enabled_nodes
        }
    
    def _get_job_results(self, server_url: str, job_id: str) -> Optional[Dict]:
        """Get job results from server"""
        try:
            response = requests.get(
                f"{server_url}/job/{job_id}/results",
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return None


def main():
    """Example usage of the client"""
    import sys
    
    # Example data
    sample_data = [
        {'value': i, 'data': f'chunk_{i}'} for i in range(100)
    ]
    
    parameters = {
        'algorithm': 'distributed_sum',
        'precision': 'float64'
    }
    
    try:
        # Initialize client with enabled nodes
        # Can be set via ENABLED_NODES env var (e.g., "TDX" or "SEV,TDX")
        # Or pass directly: TEEHPCClient(enabled_nodes=['TDX'])
        client = TEEHPCClient()
        
        # Submit job
        result = client.submit_hpc_job(
            data=sample_data,
            parameters=parameters,
            max_iterations=10
        )
        
        if result.get('success'):
            job_id = result['job_id']
            print(f"\n✓ Job submitted successfully: {job_id}")
            
            # Monitor job
            final_status = client.monitor_job(job_id)
            
            if final_status.get('success'):
                print("\n" + "="*60)
                print("Job Execution Summary")
                print("="*60)
                print(f"Job ID: {job_id}")
                print(f"Enabled nodes: {', '.join(client.enabled_nodes)}")
                
                results = final_status.get('results', {})
                for node_type in client.enabled_nodes:
                    node_results = results.get(node_type, {})
                    print(f"\n{node_type} Node Results:")
                    print(f"  Status: {node_results.get('status', 'unknown')}")
                    print(f"  Results count: {len(node_results.get('results', []))}")
            else:
                print(f"\n✗ Job monitoring failed: {final_status.get('error')}")
                sys.exit(1)
        else:
            print(f"\n✗ Job submission failed: {result.get('error')}")
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
