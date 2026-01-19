"""
HPC Job Implementation
Simple computation job that processes data in iterations
"""

import json
import time
import threading
import logging
import requests
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

# Import attestation components
try:
    from src.attestation.azure_attestation import AttestationQuoteGenerator
except ImportError:
    # Handle case where imports might fail during testing
    AttestationQuoteGenerator = None

# Set up logger for this module
logger = logging.getLogger(__name__)


class JobStatus(Enum):
    """Job status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class JobData:
    """Job data structure"""
    job_id: str
    data_chunks: List[Dict]
    parameters: Dict
    status: JobStatus
    current_iteration: int
    max_iterations: int
    results: List[Dict]


class HPCJob:
    """
    Simple HPC job that processes data in iterations
    """
    
    def __init__(self, job_id: str, data: List[Dict], parameters: Dict,
                 max_iterations: int = 100, 
                 tee_type: Optional[str] = None,
                 azure_verifier: Optional[object] = None,
                 quote_generator: Optional[object] = None,
                 node_id: Optional[str] = None,
                 total_nodes: int = 1,
                 other_node_urls: Optional[List[str]] = None,
                 sync_enabled: bool = True):
        """
        Initialize HPC job
        
        Args:
            job_id: Unique job identifier
            data: Input data chunks to process (partitioned data for this node)
            parameters: Job parameters
            max_iterations: Maximum number of iterations
            tee_type: Type of TEE ('SEV' or 'TDX')
            azure_verifier: AzureAttestationVerifier instance
            quote_generator: AttestationQuoteGenerator for generating local quotes
            node_id: Identifier for this node (e.g., 'SEV', 'TDX', or custom ID)
            total_nodes: Total number of nodes participating in this job
            other_node_urls: List of URLs for other nodes to sync with
            sync_enabled: Whether to enable synchronization between nodes
        """
        self.job_id = job_id
        self.data = data
        self.parameters = parameters
        self.max_iterations = max_iterations
        self.tee_type = tee_type
        self.azure_verifier = azure_verifier
        self.quote_generator = quote_generator
        
        # Multi-node configuration
        self.node_id = node_id or tee_type or 'node_0'
        self.total_nodes = total_nodes
        self.other_node_urls = other_node_urls or []
        self.sync_enabled = sync_enabled and total_nodes > 1
        
        self.status = JobStatus.PENDING
        self.current_iteration = 0
        self.results = []
        self.local_state = {}
        self.synced_state = {}  # State received from other nodes
        self.lock = threading.Lock()
        
        logger.info(f"Job {self.job_id} initialized on node {self.node_id} "
                   f"(total_nodes={self.total_nodes}, sync_enabled={self.sync_enabled})")
    
    def run(self):
        """Execute the HPC job with multi-node synchronization"""
        logger.info(f"Starting job execution: {self.job_id} on node {self.node_id}")
        self.status = JobStatus.RUNNING
        
        try:
            for iteration in range(self.max_iterations):
                self.current_iteration = iteration
                logger.debug(f"Job {self.job_id} [{self.node_id}]: Processing iteration {iteration}/{self.max_iterations}")
                
                # Process local data chunk
                iteration_result = self._process_iteration(iteration)
                
                # Synchronize with other nodes if multi-node execution
                if self.sync_enabled:
                    sync_result = self._sync_with_other_nodes(iteration, iteration_result)
                    if sync_result:
                        # Merge synced data into result
                        iteration_result['synced_data'] = sync_result
                        iteration_result['global_sum'] = sync_result.get('global_sum', iteration_result.get('local_sum', 0))
                        logger.debug(f"Job {self.job_id} [{self.node_id}]: Synced with other nodes, global_sum={iteration_result.get('global_sum')}")
                
                logger.debug(f"Job {self.job_id} [{self.node_id}]: Iteration {iteration} processed, result: {iteration_result}")
                
                self.results.append({
                    'iteration': iteration,
                    'result': iteration_result,
                    'timestamp': time.time(),
                    'node_id': self.node_id
                })
                
                self.status = JobStatus.RUNNING
                
                # Small delay to simulate computation
                time.sleep(0.1)
            
            logger.info(f"Job {self.job_id} [{self.node_id}]: Completed successfully after {self.max_iterations} iterations")
            self.status = JobStatus.COMPLETED
            
        except Exception as e:
            logger.error(f"Job {self.job_id} [{self.node_id}]: Failed at iteration {self.current_iteration}: {e}")
            logger.exception("Job execution exception details:")
            self.status = JobStatus.FAILED
            raise
    
    def _process_iteration(self, iteration: int) -> Dict:
        """
        Process a single iteration on local partitioned data
        
        Args:
            iteration: Current iteration number
            
        Returns:
            Iteration result with local computation
        """
        # Simple computation: sum of data values with iteration factor
        local_sum = sum(chunk.get('value', 0) for chunk in self.data)
        result = {
            'iteration': iteration,
            'node_id': self.node_id,
            'local_sum': local_sum,
            'data_chunks_count': len(self.data),
            'computed_value': local_sum * (iteration + 1)
        }
        
        # Update local state
        with self.lock:
            self.local_state[f'iter_{iteration}'] = result
        
        return result
    
    def _sync_with_other_nodes(self, iteration: int, local_result: Dict) -> Optional[Dict]:
        """
        Synchronize data with other nodes for the current iteration
        
        Args:
            iteration: Current iteration number
            local_result: Local computation result
            
        Returns:
            Aggregated result from all nodes, or None if sync failed
        """
        if not self.other_node_urls:
            return None
        
        try:
            # Prepare sync data to send
            sync_data = {
                'job_id': self.job_id,
                'iteration': iteration,
                'node_id': self.node_id,
                'local_result': local_result,
                'timestamp': time.time()
            }
            
            # Collect results from other nodes
            other_results = []
            for node_url in self.other_node_urls:
                try:
                    response = requests.post(
                        f"{node_url}/job/{self.job_id}/sync",
                        json=sync_data,
                        timeout=5.0
                    )
                    if response.status_code == 200:
                        node_result = response.json()
                        other_results.append(node_result)
                        logger.debug(f"Synced with node at {node_url}: {node_result.get('node_id')}")
                    else:
                        logger.warning(f"Sync failed with {node_url}: Status {response.status_code}")
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Failed to sync with {node_url}: {e}")
                    # Continue with other nodes even if one fails
            
            # Aggregate results
            if other_results:
                # Calculate global sum across all nodes
                global_sum = local_result.get('local_sum', 0)
                for node_result in other_results:
                    node_local_result = node_result.get('local_result', {})
                    global_sum += node_local_result.get('local_sum', 0)
                
                aggregated = {
                    'global_sum': global_sum,
                    'nodes_participated': len(other_results) + 1,  # +1 for this node
                    'total_nodes': self.total_nodes,
                    'other_node_results': other_results
                }
                
                # Store synced state
                with self.lock:
                    self.synced_state[f'iter_{iteration}'] = aggregated
                
                return aggregated
            
            return None
            
        except Exception as e:
            logger.error(f"Error during sync with other nodes: {e}")
            return None
    
    def receive_sync(self, sync_data: Dict) -> Dict:
        """
        Receive synchronization data from another node
        
        Args:
            sync_data: Sync data from another node containing:
                - job_id: Job identifier
                - iteration: Iteration number
                - node_id: Source node identifier
                - local_result: Local result from source node
                
        Returns:
            This node's local result for the same iteration
        """
        iteration = sync_data.get('iteration')
        source_node_id = sync_data.get('node_id')
        
        logger.debug(f"Received sync from node {source_node_id} for iteration {iteration}")
        
        # Return our local result for this iteration
        with self.lock:
            local_result = self.local_state.get(f'iter_{iteration}')
            if local_result:
                return {
                    'node_id': self.node_id,
                    'local_result': local_result,
                    'timestamp': time.time()
                }
            else:
                # If we haven't processed this iteration yet, return current state
                return {
                    'node_id': self.node_id,
                    'local_result': {
                        'iteration': iteration,
                        'node_id': self.node_id,
                        'local_sum': sum(chunk.get('value', 0) for chunk in self.data),
                        'data_chunks_count': len(self.data)
                    },
                    'timestamp': time.time(),
                    'note': 'Iteration not yet processed'
                }
    
    def get_status(self) -> Dict:
        """Get current job status"""
        return {
            'job_id': self.job_id,
            'node_id': self.node_id,
            'status': self.status.value,
            'current_iteration': self.current_iteration,
            'max_iterations': self.max_iterations,
            'results_count': len(self.results),
            'total_nodes': self.total_nodes,
            'sync_enabled': self.sync_enabled
        }
    
    def get_results(self) -> List[Dict]:
        """Get job results"""
        return self.results
    
    def to_dict(self) -> Dict:
        """Convert job to dictionary"""
        return {
            'job_id': self.job_id,
            'status': self.status.value,
            'current_iteration': self.current_iteration,
            'max_iterations': self.max_iterations,
            'results': self.results
        }
