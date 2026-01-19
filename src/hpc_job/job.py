"""
HPC Job Implementation
Simple computation job that processes data in iterations
"""

import json
import time
import threading
import logging
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
                 quote_generator: Optional[object] = None):
        """
        Initialize HPC job
        
        Args:
            job_id: Unique job identifier
            data: Input data chunks to process
            parameters: Job parameters
            max_iterations: Maximum number of iterations
            tee_type: Type of TEE ('SEV' or 'TDX')
            azure_verifier: AzureAttestationVerifier instance
            quote_generator: AttestationQuoteGenerator for generating local quotes
        """
        self.job_id = job_id
        self.data = data
        self.parameters = parameters
        self.max_iterations = max_iterations
        self.tee_type = tee_type
        self.azure_verifier = azure_verifier
        self.quote_generator = quote_generator
        
        self.status = JobStatus.PENDING
        self.current_iteration = 0
        self.results = []
        self.local_state = {}
        self.lock = threading.Lock()
    
    def run(self):
        """Execute the HPC job"""
        logger.info(f"Starting job execution: {self.job_id}")
        self.status = JobStatus.RUNNING
        
        try:
            for iteration in range(self.max_iterations):
                self.current_iteration = iteration
                logger.debug(f"Job {self.job_id}: Processing iteration {iteration}/{self.max_iterations}")
                
                # Process local data chunk
                iteration_result = self._process_iteration(iteration)
                logger.debug(f"Job {self.job_id}: Iteration {iteration} processed, result: {iteration_result}")
                
                self.results.append({
                    'iteration': iteration,
                    'result': iteration_result,
                    'timestamp': time.time()
                })
                
                self.status = JobStatus.RUNNING
                
                # Small delay to simulate computation
                time.sleep(0.1)
            
            logger.info(f"Job {self.job_id}: Completed successfully after {self.max_iterations} iterations")
            self.status = JobStatus.COMPLETED
            
        except Exception as e:
            logger.error(f"Job {self.job_id}: Failed at iteration {self.current_iteration}: {e}")
            logger.exception("Job execution exception details:")
            self.status = JobStatus.FAILED
            raise
    
    def _process_iteration(self, iteration: int) -> Dict:
        """
        Process a single iteration
        
        Args:
            iteration: Current iteration number
            
        Returns:
            Iteration result
        """
        # Simple computation: sum of data values with iteration factor
        result = {
            'iteration': iteration,
            'local_sum': sum(chunk.get('value', 0) for chunk in self.data),
            'computed_value': sum(chunk.get('value', 0) for chunk in self.data) * (iteration + 1)
        }
        
        # Update local state
        with self.lock:
            self.local_state[f'iter_{iteration}'] = result
        
        return result
    
    def get_status(self) -> Dict:
        """Get current job status"""
        return {
            'job_id': self.job_id,
            'status': self.status.value,
            'current_iteration': self.current_iteration,
            'max_iterations': self.max_iterations,
            'results_count': len(self.results)
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
