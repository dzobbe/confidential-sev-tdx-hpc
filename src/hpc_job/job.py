"""
HPC Job Implementation
Simple distributed computation job that requires synchronization between nodes
"""

import json
import time
import threading
import logging
import base64
import hashlib
import uuid
import requests
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum

# Import attestation components
try:
    from src.attestation.mutual_attestation import MutualAttestationSession
    from src.attestation.azure_attestation import AttestationQuoteGenerator
except ImportError:
    # Handle case where imports might fail during testing
    MutualAttestationSession = None
    AttestationQuoteGenerator = None

# Set up logger for this module
logger = logging.getLogger(__name__)


class JobStatus(Enum):
    """Job status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    SYNCING = "syncing"
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
    sync_points: List[Dict]


class HPCJob:
    """
    Simple HPC job that processes data in iterations with synchronization
    """
    
    def __init__(self, job_id: str, data: List[Dict], parameters: Dict,
                 max_iterations: int = 100, 
                 tee_type: Optional[str] = None,
                 azure_verifier: Optional[object] = None,
                 peer_url: Optional[str] = None,
                 quote_generator: Optional[object] = None):
        """
        Initialize HPC job
        
        Args:
            job_id: Unique job identifier
            data: Input data chunks to process
            parameters: Job parameters
            max_iterations: Maximum number of iterations
            tee_type: Type of TEE ('SEV' or 'TDX')
            azure_verifier: AzureAttestationVerifier instance for verifying peer quotes
            peer_url: URL of peer node for synchronization
            quote_generator: AttestationQuoteGenerator for generating local quotes
        """
        self.job_id = job_id
        self.data = data
        self.parameters = parameters
        self.max_iterations = max_iterations
        self.tee_type = tee_type
        self.azure_verifier = azure_verifier
        self.peer_url = peer_url
        self.quote_generator = quote_generator
        
        self.status = JobStatus.PENDING
        self.current_iteration = 0
        self.results = []
        self.sync_points = []
        self.local_state = {}
        self.peer_state = {}
        self.lock = threading.Lock()
        
        # Mutual attestation session (established during first sync)
        self.mutual_attestation_session: Optional[object] = None
    
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
                
                # Synchronize with peer
                if self.peer_url:
                    logger.debug(f"Job {self.job_id}: Synchronizing with peer at iteration {iteration}")
                    self.status = JobStatus.SYNCING
                    sync_result = self._synchronize_with_peer(iteration, iteration_result)
                    
                    if not sync_result:
                        logger.error(f"Job {self.job_id}: Synchronization failed at iteration {iteration}")
                        raise Exception(f"Synchronization failed at iteration {iteration}")
                    
                    logger.debug(f"Job {self.job_id}: Synchronization successful at iteration {iteration}")
                    self.sync_points.append({
                        'iteration': iteration,
                        'timestamp': time.time(),
                        'local_state': self.local_state.copy(),
                        'peer_state': self.peer_state.copy()
                    })
                else:
                    logger.debug(f"Job {self.job_id}: No peer URL provided, skipping synchronization")
                
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
    
    def _synchronize_with_peer(self, iteration: int, local_result: Dict) -> bool:
        """
        Synchronize with peer node, establishing mutual attestation if needed
        
        Args:
            iteration: Current iteration number
            local_result: Local iteration result
            
        Returns:
            True if synchronization successful or skipped (no peer), False if synchronization failed
        """
        if not self.peer_url:
            logger.debug(f"Job {self.job_id}: No peer URL, skipping synchronization")
            return True
        
        try:
            # Establish mutual attestation if not already established
            if self.mutual_attestation_session is None:
                logger.info(f"Job {self.job_id}: Establishing mutual attestation with peer {self.peer_url}")
                
                if not self.tee_type or not self.quote_generator or not self.azure_verifier:
                    logger.error(f"Job {self.job_id}: Missing attestation components (tee_type, quote_generator, or azure_verifier)")
                    return False
                
                if MutualAttestationSession is None:
                    logger.error(f"Job {self.job_id}: MutualAttestationSession not available")
                    return False
                
                # Use deterministic nonce based on job_id so both sides use the same nonce
                nonce = hashlib.sha256(self.job_id.encode()).digest()[:32]
                
                # Generate local quote
                if self.tee_type.upper() == 'SEV':
                    local_quote = self.quote_generator.generate_sev_quote(nonce)
                elif self.tee_type.upper() == 'TDX':
                    local_quote = self.quote_generator.generate_tdx_quote(nonce)
                else:
                    logger.error(f"Job {self.job_id}: Unknown TEE type: {self.tee_type}")
                    return False
                
                # Create mutual attestation session
                session = MutualAttestationSession(
                    local_tee_type=self.tee_type,
                    local_quote=local_quote,
                    azure_verifier=self.azure_verifier,
                    session_id=f"{self.job_id}_{uuid.uuid4().hex[:8]}"
                )
                
                self.mutual_attestation_session = session
                
                # Send attestation request to peer (include nonce for verification)
                attestation_request = session.initiate_attestation()
                attestation_request['nonce'] = base64.b64encode(nonce).decode()
                
                try:
                    response = requests.post(
                        f"{self.peer_url}/mutual-attestation/verify",
                        json=attestation_request,
                        timeout=30
                    )
                    
                    if response.status_code == 200:
                        peer_response = response.json()
                        if peer_response.get('verified'):
                            # Verify peer's quote if provided
                            if 'our_quote' in peer_response:
                                peer_quote_b64 = peer_response.get('our_quote')
                                peer_tee_type = peer_response.get('our_tee_type')
                                peer_quote = base64.b64decode(peer_quote_b64)
                                
                                # Verify peer quote using the same nonce
                                is_valid, result = self.azure_verifier.verify_quote(
                                    quote=peer_quote,
                                    tee_type=peer_tee_type,
                                    nonce=nonce
                                )
                                
                                if is_valid:
                                    session.peer_quote = peer_quote
                                    session.peer_verified = True
                                    session.session_key = session._derive_session_key(session.local_quote, peer_quote)
                                    logger.info(f"Job {self.job_id}: Mutual attestation established")
                                else:
                                    logger.error(f"Job {self.job_id}: Failed to verify peer quote: {result.get('error')}")
                                    return False
                            else:
                                logger.warning(f"Job {self.job_id}: Peer response missing quote")
                        else:
                            error_msg = peer_response.get('error', 'Peer verification failed')
                            logger.error(f"Job {self.job_id}: Peer verification failed: {error_msg}")
                            return False
                    else:
                        error_msg = f"Failed to communicate with peer: status {response.status_code}"
                        logger.error(f"Job {self.job_id}: {error_msg}")
                        return False
                except Exception as e:
                    logger.error(f"Job {self.job_id}: Error establishing mutual attestation: {e}")
                    logger.exception("Mutual attestation exception details:")
                    return False
            
            # Check if session is ready
            if not self.mutual_attestation_session.is_session_ready():
                logger.warning(f"Job {self.job_id}: Mutual attestation session not ready")
                return False
            
            # Prepare sync data
            sync_data = {
                'job_id': self.job_id,
                'iteration': iteration,
                'local_state': local_result,
                'local_full_state': self.local_state.copy()
            }
            
            logger.debug(f"Job {self.job_id}: Preparing sync data for iteration {iteration}")
            
            # Encrypt sync data if mutual attestation is established
            if self.mutual_attestation_session.is_session_ready():
                logger.debug(f"Job {self.job_id}: Encrypting sync data")
                sync_data_encrypted = self.mutual_attestation_session.encrypt_message(
                    json.dumps(sync_data).encode()
                )
                sync_data = {'encrypted': base64.b64encode(sync_data_encrypted).decode()}
            
            # Send sync request to peer
            logger.info(f"Job {self.job_id}: Sending sync request to {self.peer_url}/sync")
            response = requests.post(
                f"{self.peer_url}/sync",
                json=sync_data,
                timeout=30
            )
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    
                    # Decrypt if needed
                    if self.mutual_attestation_session.is_session_ready() and 'encrypted' in result:
                        logger.debug(f"Job {self.job_id}: Decrypting response")
                        decrypted = self.mutual_attestation_session.decrypt_message(
                            base64.b64decode(result['encrypted'])
                        )
                        result = json.loads(decrypted.decode())
                    
                    if result.get('success'):
                        # Update peer state
                        with self.lock:
                            self.peer_state = result.get('peer_state', {})
                        
                        logger.debug(f"Job {self.job_id}: Updated peer state, keys: {list(self.peer_state.keys())}")
                        
                        # Combine results if needed
                        if result.get('combined_result'):
                            logger.debug(f"Job {self.job_id}: Combining results: {result.get('combined_result')}")
                            local_result.update(result['combined_result'])
                        
                        logger.info(f"Job {self.job_id}: Sync successful for iteration {iteration}")
                        return True
                    else:
                        logger.warning(f"Job {self.job_id}: Sync failed - response: {result}")
                        return False
                except json.JSONDecodeError as e:
                    logger.error(f"Job {self.job_id}: Failed to parse JSON response: {e}")
                    return False
            else:
                logger.warning(f"Job {self.job_id}: Peer returned status {response.status_code}")
                return False
                
        except requests.exceptions.Timeout as e:
            logger.error(f"Job {self.job_id}: Timeout error during sync: {e}")
            return False
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Job {self.job_id}: Connection error during sync: {e}")
            return False
        except Exception as e:
            logger.error(f"Job {self.job_id}: Synchronization error at iteration {iteration}: {e}")
            logger.exception("Synchronization exception details:")
            return False
    
    def get_status(self) -> Dict:
        """Get current job status"""
        return {
            'job_id': self.job_id,
            'status': self.status.value,
            'current_iteration': self.current_iteration,
            'max_iterations': self.max_iterations,
            'results_count': len(self.results),
            'sync_points_count': len(self.sync_points)
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
            'results': self.results,
            'sync_points': self.sync_points
        }
