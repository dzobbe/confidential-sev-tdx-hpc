"""
HPC Job Implementation
Simple computation job that processes data in iterations
"""

import json
import time
import threading
import logging
import requests
import base64
import uuid
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

# Import attestation components
try:
    from src.attestation.azure_attestation import AttestationQuoteGenerator
    from src.attestation.mutual_attestation import MutualAttestationSession
except ImportError:
    # Handle case where imports might fail during testing
    AttestationQuoteGenerator = None
    MutualAttestationSession = None

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
                 sync_enabled: bool = True,
                 require_attestation: bool = True):
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
            require_attestation: Whether to require successful attestation verification for sync (default: True)
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
        self.require_attestation = require_attestation
        
        self.status = JobStatus.PENDING
        self.current_iteration = 0
        self.results = []
        self.local_state = {}
        self.synced_state = {}  # State received from other nodes
        self.lock = threading.Lock()
        
        # Attestation session management per peer node
        # Maps node_url/node_id -> MutualAttestationSession
        self.attestation_sessions: Dict[str, object] = {}
        
        # Note: We don't generate a quote here because quotes must be generated
        # with a specific nonce that will be used for verification. Quotes are
        # generated fresh during each sync operation with the appropriate nonce.
        
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
    
    def _get_or_create_attestation_session(self, peer_identifier: str) -> Optional[object]:
        """
        Get or create mutual attestation session for a peer node
        
        Args:
            peer_identifier: URL or node_id of the peer node
            
        Returns:
            MutualAttestationSession if available, None otherwise
        """
        if peer_identifier in self.attestation_sessions:
            return self.attestation_sessions[peer_identifier]
        
        # Create new session if we have the required components
        # Note: We'll generate quotes dynamically during sync, so we don't need
        # a pre-generated local_quote for the session initialization
        if (MutualAttestationSession and self.azure_verifier and self.tee_type):
            try:
                session_id = f"{self.job_id}_{self.node_id}_{peer_identifier}"
                # Create a placeholder session - we'll update it with quotes during sync
                # For now, we'll create it without a local quote and update it later
                # Note: MutualAttestationSession requires local_quote, so we'll need
                # to generate a temporary one or modify the approach
                import os
                temp_nonce = os.urandom(32)
                temp_quote = None
                if self.quote_generator:
                    try:
                        if self.tee_type.upper() == 'SEV':
                            temp_quote = self.quote_generator.generate_sev_quote(temp_nonce)
                        elif self.tee_type.upper() == 'TDX':
                            temp_quote = self.quote_generator.generate_tdx_quote(temp_nonce)
                    except Exception:
                        pass
                
                if temp_quote:
                    session = MutualAttestationSession(
                        local_tee_type=self.tee_type,
                        local_quote=temp_quote,
                        azure_verifier=self.azure_verifier,
                        session_id=session_id
                    )
                    self.attestation_sessions[peer_identifier] = session
                    return session
            except Exception as e:
                logger.warning(f"Failed to create attestation session for {peer_identifier}: {e}")
                return None
        
        return None
    
    def _sync_with_other_nodes(self, iteration: int, local_result: Dict) -> Optional[Dict]:
        """
        Synchronize data with other nodes for the current iteration
        Includes attestation quote verification
        
        Args:
            iteration: Current iteration number
            local_result: Local computation result
            
        Returns:
            Aggregated result from all nodes, or None if sync failed
        """
        if not self.other_node_urls:
            return None
        
        try:
            # Generate nonce for attestation
            import os
            nonce = os.urandom(32)
            
            # Generate fresh attestation quote with this nonce for verification
            attestation_quote = None
            if self.quote_generator and self.tee_type:
                try:
                    if self.tee_type.upper() == 'SEV':
                        attestation_quote = self.quote_generator.generate_sev_quote(nonce)
                    elif self.tee_type.upper() == 'TDX':
                        attestation_quote = self.quote_generator.generate_tdx_quote(nonce)
                except Exception as e:
                    logger.warning(f"Failed to generate attestation quote for sync: {e}")
            
            # Prepare sync data to send with attestation quote
            sync_data = {
                'job_id': self.job_id,
                'iteration': iteration,
                'node_id': self.node_id,
                'local_result': local_result,
                'timestamp': time.time(),
                'nonce': base64.b64encode(nonce).decode()  # Include nonce for quote verification
            }
            
            # Add attestation quote if generated successfully
            if attestation_quote:
                sync_data['attestation_quote'] = base64.b64encode(attestation_quote).decode()
                sync_data['tee_type'] = self.tee_type
            
            # Collect results from other nodes
            other_results = []
            for node_url in self.other_node_urls:
                try:
                    # Get or create attestation session for this peer
                    session = self._get_or_create_attestation_session(node_url)
                    
                    # Add source URL to sync data so receiving node can identify us
                    sync_data_with_source = sync_data.copy()
                    # Note: We don't have our own URL here, but the receiving node
                    # can identify us by node_id for attestation session management
                    
                    response = requests.post(
                        f"{node_url}/job/{self.job_id}/sync",
                        json=sync_data_with_source,
                        timeout=10.0  # Increased timeout for attestation verification
                    )
                    
                    # Handle error responses (e.g., attestation verification failed)
                    if response.status_code == 403:
                        error_data = response.json()
                        error_msg = error_data.get('error', 'Attestation verification failed')
                        logger.error(f"Sync rejected by {node_url} due to attestation failure: {error_msg}")
                        if self.require_attestation:
                            # Skip this node if attestation is required
                            continue
                    
                    if response.status_code == 200:
                        node_result = response.json()
                        
                        # Check if response contains an error (even with 200 status)
                        if node_result.get('error'):
                            error_msg = node_result.get('error', 'Unknown error')
                            logger.error(f"Sync error from {node_url}: {error_msg}")
                            if self.require_attestation and 'attestation' in error_msg.lower():
                                # Skip this node if attestation is required
                                continue
                        
                        # Verify attestation quote from peer if present
                        # Always verify fresh - never trust cached session state
                        attestation_verified = False
                        
                        if node_result.get('attestation_quote'):
                            peer_quote_b64 = node_result.get('attestation_quote')
                            peer_tee_type = node_result.get('tee_type')
                            
                            if not peer_tee_type:
                                logger.warning(f"No tee_type provided with attestation quote from {node_url}")
                                node_result['attestation_verified'] = False
                                node_result['attestation_error'] = 'Missing tee_type'
                                
                                # Reset session verification status
                                if session:
                                    session.peer_verified = False
                                    session.peer_quote = None
                                
                                if self.require_attestation:
                                    logger.error(f"Attestation required but missing tee_type from {node_url}. Skipping sync with this node.")
                                    continue
                            else:
                                try:
                                    peer_quote = base64.b64decode(peer_quote_b64)
                                    # Use the nonce we sent for verification - always verify fresh
                                    is_valid, verify_result = self.azure_verifier.verify_quote(
                                        quote=peer_quote,
                                        tee_type=peer_tee_type,
                                        nonce=nonce
                                    )
                                    
                                    if is_valid:
                                        attestation_verified = True
                                        logger.debug(f"Verified attestation quote from {node_url}")
                                        
                                        # Update session with verified peer quote
                                        if session:
                                            session.peer_quote = peer_quote
                                            session.peer_verified = True
                                    else:
                                        error_msg = verify_result.get('error', 'Attestation verification failed')
                                        logger.warning(f"Attestation verification failed for {node_url}: {error_msg}")
                                        node_result['attestation_verified'] = False
                                        node_result['attestation_error'] = error_msg
                                        
                                        # Reset session verification status - trust is broken
                                        if session:
                                            session.peer_verified = False
                                            session.peer_quote = None
                                            logger.warning(f"Invalidated attestation session for {node_url} due to verification failure")
                                        
                                        # If attestation is required, fail the sync for this node
                                        if self.require_attestation:
                                            logger.error(f"Attestation required but verification failed for {node_url}. Skipping sync with this node.")
                                            continue  # Skip this node and don't add it to results
                                except Exception as e:
                                    logger.warning(f"Error verifying attestation from {node_url}: {e}")
                                    node_result['attestation_verified'] = False
                                    node_result['attestation_error'] = str(e)
                                    
                                    # Reset session verification status - trust is broken
                                    if session:
                                        session.peer_verified = False
                                        session.peer_quote = None
                                        logger.warning(f"Invalidated attestation session for {node_url} due to verification error")
                                    
                                    # If attestation is required, fail the sync for this node
                                    if self.require_attestation:
                                        logger.error(f"Attestation required but verification error occurred for {node_url}. Skipping sync with this node.")
                                        continue  # Skip this node and don't add it to results
                        else:
                            # No attestation quote provided
                            logger.debug(f"No attestation quote provided by {node_url}")
                            attestation_verified = False
                            
                            # Reset session verification status if no quote provided when required
                            if session and self.require_attestation:
                                session.peer_verified = False
                                session.peer_quote = None
                                logger.warning(f"Invalidated attestation session for {node_url} - no quote provided")
                            
                            # If attestation is required, fail the sync for this node
                            if self.require_attestation:
                                logger.error(f"Attestation required but no quote provided by {node_url}. Skipping sync with this node.")
                                continue  # Skip this node and don't add it to results
                        
                        # Only add to results if we reach here (verification passed or not required)
                        # Set attestation_verified flag in result
                        node_result['attestation_verified'] = attestation_verified
                        other_results.append(node_result)
                        logger.debug(f"Synced with node at {node_url}: {node_result.get('node_id')} (attestation_verified={attestation_verified})")
                    else:
                        logger.warning(f"Sync failed with {node_url}: Status {response.status_code}")
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Failed to sync with {node_url}: {e}")
                    # Continue with other nodes even if one fails
            
            # Aggregate results
            if other_results:
                # Calculate global sum across all nodes
                global_sum = local_result.get('local_sum', 0)
                verified_nodes = 0
                for node_result in other_results:
                    node_local_result = node_result.get('local_result', {})
                    global_sum += node_local_result.get('local_sum', 0)
                    if node_result.get('attestation_verified', False):
                        verified_nodes += 1
                
                aggregated = {
                    'global_sum': global_sum,
                    'nodes_participated': len(other_results) + 1,  # +1 for this node
                    'total_nodes': self.total_nodes,
                    'verified_nodes': verified_nodes + 1,  # +1 for this node
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
        Verifies attestation quote from the peer node
        
        Args:
            sync_data: Sync data from another node containing:
                - job_id: Job identifier
                - iteration: Iteration number
                - node_id: Source node identifier
                - local_result: Local result from source node
                - nonce: Nonce for attestation verification
                - attestation_quote: Base64-encoded attestation quote (optional)
                - tee_type: TEE type of source node (optional)
                
        Returns:
            This node's local result for the same iteration, including attestation quote
        """
        iteration = sync_data.get('iteration')
        source_node_id = sync_data.get('node_id')
        source_node_url = sync_data.get('source_url')  # Optional: URL of source node
        
        logger.debug(f"Received sync from node {source_node_id} for iteration {iteration}")
        
        # Verify attestation quote from peer if provided
        attestation_verified = False
        attestation_error = None
        
        if sync_data.get('attestation_quote') and self.azure_verifier:
            peer_quote_b64 = sync_data.get('attestation_quote')
            peer_tee_type = sync_data.get('tee_type')
            nonce_b64 = sync_data.get('nonce')
            
            if peer_tee_type and nonce_b64:
                try:
                    peer_quote = base64.b64decode(peer_quote_b64)
                    nonce = base64.b64decode(nonce_b64)
                    
                    # Verify quote with Azure Attestation Service
                    is_valid, verify_result = self.azure_verifier.verify_quote(
                        quote=peer_quote,
                        tee_type=peer_tee_type,
                        nonce=nonce
                    )
                    
                    if is_valid:
                        attestation_verified = True
                        logger.debug(f"Verified attestation quote from node {source_node_id}")
                        
                        # Store attestation session using node_id or URL as identifier
                        session_identifier = source_node_url or source_node_id
                        if session_identifier and MutualAttestationSession:
                            session = self._get_or_create_attestation_session(session_identifier)
                            if session:
                                session.peer_quote = peer_quote
                                session.peer_verified = True
                    else:
                        attestation_error = verify_result.get('error', 'Attestation verification failed')
                        logger.warning(f"Attestation verification failed for node {source_node_id}: {attestation_error}")
                        
                        # Reset session verification status - trust is broken
                        session_identifier = source_node_url or source_node_id
                        if session_identifier and MutualAttestationSession:
                            session = self._get_or_create_attestation_session(session_identifier)
                            if session:
                                session.peer_verified = False
                                session.peer_quote = None
                                logger.warning(f"Invalidated attestation session for {source_node_id} due to verification failure")
                        
                        # If attestation is required, reject the sync
                        if self.require_attestation:
                            logger.error(f"Attestation required but verification failed for node {source_node_id}. Rejecting sync request.")
                            return {
                                'error': 'Attestation verification failed',
                                'attestation_error': attestation_error,
                                'node_id': self.node_id
                            }
                except Exception as e:
                    attestation_error = str(e)
                    logger.warning(f"Error verifying attestation from node {source_node_id}: {e}")
                    
                    # Reset session verification status - trust is broken
                    session_identifier = source_node_url or source_node_id
                    if session_identifier and MutualAttestationSession:
                        session = self._get_or_create_attestation_session(session_identifier)
                        if session:
                            session.peer_verified = False
                            session.peer_quote = None
                            logger.warning(f"Invalidated attestation session for {source_node_id} due to verification error")
                    
                    # If attestation is required, reject the sync
                    if self.require_attestation:
                        logger.error(f"Attestation required but verification error occurred for node {source_node_id}. Rejecting sync request.")
                        return {
                            'error': 'Attestation verification error',
                            'attestation_error': attestation_error,
                            'node_id': self.node_id
                        }
            else:
                attestation_error = "Missing nonce or tee_type for attestation verification"
                
                # Reset session verification status
                session_identifier = source_node_url or source_node_id
                if session_identifier and MutualAttestationSession:
                    session = self._get_or_create_attestation_session(session_identifier)
                    if session:
                        session.peer_verified = False
                        session.peer_quote = None
                        logger.warning(f"Invalidated attestation session for {source_node_id} - missing attestation data")
                
                # If attestation is required, reject the sync
                if self.require_attestation:
                    logger.error(f"Attestation required but missing nonce or tee_type from node {source_node_id}. Rejecting sync request.")
                    return {
                        'error': 'Missing attestation data',
                        'attestation_error': attestation_error,
                        'node_id': self.node_id
                    }
        else:
            logger.debug(f"No attestation quote provided by node {source_node_id}")
            
            # Reset session verification status
            session_identifier = source_node_url or source_node_id
            if session_identifier and MutualAttestationSession and self.require_attestation:
                session = self._get_or_create_attestation_session(session_identifier)
                if session:
                    session.peer_verified = False
                    session.peer_quote = None
                    logger.warning(f"Invalidated attestation session for {source_node_id} - no quote provided")
            
            # If attestation is required, reject the sync
            if self.require_attestation:
                logger.error(f"Attestation required but no quote provided by node {source_node_id}. Rejecting sync request.")
                return {
                    'error': 'No attestation quote provided',
                    'attestation_error': 'Attestation quote is required but was not provided',
                    'node_id': self.node_id
                }
        
        # Return our local result for this iteration
        with self.lock:
            local_result = self.local_state.get(f'iter_{iteration}')
            if local_result:
                result = {
                    'node_id': self.node_id,
                    'local_result': local_result,
                    'timestamp': time.time(),
                    'attestation_verified': attestation_verified
                }
            else:
                # If we haven't processed this iteration yet, return current state
                result = {
                    'node_id': self.node_id,
                    'local_result': {
                        'iteration': iteration,
                        'node_id': self.node_id,
                        'local_sum': sum(chunk.get('value', 0) for chunk in self.data),
                        'data_chunks_count': len(self.data)
                    },
                    'timestamp': time.time(),
                    'note': 'Iteration not yet processed',
                    'attestation_verified': attestation_verified
                }
            
                # Generate fresh attestation quote with the nonce from the request
            if sync_data.get('nonce') and self.quote_generator and self.tee_type:
                try:
                    nonce_b64 = sync_data.get('nonce')
                    nonce = base64.b64decode(nonce_b64)
                    
                    if self.tee_type.upper() == 'SEV':
                        quote = self.quote_generator.generate_sev_quote(nonce)
                    elif self.tee_type.upper() == 'TDX':
                        quote = self.quote_generator.generate_tdx_quote(nonce)
                    else:
                        quote = None
                    
                    if quote:
                        result['attestation_quote'] = base64.b64encode(quote).decode()
                        result['tee_type'] = self.tee_type
                except Exception as e:
                    logger.warning(f"Failed to generate attestation quote in receive_sync: {e}")
            
            if attestation_error:
                result['attestation_error'] = attestation_error
            
            return result
    
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
