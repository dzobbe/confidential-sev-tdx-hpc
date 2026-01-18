"""
TEE Server Application
Runs on SEV and TDX VMs, handles attestation quotes and HPC job execution
"""

import os
import json
import base64
import uuid
import threading
import logging
import hashlib
from flask import Flask, request, jsonify
from flask_cors import CORS
from typing import Dict, Optional
from dotenv import load_dotenv

from src.attestation.azure_attestation import AttestationQuoteGenerator, AzureAttestationVerifier
from src.attestation.mutual_attestation import MutualAttestationSession
from src.hpc_job.job import HPCJob, JobStatus

load_dotenv()

# Configure logging
log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
numeric_level = getattr(logging, log_level, logging.INFO)
logging.basicConfig(
    level=numeric_level,
    format='[%(levelname)s] :: %(asctime)s :: {%(name)s:%(lineno)d} :: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)
logger.info(f"Logging initialized at level: {log_level}")

app = Flask(__name__)
CORS(app)

# Configure Flask's logger
app.logger.setLevel(numeric_level)

# Configuration
TEE_TYPE = os.getenv('TEE_TYPE', 'SEV')  # 'SEV' or 'TDX'
AZURE_ENDPOINT = os.getenv('AZURE_ATTESTATION_ENDPOINT')

# Initialize Azure Attestation Verifier
# No authentication required - Azure Attestation Service endpoints are public
azure_verifier = None
if AZURE_ENDPOINT:
    azure_verifier = AzureAttestationVerifier(endpoint=AZURE_ENDPOINT)

# Server state
active_jobs: Dict[str, HPCJob] = {}
mutual_attestation_sessions: Dict[str, MutualAttestationSession] = {}
peer_connections: Dict[str, str] = {}  # job_id -> peer_url


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'tee_type': TEE_TYPE,
        'server_id': os.getenv('SERVER_ID', 'unknown')
    })


@app.route('/attestation/quote', methods=['POST'])
def get_attestation_quote():
    """
    Generate and return attestation quote
    
    Request body:
        {
            "nonce": "<base64_encoded_nonce>"
        }
    
    Response:
        {
            "quote": "<base64_encoded_quote>",
            "tee_type": "SEV" | "TDX",
            "timestamp": "<iso_timestamp>"
        }
    """
    try:
        data = request.get_json()
        nonce_b64 = data.get('nonce')
        
        if not nonce_b64:
            return jsonify({'error': 'Missing nonce'}), 400
        
        nonce = base64.b64decode(nonce_b64)
        
        # Generate quote based on TEE type
        if TEE_TYPE.upper() == 'SEV':
            quote = AttestationQuoteGenerator.generate_sev_quote(nonce)
        elif TEE_TYPE.upper() == 'TDX':
            quote = AttestationQuoteGenerator.generate_tdx_quote(nonce)
        else:
            return jsonify({'error': f'Unsupported TEE type: {TEE_TYPE}'}), 400
        
        return jsonify({
            'quote': base64.b64encode(quote).decode(),
            'tee_type': TEE_TYPE,
            'timestamp': __import__('datetime').datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/job/submit', methods=['POST'])
def submit_job():
    """
    Submit HPC job for execution
    
    Request body:
        {
            "job_id": "<job_id>",
            "data": [...],
            "parameters": {...},
            "max_iterations": 100,
            "peer_url": "<peer_server_url>"
        }
    
    Response:
        {
            "job_id": "<job_id>",
            "status": "accepted",
            "message": "Job submitted successfully"
        }
    """
    try:
        data = request.get_json()
        job_id = data.get('job_id')
        job_data = data.get('data', [])
        parameters = data.get('parameters', {})
        max_iterations = data.get('max_iterations', 100)
        peer_url = data.get('peer_url')
        
        if not job_id:
            job_id = str(uuid.uuid4())
        
        # Create HPC job with attestation components
        job = HPCJob(
            job_id=job_id,
            data=job_data,
            parameters=parameters,
            max_iterations=max_iterations,
            tee_type=TEE_TYPE,
            azure_verifier=azure_verifier,
            peer_url=peer_url,
            quote_generator=AttestationQuoteGenerator
        )
        
        # Store job
        active_jobs[job_id] = job
        
        # Start job in background thread
        job_thread = threading.Thread(target=job.run, daemon=True)
        job_thread.start()
        
        if peer_url:
            peer_connections[job_id] = peer_url
        
        return jsonify({
            'job_id': job_id,
            'status': 'accepted',
            'message': 'Job submitted successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/job/<job_id>/status', methods=['GET'])
def get_job_status(job_id):
    """Get job status"""
    if job_id not in active_jobs:
        return jsonify({'error': 'Job not found'}), 404
    
    job = active_jobs[job_id]
    return jsonify(job.get_status())


@app.route('/job/<job_id>/results', methods=['GET'])
def get_job_results(job_id):
    """Get job results"""
    if job_id not in active_jobs:
        return jsonify({'error': 'Job not found'}), 404
    
    job = active_jobs[job_id]
    return jsonify({
        'job_id': job_id,
        'results': job.get_results(),
        'status': job.status.value
    })


@app.route('/mutual-attestation/initiate', methods=['POST'])
def initiate_mutual_attestation():
    """
    Initiate mutual attestation with peer
    
    Request body:
        {
            "job_id": "<job_id>",
            "peer_url": "<peer_server_url>"
        }
    """
    try:
        data = request.get_json()
        job_id = data.get('job_id')
        peer_url = data.get('peer_url')
        
        if not job_id or not peer_url:
            return jsonify({'error': 'Missing job_id or peer_url'}), 400
        
        # Generate local quote
        nonce = azure_verifier.generate_nonce() if azure_verifier else os.urandom(32)
        
        if TEE_TYPE.upper() == 'SEV':
            local_quote = AttestationQuoteGenerator.generate_sev_quote(nonce)
        else:
            local_quote = AttestationQuoteGenerator.generate_tdx_quote(nonce)
        
        # Create mutual attestation session
        session = MutualAttestationSession(
            local_tee_type=TEE_TYPE,
            local_quote=local_quote,
            azure_verifier=azure_verifier,
            session_id=f"{job_id}_{uuid.uuid4().hex[:8]}"
        )
        
        mutual_attestation_sessions[job_id] = session
        
        # Send attestation request to peer
        attestation_request = session.initiate_attestation()
        
        import requests
        response = requests.post(
            f"{peer_url}/mutual-attestation/verify",
            json=attestation_request,
            timeout=30
        )
        
        if response.status_code == 200:
            peer_response = response.json()
            if peer_response.get('verified'):
                return jsonify({
                    'session_id': session.session_id,
                    'status': 'established',
                    'message': 'Mutual attestation successful'
                })
            else:
                return jsonify({
                    'error': peer_response.get('error', 'Peer verification failed')
                }), 400
        else:
            return jsonify({'error': 'Failed to communicate with peer'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/mutual-attestation/verify', methods=['POST'])
def verify_peer_attestation():
    """
    Verify peer's attestation request
    
    Request body:
        {
            "session_id": "<session_id>",
            "tee_type": "SEV" | "TDX",
            "quote": "<base64_encoded_quote>",
            "timestamp": "<iso_timestamp>",
            "action": "attestation_request"
        }
    """
    try:
        data = request.get_json()
        session_id = data.get('session_id')
        peer_quote_b64 = data.get('quote')
        peer_tee_type = data.get('tee_type')
        
        if not session_id or not peer_quote_b64:
            return jsonify({'error': 'Missing session_id or quote'}), 400
        
        # Find or create session
        # For simplicity, we'll create a new session
        # In production, session_id should map to job_id
        job_id = session_id.split('_')[0]  # Extract job_id from session_id
        
        # Use the same nonce from the request, or derive deterministically from job_id
        nonce_b64 = data.get('nonce')
        if nonce_b64:
            nonce = base64.b64decode(nonce_b64)
        else:
            # Fallback: use deterministic nonce based on job_id
            nonce = hashlib.sha256(job_id.encode()).digest()[:32]
        
        if TEE_TYPE.upper() == 'SEV':
            local_quote = AttestationQuoteGenerator.generate_sev_quote(nonce)
        else:
            local_quote = AttestationQuoteGenerator.generate_tdx_quote(nonce)
        
        # Create session if not exists
        if job_id not in mutual_attestation_sessions:
            session = MutualAttestationSession(
                local_tee_type=TEE_TYPE,
                local_quote=local_quote,
                azure_verifier=azure_verifier,
                session_id=session_id
            )
            mutual_attestation_sessions[job_id] = session
            
            # Also store in job if job exists
            if job_id in active_jobs:
                active_jobs[job_id].mutual_attestation_session = session
        
        session = mutual_attestation_sessions[job_id]
        
        # Verify peer attestation
        is_valid, error = session.verify_peer_attestation(data, nonce)
        
        if is_valid:
            # Generate our quote using the same nonce
            if TEE_TYPE.upper() == 'SEV':
                our_quote = AttestationQuoteGenerator.generate_sev_quote(nonce)
            else:
                our_quote = AttestationQuoteGenerator.generate_tdx_quote(nonce)
            
            # Update session with our quote
            session.local_quote = our_quote
            
            # Send our attestation back
            our_request = session.initiate_attestation()
            return jsonify({
                'verified': True,
                'session_id': session.session_id,
                'our_quote': our_request['quote'],
                'our_tee_type': TEE_TYPE
            })
        else:
            return jsonify({
                'verified': False,
                'error': error
            }), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/sync', methods=['POST'])
def sync():
    """
    Synchronize with peer during job execution
    
    Request body:
        {
            "job_id": "<job_id>",
            "iteration": <iteration_number>,
            "local_state": {...},
            "local_full_state": {...}
        }
    """
    try:
        data = request.get_json()
        job_id = data.get('job_id')
        iteration = data.get('iteration')
        
        # Handle encrypted data if mutual attestation is established
        if 'encrypted' in data:
            if job_id not in mutual_attestation_sessions:
                return jsonify({'error': 'Mutual attestation not established, cannot decrypt'}), 403
            
            session = mutual_attestation_sessions[job_id]
            if not session.is_session_ready():
                return jsonify({'error': 'Mutual attestation session not ready, cannot decrypt'}), 403
            
            try:
                decrypted = session.decrypt_message(base64.b64decode(data['encrypted']))
                data = json.loads(decrypted.decode())
            except Exception as e:
                logger.error(f"sync: Failed to decrypt data for job {job_id}: {e}")
                return jsonify({'error': 'Failed to decrypt sync data'}), 400
        
        peer_state = data.get('local_state')
        peer_full_state = data.get('local_full_state', {})
        
        if job_id not in active_jobs:
            return jsonify({'error': 'Job not found'}), 404
        
        job = active_jobs[job_id]
        
        # Check if we have a mutual attestation session (either in job or global dict)
        session = None
        if hasattr(job, 'mutual_attestation_session') and job.mutual_attestation_session:
            session = job.mutual_attestation_session
        elif job_id in mutual_attestation_sessions:
            session = mutual_attestation_sessions[job_id]
            # Link it to the job
            job.mutual_attestation_session = session
        
        # If we have encrypted data but no session, mutual attestation wasn't established
        if 'encrypted' in data and not session:
            return jsonify({'error': 'Mutual attestation not established, cannot decrypt'}), 403
        
        # Update peer state
        job.peer_state = peer_full_state
        
        # Combine results
        combined_result = {
            'combined_sum': job.local_state.get('iter_0', {}).get('local_sum', 0) + 
                          peer_state.get('local_sum', 0)
        }
        
        response_data = {
            'success': True,
            'peer_state': job.local_state.copy(),
            'combined_result': combined_result
        }
        
        # Encrypt response if mutual attestation is established
        if session and session.is_session_ready():
            encrypted_response = session.encrypt_message(json.dumps(response_data).encode())
            return jsonify({'encrypted': base64.b64encode(encrypted_response).decode()})
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"sync: Error processing sync request: {e}")
        logger.exception("Sync endpoint exception details:")
        return jsonify({'error': str(e)}), 500


def sync_with_peer(job_id: str, sync_data: Dict, peer_url: Optional[str]) -> Optional[Dict]:
    """
    Helper function to sync with peer node
    
    Args:
        job_id: Job identifier
        sync_data: Data to sync
        peer_url: Peer server URL
        
    Returns:
        Peer response or None
    """
    logger.debug(f"sync_with_peer called: job_id={job_id}, peer_url={peer_url}")
    
    if not peer_url:
        logger.warning(f"sync_with_peer: No peer_url provided for job {job_id}")
        return None
    
    try:
        import requests
        
        # Establish mutual attestation if not already established
        if job_id not in mutual_attestation_sessions:
            logger.info(f"sync_with_peer: Establishing mutual attestation for job {job_id} with peer {peer_url}")
            
            # Use deterministic nonce based on job_id so both sides use the same nonce
            nonce = hashlib.sha256(job_id.encode()).digest()[:32]
            
            if TEE_TYPE.upper() == 'SEV':
                local_quote = AttestationQuoteGenerator.generate_sev_quote(nonce)
            else:
                local_quote = AttestationQuoteGenerator.generate_tdx_quote(nonce)
            
            # Create mutual attestation session
            session = MutualAttestationSession(
                local_tee_type=TEE_TYPE,
                local_quote=local_quote,
                azure_verifier=azure_verifier,
                session_id=f"{job_id}_{uuid.uuid4().hex[:8]}"
            )
            
            mutual_attestation_sessions[job_id] = session
            
            # Send attestation request to peer (include nonce for verification)
            attestation_request = session.initiate_attestation()
            attestation_request['nonce'] = base64.b64encode(nonce).decode()
            
            try:
                response = requests.post(
                    f"{peer_url}/mutual-attestation/verify",
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
                            is_valid, result = azure_verifier.verify_quote(
                                quote=peer_quote,
                                tee_type=peer_tee_type,
                                nonce=nonce
                            ) if azure_verifier else (True, {})
                            
                            if is_valid:
                                session.peer_quote = peer_quote
                                session.peer_verified = True
                                session.session_key = session._derive_session_key(session.local_quote, peer_quote)
                                logger.info(f"sync_with_peer: Mutual attestation established for job {job_id}")
                            else:
                                logger.error(f"sync_with_peer: Failed to verify peer quote for job {job_id}: {result.get('error')}")
                                return {'success': False, 'error': f"Peer attestation verification failed: {result.get('error')}"}
                        else:
                            logger.warning(f"sync_with_peer: Peer response missing quote for job {job_id}")
                    else:
                        error_msg = peer_response.get('error', 'Peer verification failed')
                        logger.error(f"sync_with_peer: Peer verification failed for job {job_id}: {error_msg}")
                        return {'success': False, 'error': error_msg}
                else:
                    error_msg = f"Failed to communicate with peer: status {response.status_code}"
                    logger.error(f"sync_with_peer: {error_msg} for job {job_id}")
                    return {'success': False, 'error': error_msg}
            except Exception as e:
                logger.error(f"sync_with_peer: Error establishing mutual attestation for job {job_id}: {e}")
                logger.exception("Mutual attestation exception details:")
                return {'success': False, 'error': f"Mutual attestation failed: {str(e)}"}
        
        # Check if session is ready
        session = mutual_attestation_sessions[job_id]
        if not session.is_session_ready():
            logger.warning(f"sync_with_peer: Mutual attestation session not ready for job {job_id}, attempting to retry")
            # Could implement retry logic here if needed
        
        logger.debug(f"sync_with_peer: Preparing sync data for job {job_id} to {peer_url}")
        logger.debug(f"sync_with_peer: Sync data keys: {list(sync_data.keys()) if isinstance(sync_data, dict) else 'not a dict'}")
        
        # Encrypt sync data if mutual attestation is established
        if session.is_session_ready():
            logger.debug(f"sync_with_peer: Encrypting sync data for job {job_id}")
            sync_data_encrypted = session.encrypt_message(json.dumps(sync_data).encode())
            sync_data = {'encrypted': base64.b64encode(sync_data_encrypted).decode()}
            logger.debug(f"sync_with_peer: Sync data encrypted, length: {len(sync_data['encrypted'])}")
        else:
            logger.warning(f"sync_with_peer: Mutual attestation session not ready for job {job_id}, sending unencrypted")
        
        logger.info(f"sync_with_peer: Sending sync request to {peer_url}/sync for job {job_id}")
        response = requests.post(
            f"{peer_url}/sync",
            json=sync_data,
            timeout=30
        )
        
        logger.debug(f"sync_with_peer: Received response status {response.status_code} for job {job_id}")
        
        if response.status_code == 200:
            try:
                result = response.json()
                logger.debug(f"sync_with_peer: Successfully parsed JSON response for job {job_id}")
                logger.debug(f"sync_with_peer: Response keys: {list(result.keys()) if isinstance(result, dict) else 'not a dict'}")
                
                # Decrypt if needed
                if job_id in mutual_attestation_sessions:
                    session = mutual_attestation_sessions[job_id]
                    if session.is_session_ready() and 'encrypted' in result:
                        logger.debug(f"sync_with_peer: Decrypting response for job {job_id}")
                        decrypted = session.decrypt_message(base64.b64decode(result['encrypted']))
                        result = json.loads(decrypted.decode())
                        logger.debug(f"sync_with_peer: Response decrypted successfully for job {job_id}")
                
                logger.info(f"sync_with_peer: Sync successful for job {job_id}")
                return result
            except json.JSONDecodeError as e:
                logger.error(f"sync_with_peer: Failed to parse JSON response for job {job_id}: {e}")
                logger.error(f"sync_with_peer: Response text (first 500 chars): {response.text[:500]}")
                return None
        else:
            logger.warning(f"sync_with_peer: Peer returned status {response.status_code} for job {job_id}")
            logger.warning(f"sync_with_peer: Response text (first 500 chars): {response.text[:500]}")
            return None
            
    except requests.exceptions.Timeout as e:
        logger.error(f"sync_with_peer: Timeout error for job {job_id} to {peer_url}: {e}")
        logger.exception("Timeout exception details:")
        return None
    except requests.exceptions.ConnectionError as e:
        logger.error(f"sync_with_peer: Connection error for job {job_id} to {peer_url}: {e}")
        logger.exception("Connection exception details:")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"sync_with_peer: Request error for job {job_id} to {peer_url}: {e}")
        logger.exception("Request exception details:")
        return None
    except Exception as e:
        logger.error(f"sync_with_peer: Unexpected error for job {job_id}: {e}")
        logger.exception("Sync exception details:")
        return None


if __name__ == '__main__':
    port = int(os.getenv('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=True)
