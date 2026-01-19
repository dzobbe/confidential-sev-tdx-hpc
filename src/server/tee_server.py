"""
TEE Server Application
Runs on SEV and TDX VMs, handles attestation quotes and HPC job execution
"""

import os
import base64
import uuid
import threading
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from typing import Dict
from dotenv import load_dotenv

from src.attestation.azure_attestation import AttestationQuoteGenerator, AzureAttestationVerifier
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
            "node_id": "<node_id>",  # Optional, defaults to TEE_TYPE
            "total_nodes": 1,  # Total number of nodes
            "other_node_urls": ["http://...", ...]  # URLs of other nodes for sync
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
        node_id = data.get('node_id', TEE_TYPE)
        total_nodes = data.get('total_nodes', 1)
        other_node_urls = data.get('other_node_urls', [])
        
        if not job_id:
            job_id = str(uuid.uuid4())
        
        # Create HPC job with attestation components and multi-node support
        job = HPCJob(
            job_id=job_id,
            data=job_data,
            parameters=parameters,
            max_iterations=max_iterations,
            tee_type=TEE_TYPE,
            azure_verifier=azure_verifier,
            quote_generator=AttestationQuoteGenerator,
            node_id=node_id,
            total_nodes=total_nodes,
            other_node_urls=other_node_urls,
            sync_enabled=total_nodes > 1
        )
        
        # Store job
        active_jobs[job_id] = job
        
        # Start job in background thread
        job_thread = threading.Thread(target=job.run, daemon=True)
        job_thread.start()
        
        return jsonify({
            'job_id': job_id,
            'status': 'accepted',
            'message': 'Job submitted successfully',
            'node_id': node_id,
            'total_nodes': total_nodes
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
        'status': job.status.value,
        'node_id': job.node_id
    })


@app.route('/job/<job_id>/sync', methods=['POST'])
def sync_job_data(job_id):
    """
    Synchronize job data with another node
    Includes attestation quote verification
    
    Request body:
        {
            "job_id": "<job_id>",
            "iteration": <iteration_number>,
            "node_id": "<source_node_id>",
            "local_result": {...},
            "nonce": "<base64_encoded_nonce>",
            "attestation_quote": "<base64_encoded_quote>",  # Optional
            "tee_type": "<SEV|TDX>"  # Optional
        }
    
    Response:
        {
            "node_id": "<this_node_id>",
            "local_result": {...},
            "timestamp": "<timestamp>",
            "attestation_quote": "<base64_encoded_quote>",  # If available
            "tee_type": "<SEV|TDX>",  # If available
            "attestation_verified": <bool>
        }
    """
    if job_id not in active_jobs:
        return jsonify({'error': 'Job not found'}), 404
    
    try:
        sync_data = request.get_json()
        job = active_jobs[job_id]
        
        # Extract source URL from request (if available via headers or construct from request)
        # For now, we'll use node_id to identify the peer, but we can enhance this
        source_url = sync_data.get('source_url')
        if not source_url:
            # Try to construct from request
            source_url = request.headers.get('Origin') or request.headers.get('Referer')
        
        # Add source URL to sync data for attestation session management
        if source_url:
            sync_data['source_url'] = source_url
        
        # Receive sync data and return our local result (with attestation verification)
        result = job.receive_sync(sync_data)
        
        # If attestation failed and is required, return error status
        if result.get('error') and 'attestation' in result.get('error', '').lower():
            return jsonify(result), 403  # Forbidden - attestation verification failed
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in sync endpoint: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    port = int(os.getenv('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=True)
