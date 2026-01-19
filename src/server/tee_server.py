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
            "max_iterations": 100
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
            quote_generator=AttestationQuoteGenerator
        )
        
        # Store job
        active_jobs[job_id] = job
        
        # Start job in background thread
        job_thread = threading.Thread(target=job.run, daemon=True)
        job_thread.start()
        
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


if __name__ == '__main__':
    port = int(os.getenv('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=True)
