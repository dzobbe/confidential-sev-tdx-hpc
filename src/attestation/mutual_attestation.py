"""
Mutual Attestation Protocol
Handles mutual attestation between TEE VMs during HPC job execution
"""

import json
import base64
import hashlib
from typing import Dict, Optional, Tuple
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


class MutualAttestationSession:
    """Manages mutual attestation session between two TEE VMs"""
    
    def __init__(self, local_tee_type: str, local_quote: bytes, 
                 azure_verifier, session_id: str):
        """
        Initialize mutual attestation session
        
        Args:
            local_tee_type: Type of local TEE ('SEV' or 'TDX')
            local_quote: Local attestation quote
            azure_verifier: AzureAttestationVerifier instance
            session_id: Unique session identifier
        """
        self.local_tee_type = local_tee_type
        self.local_quote = local_quote
        self.azure_verifier = azure_verifier
        self.session_id = session_id
        self.peer_quote: Optional[bytes] = None
        self.peer_verified = False
        self.session_key: Optional[bytes] = None
        self.created_at = datetime.utcnow()
    
    def initiate_attestation(self) -> Dict:
        """
        Create attestation request message to send to peer
        
        Returns:
            Dictionary containing attestation request
        """
        return {
            'session_id': self.session_id,
            'tee_type': self.local_tee_type,
            'quote': base64.b64encode(self.local_quote).decode(),
            'timestamp': self.created_at.isoformat(),
            'action': 'attestation_request'
        }
    
    def verify_peer_attestation(self, peer_request: Dict, nonce: bytes) -> Tuple[bool, str]:
        """
        Verify peer's attestation quote
        
        Args:
            peer_request: Attestation request from peer
            nonce: Nonce used for verification
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            # Extract peer quote
            peer_quote_b64 = peer_request.get('quote')
            if not peer_quote_b64:
                return False, "Missing quote in peer request"
            
            self.peer_quote = base64.b64decode(peer_quote_b64)
            peer_tee_type = peer_request.get('tee_type')
            
            # Log nonce details for debugging
            logger.info(f"Verifying peer attestation: TEE type={peer_tee_type}, nonce length={len(nonce) if nonce else 0}, quote length={len(self.peer_quote)}")
            logger.debug(f"Nonce (hex): {nonce.hex() if nonce else 'None'}")
            logger.debug(f"Peer quote (first 50 bytes hex): {self.peer_quote[:50].hex() if len(self.peer_quote) >= 50 else self.peer_quote.hex()}")
            
            # Verify quote with Azure Attestation Service
            is_valid, result = self.azure_verifier.verify_quote(
                quote=self.peer_quote,
                tee_type=peer_tee_type,
                nonce=nonce
            )
            
            if is_valid:
                self.peer_verified = True
                # Generate session key from both quotes
                self.session_key = self._derive_session_key(self.local_quote, self.peer_quote)
                logger.info("Peer attestation verification successful")
                return True, ""
            else:
                error_msg = result.get('error', 'Attestation verification failed')
                logger.error(f"Peer attestation verification failed: {error_msg}")
                logger.debug(f"Verification result: {result}")
                return False, error_msg
                
        except Exception as e:
            logger.error(f"Error verifying peer attestation: {str(e)}", exc_info=True)
            return False, f"Error verifying peer attestation: {str(e)}"
    
    def create_attestation_response(self, verified: bool, error: str = "") -> Dict:
        """
        Create response to peer's attestation request
        
        Args:
            verified: Whether peer attestation was verified
            error: Error message if verification failed
            
        Returns:
            Dictionary containing attestation response
        """
        return {
            'session_id': self.session_id,
            'verified': verified,
            'error': error,
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'attestation_response'
        }
    
    def _derive_session_key(self, quote1: bytes, quote2: bytes) -> bytes:
        """
        Derive session key from two attestation quotes
        
        Args:
            quote1: First attestation quote
            quote2: Second attestation quote
            
        Returns:
            Derived session key (32 bytes)
        """
        # Combine quotes deterministically
        combined = quote1 + quote2 + self.session_id.encode()
        # Use SHA-256 to derive key
        return hashlib.sha256(combined).digest()
    
    def is_session_ready(self) -> bool:
        """Check if mutual attestation is complete and session is ready"""
        return self.peer_verified and self.session_key is not None
    
    def encrypt_message(self, message: bytes) -> bytes:
        """
        Encrypt message using session key
        
        Note: This is a simplified implementation.
        In production, use proper authenticated encryption (e.g., AES-GCM)
        """
        if not self.session_key:
            raise ValueError("Session key not established")
        
        # Simplified encryption - use proper crypto in production
        from cryptography.fernet import Fernet
        key = base64.urlsafe_b64encode(self.session_key)
        f = Fernet(key)
        return f.encrypt(message)
    
    def decrypt_message(self, encrypted_message: bytes) -> bytes:
        """
        Decrypt message using session key
        """
        if not self.session_key:
            raise ValueError("Session key not established")
        
        from cryptography.fernet import Fernet
        key = base64.urlsafe_b64encode(self.session_key)
        f = Fernet(key)
        return f.decrypt(encrypted_message)
