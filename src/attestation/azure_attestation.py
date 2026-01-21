"""
Azure Attestation Service Integration
Handles verification of attestation quotes from SEV and TDX TEEs
Uses REST API calls exclusively - no Azure SDK dependencies

REST API Endpoints (based on official Azure documentation):
- POST {endpoint}/attest/SevSnpVm?api-version=2022-08-01 (for SEV-SNP)
- POST {endpoint}/attest/TdxVm?api-version=2025-06-01 (for TDX)

Reference:
- TDX: https://learn.microsoft.com/en-us/rest/api/attestation/attestation/attest-tdx-vm
- SEV-SNP: Azure Attestation Service REST API

Note: Azure Attestation Service attestation endpoints are public and do not require authentication.
Authentication is only needed for policy management, not for attestation requests.

Response Format:
- Azure returns a JWT token containing attestation claims
- The token is decoded to extract claims for validation
"""

import os
import json
import base64
import logging
import subprocess
import shutil
import urllib.parse
import urllib.request
import hashlib
import tempfile
from pathlib import Path
from typing import Dict, Optional, Tuple
import requests

# Set up logger for this module
logger = logging.getLogger(__name__)

# SEV-SNP constants
TPM_NV_INDEX_SNP = "0x01400001"
SNP_REPORT_OFFSET = 32
SNP_REPORT_SIZE = 1184

# TDX constants
TPM_NVINDEX_ATTESTATION_REPORT = "0x01400001"  # Same NV index as SEV, but different format
TPM_NVINDEX_ATTESTATION_REPORT_SIZE = 2600
AZ_HCL_HEADER_SIZE = 32
TDREPORT_SIZE = 1024
MRTD_OFFSET = 528  # MRTD location inside TDREPORT
MRTD_SIZE = 48
NV_REPORT_DATA = "0x01400002"  # NV index for user data (file hash)

# Azure Instance Metadata Service (IMDS) endpoint
IMDS_BASE = "http://169.254.169.254"
IMDS_TDQUOTE_URL = f"{IMDS_BASE}/acc/tdquote"
IMDS_HDRS = {"Metadata": "true"}


class AzureAttestationVerifier:
    """Verifies attestation quotes using Azure Attestation Service REST API"""
    
    def __init__(self, endpoint: str):
        """
        Initialize Azure Attestation Verifier
        
        Args:
            endpoint: Azure Attestation Service endpoint URL
        """
        self.endpoint = endpoint.rstrip('/')
    
    def verify_quote(self, quote: bytes, tee_type: str, nonce: Optional[bytes] = None,
                     runtime_data: Optional[Dict] = None, init_time_data: Optional[Dict] = None) -> Tuple[bool, Dict]:
        """
        Verify an attestation quote using Azure Attestation Service REST API
        
        Args:
            quote: The attestation quote bytes
            tee_type: Type of TEE ('SEV' or 'TDX')
            nonce: Optional nonce used for quote generation (as bytes, will be converted to string)
            runtime_data: Optional runtime data (dict with 'data' and 'dataType' fields)
            init_time_data: Optional initialization time data (dict with 'data' and 'dataType' fields)
            
        Returns:
            Tuple of (is_valid, attestation_result)
        """
        logger.info(f"Starting attestation verification for TEE type: {tee_type}")
        logger.debug(f"Quote length: {len(quote)} bytes, Nonce provided: {nonce is not None}")
        
        try:
            # Determine attestation type and API version for Azure API
            # Based on official Azure Attestation Service REST API documentation
            if tee_type.upper() == "SEV":
                attestation_type = "SevSnpVm"  # SEV-SNP VM attestation
                api_version = "2025-06-01"  # Updated to match Azure MAA latest API version
                # SEV uses 'report' field
                # The report field is base64url(JSON({ "SnpReport": b64url(raw_report), "VcekCertChain": b64(pem_chain) }))
                # If quote is already a string (MAA report field format), use it directly
                # Otherwise, assume it's raw bytes and encode it
                quote_field = "report"
                if isinstance(quote, bytes):
                    # Try to decode as UTF-8 string (MAA report field format)
                    try:
                        quote_str = quote.decode('utf-8')
                        # Check if it looks like a base64url string (MAA report field)
                        # Base64url strings contain only A-Z, a-z, 0-9, -, _ characters
                        if all(c.isalnum() or c in ('-', '_') for c in quote_str):
                            quote_encoded = quote_str
                            logger.debug("Using quote as MAA report field (base64url string)")
                        else:
                            # Not a valid base64url string, treat as raw bytes
                            quote_encoded = base64.b64encode(quote).decode('utf-8')
                            logger.debug("Encoding quote bytes as base64")
                    except UnicodeDecodeError:
                        # Not valid UTF-8, treat as raw bytes
                        quote_encoded = base64.b64encode(quote).decode('utf-8')
                        logger.debug("Quote is not UTF-8, encoding as base64")
                else:
                    # Already a string, use directly
                    quote_encoded = str(quote)
                    logger.debug("Using quote as string directly")
            elif tee_type.upper() == "TDX":
                attestation_type = "TdxVm"  # TDX VM attestation
                api_version = "2025-06-01"
                # TDX uses 'quote' field (base64url encoded)
                quote_field = "quote"
                # Convert to base64url (replace + with -, / with _, remove padding)
                quote_b64 = base64.b64encode(quote).decode('utf-8')
                quote_encoded = quote_b64.replace('+', '-').replace('/', '_').rstrip('=')
            else:
                error_msg = f"Unsupported TEE type: {tee_type}"
                logger.error(error_msg)
                raise ValueError(error_msg)
            
            # Prepare request body according to Azure API specification
            request_body = {
                quote_field: quote_encoded
            }
            
            # Add nonce if provided (as string per Azure API specification)
            if nonce:
                # Azure API expects nonce as a plain string
                # Convert bytes to base64 string for transmission
                request_body["nonce"] = base64.b64encode(nonce).decode('utf-8')
                logger.debug("Nonce added to request body")
            
            # Add optional runtime data if provided
            if runtime_data:
                request_body["runtimeData"] = runtime_data
                logger.debug("Runtime data added to request body")
            
            # Add optional init time data if provided
            if init_time_data:
                request_body["initTimeData"] = init_time_data
                logger.debug("Init time data added to request body")
            
            # Make REST API call to Azure Attestation Service
            # No authentication required - attestation endpoints are public
            attest_url = f"{self.endpoint}/attest/{attestation_type}?api-version={api_version}"
            
            headers = {
                "Content-Type": "application/json"
            }
            
            logger.info(f"Sending attestation request to Azure endpoint: {attest_url}")
            logger.debug(f"Request body keys: {list(request_body.keys())}, Quote field length: {len(quote_encoded)}")

            response = requests.post(
                attest_url,
                json=request_body,
                headers=headers,
                timeout=30
            )
            
            print(response.text)
            logger.debug(f"Azure Attestation Service response status: {response.status_code}")
            
            if response.status_code != 200:
                error_msg = f"Azure Attestation Service returned status {response.status_code}"
                try:
                    error_detail = response.json()
                    error_msg += f": {error_detail}"
                    logger.error(f"Full error response: {json.dumps(error_detail, indent=2)}")
                except Exception as e:
                    error_msg += f": {response.text}"
                    logger.error(f"Azure Attestation Service error (non-JSON): {response.text[:500]}")
                    logger.debug(f"Failed to parse error response as JSON: {e}")
                
                # Log request details for debugging
                logger.debug(f"Request details - TEE type: {tee_type}, Nonce provided: {nonce is not None}, Nonce length: {len(nonce) if nonce else 0}")
                if nonce:
                    logger.debug(f"Nonce (hex): {nonce.hex()}")
                logger.debug(f"Quote length: {len(quote)}, Quote type: {type(quote)}")
                logger.debug(f"Request URL: {attest_url}")
                logger.debug(f"Request body keys: {list(request_body.keys())}")
                
                return False, {
                    'error': error_msg,
                    'is_valid': False,
                    'tee_type': tee_type,
                    'status_code': response.status_code,
                    'response_body': error_detail if 'error_detail' in locals() else response.text[:500]
                }
            
            # Parse response
            try:
                response_data = response.json()
                logger.debug("Successfully parsed JSON response from Azure")
            except Exception as e:
                logger.error(f"Failed to parse Azure response as JSON: {e}")
                logger.error(f"Response text (first 500 chars): {response.text[:500]}")
                raise ValueError(f"Invalid JSON response from Azure: {e}")
            
            # Azure Attestation Service returns a JWT token in the response
            # Extract and decode the token to get claims
            token = response_data.get('token')
            if token:
                logger.debug("JWT token found in response, decoding...")
                # Decode JWT token (without signature verification for now)
                # In production, you should verify the signature using Azure's public keys
                try:
                    import jwt
                    claims = jwt.decode(token, options={"verify_signature": False})
                    logger.debug("Successfully decoded JWT token using PyJWT")
                except ImportError:
                    logger.warning("PyJWT not available, attempting manual JWT parsing")
                    # If PyJWT is not available, try to parse manually
                    # JWT format: header.payload.signature
                    parts = token.split('.')
                    if len(parts) >= 2:
                        # Decode payload (add padding if needed)
                        payload_b64 = parts[1]
                        padding = len(payload_b64) % 4
                        if padding:
                            payload_b64 += '=' * (4 - padding)
                        payload_json = base64.urlsafe_b64decode(payload_b64)
                        claims = json.loads(payload_json)
                        logger.debug("Successfully decoded JWT token manually")
                    else:
                        logger.warning(f"Invalid JWT token format, expected 3 parts, got {len(parts)}")
                        claims = {'raw_token': token}
                except Exception as e:
                    logger.error(f"Failed to decode JWT token: {e}")
                    logger.exception("Exception details:")
                    raise
            else:
                # If no token, use the response data directly
                logger.warning("No JWT token found in response, using response data directly")
                claims = response_data
            
            # Basic validation
            logger.debug("Validating attestation claims...")
            is_valid = self._validate_claims(claims, tee_type)
            
            if is_valid:
                logger.info(f"Attestation verification successful for TEE type: {tee_type}")
            else:
                logger.warning(f"Attestation verification failed validation for TEE type: {tee_type}")
            
            return is_valid, {
                'claims': claims,
                'is_valid': is_valid,
                'tee_type': tee_type,
                'token': token if 'token' in response_data else None
            }
            
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout error during attestation verification: {e}")
            logger.exception("Timeout exception details:")
            return False, {
                'error': f"Network timeout: {str(e)}",
                'is_valid': False,
                'tee_type': tee_type
            }
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error during attestation verification: {e}")
            logger.exception("Connection exception details:")
            return False, {
                'error': f"Connection error: {str(e)}",
                'is_valid': False,
                'tee_type': tee_type
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error during attestation verification: {e}")
            logger.exception("Request exception details:")
            return False, {
                'error': f"Network error: {str(e)}",
                'is_valid': False,
                'tee_type': tee_type
            }
        except ValueError as e:
            logger.error(f"Value error during attestation verification: {e}")
            logger.exception("Value error exception details:")
            return False, {
                'error': str(e),
                'is_valid': False,
                'tee_type': tee_type
            }
        except Exception as e:
            logger.error(f"Unexpected error during attestation verification: {e}")
            logger.exception("Unexpected exception details:")
            return False, {
                'error': str(e),
                'is_valid': False,
                'tee_type': tee_type
            }
    
    def _validate_claims(self, claims: Dict, tee_type: str) -> bool:
        """
        Validate attestation claims
        
        Args:
            claims: Attestation claims from Azure
            tee_type: Expected TEE type
            
        Returns:
            True if claims are valid
        """
        logger.debug(f"Validating claims for TEE type: {tee_type}")
        
        # Basic validation - expand based on your security requirements
        # Check for expected TEE type in claims
        # Verify policy compliance
        # Check for expected measurements/MRENCLAVE values
        
        # Placeholder validation
        if not claims:
            logger.warning("Empty claims dictionary received")
            return False
        
        logger.debug(f"Claims keys: {list(claims.keys())[:10]}")  # Log first 10 keys
        
        # Add specific claim validation here
        # Example: verify MRENCLAVE, MRSIGNER, etc.
        
        return True
    
    def generate_nonce(self) -> bytes:
        """Generate a random nonce for attestation"""
        import secrets
        return secrets.token_bytes(32)


class AttestationQuoteGenerator:
    """
    Generates attestation quotes from TEE environment
    """
    
    @staticmethod
    def _have_cmd(cmd: str) -> bool:
        """Check if a command is available in PATH"""
        return shutil.which(cmd) is not None
    
    @staticmethod
    def _http_get_json(url: str, headers: dict) -> dict:
        """Make HTTP GET request and return JSON response"""
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))
    
    @staticmethod
    def _read_nv_blob() -> bytes:
        """
        Read SNP report blob from TPM NV index
        
        Returns:
            Raw NV blob bytes containing SNP report
            
        Raises:
            RuntimeError: If tpm2_nvread is not available or fails
        """
        if not AttestationQuoteGenerator._have_cmd("tpm2_nvread"):
            raise RuntimeError(
                "tpm2_nvread not found. Install tpm2-tools (e.g., sudo apt-get install tpm2-tools)."
            )
        
        try:
            proc = subprocess.run(
                ["tpm2_nvread", "-C", "o", TPM_NV_INDEX_SNP],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as e:
            stderr_msg = e.stderr.decode("utf-8", errors="replace") if e.stderr else ""
            raise RuntimeError(f"tpm2_nvread failed. stderr:\n{stderr_msg}")
        
        blob = proc.stdout
        need = SNP_REPORT_OFFSET + SNP_REPORT_SIZE
        if len(blob) < need:
            raise RuntimeError(
                f"NV read blob too small ({len(blob)} bytes). Need at least {need} bytes."
            )
        return blob
    
    @staticmethod
    def _extract_snp_report(nv_blob: bytes) -> bytes:
        """Extract raw 1184-byte SNP report from NV blob"""
        return nv_blob[SNP_REPORT_OFFSET : SNP_REPORT_OFFSET + SNP_REPORT_SIZE]
    
    @staticmethod
    def _b64url(data: bytes, pad: bool = False) -> str:
        """Base64URL encoding (RFC 4648 §5). Many Azure attestation examples use unpadded."""
        s = base64.urlsafe_b64encode(data).decode("ascii")
        return s if pad else s.rstrip("=")
    
    @staticmethod
    def _b64_std(data: bytes) -> str:
        """Standard base64 encoding with padding."""
        return base64.b64encode(data).decode("ascii")
    
    @staticmethod
    def _read_hcl_report_from_vtpm() -> bytes:
        """
        Reads the Azure HCL attestation report blob from vTPM NV index 0x01400001
        using tpm2_nvread.
        
        Returns:
            Raw HCL attestation report bytes (2600 bytes)
            
        Raises:
            RuntimeError: If tpm2_nvread is not available or fails
        """
        if not AttestationQuoteGenerator._have_cmd("tpm2_nvread"):
            raise RuntimeError(
                "tpm2_nvread not found. Install tpm2-tools (e.g., 'sudo apt-get install tpm2-tools')."
            )
        
        cmd = [
            "tpm2_nvread",
            "-C",
            "o",
            TPM_NVINDEX_ATTESTATION_REPORT,
            "-s",
            str(TPM_NVINDEX_ATTESTATION_REPORT_SIZE),
        ]
        
        try:
            blob = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            stderr_msg = e.output.decode("utf-8", errors="replace") if e.output else ""
            raise RuntimeError(
                "tpm2_nvread failed. You may need elevated permissions (root) or access to /dev/tpmrm0.\n"
                f"Command: {' '.join(cmd)}\n"
                f"Output:\n{stderr_msg}"
            ) from e
        
        if len(blob) < TPM_NVINDEX_ATTESTATION_REPORT_SIZE:
            raise RuntimeError(
                f"Unexpected attestation report size: got {len(blob)} bytes, expected {TPM_NVINDEX_ATTESTATION_REPORT_SIZE}."
            )
        
        # Basic sanity check: header signature should be 'HCLA'
        sig = blob[0:4]
        if sig != b"HCLA":
            raise RuntimeError(
                f"Unexpected HCL report signature {sig!r}. Expected b'HCLA'. Are you on an Azure confidential VM with vTPM?"
            )
        
        return blob
    
    @staticmethod
    def _extract_tdreport(hcl_blob: bytes) -> bytes:
        """
        Extract the 1024-byte TDREPORT from the Azure HCL attestation report.
        
        Args:
            hcl_blob: Raw HCL attestation report bytes
            
        Returns:
            TDREPORT bytes (1024 bytes)
            
        Raises:
            RuntimeError: If HCL blob is too small
        """
        start = AZ_HCL_HEADER_SIZE
        end = start + TDREPORT_SIZE
        if len(hcl_blob) < end:
            raise RuntimeError("HCL report blob too small to contain a TDREPORT payload.")
        return hcl_blob[start:end]
    
    @staticmethod
    def _extract_mrtd_from_tdreport(tdreport: bytes) -> bytes:
        """
        Extract the 48-byte MRTD from the TDREPORT.
        
        Args:
            tdreport: TDREPORT bytes (1024 bytes)
            
        Returns:
            MRTD bytes (48 bytes)
            
        Raises:
            RuntimeError: If TDREPORT is invalid size or doesn't contain MRTD
        """
        if len(tdreport) != TDREPORT_SIZE:
            raise RuntimeError(f"TDREPORT must be {TDREPORT_SIZE} bytes; got {len(tdreport)} bytes.")
        start = MRTD_OFFSET
        end = start + MRTD_SIZE
        if end > len(tdreport):
            raise RuntimeError("TDREPORT too small to contain MRTD at the expected offset.")
        return tdreport[start:end]
    
    @staticmethod
    def _get_tdquote_from_imds(tdreport: bytes) -> str:
        """
        Call Azure IMDS to obtain a TDX quote.
        
        Args:
            tdreport: TDREPORT bytes (1024 bytes)
            
        Returns:
            Quote as base64url string (no padding)
            
        Raises:
            RuntimeError: If IMDS call fails or response is invalid
        """
        report_b64url = AttestationQuoteGenerator._b64url(tdreport, pad=False)
        body = json.dumps({"report": report_b64url}).encode("utf-8")
        
        req = urllib.request.Request(
            IMDS_TDQUOTE_URL,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp_body = resp.read()
        except Exception as e:
            raise RuntimeError(
                "Failed to call Azure IMDS tdquote endpoint. "
                "Ensure you are running inside an Azure TDX CVM and IMDS is reachable."
            ) from e
        
        try:
            payload = json.loads(resp_body.decode("utf-8"))
        except Exception as e:
            raise RuntimeError(f"IMDS response was not valid JSON: {resp_body!r}") from e
        
        quote_b64url = payload.get("quote")
        if not isinstance(quote_b64url, str) or not quote_b64url:
            raise RuntimeError(f"IMDS JSON did not contain a valid 'quote' field: {payload!r}")
        
        return quote_b64url
    
    @staticmethod
    def _hash_file_and_write_to_nv(file_path: str) -> bytes:
        """
        Read a file, compute its SHA512 hash, and write it to TPM NV index 0x01400002.
        
        This method:
        1. Reads the file content
        2. Computes SHA512 hash (64 bytes)
        3. Writes the hash to TPM NV index 0x01400002 using tpm2_nvwrite
        
        Args:
            file_path: Path to the file to hash
            
        Returns:
            SHA512 hash digest (64 bytes)
            
        Raises:
            RuntimeError: If file cannot be read, tpm2_nvwrite is not available, or write fails
        """
        logger.debug(f"Hashing file and writing to NV index: {file_path}")
        
        # Read file content
        try:
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            with open(file_path_obj, 'rb') as f:
                file_content = f.read()
            
            logger.debug(f"File read successfully, length: {len(file_content)} bytes")
        except Exception as e:
            raise RuntimeError(f"Failed to read file {file_path}: {e}") from e
        
        # Compute SHA512 hash (64 bytes)
        digest = hashlib.sha512(file_content).digest()
        logger.debug(f"SHA512 hash computed: {digest.hex()}")
        
        # Check if tpm2_nvwrite is available
        if not AttestationQuoteGenerator._have_cmd("tpm2_nvwrite"):
            raise RuntimeError(
                "tpm2_nvwrite not found. Install tpm2-tools (e.g., 'sudo apt-get install tpm2-tools')."
            )
        
        # Write hash to TPM NV index 0x01400002
        # Write exactly 64 bytes into NV 0x01400002
        # Use a temporary file since tpm2_nvwrite requires seekable input
        try:
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                tmp_file.write(digest)
                tmp_file_path = tmp_file.name
            
            try:
                proc = subprocess.run(
                    [
                        "tpm2_nvwrite",
                        "-C", "o",
                        NV_REPORT_DATA,
                        "-i", tmp_file_path
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True
                )
                logger.info(f"Successfully wrote file hash to TPM NV index {NV_REPORT_DATA}")
            finally:
                # Clean up temporary file
                try:
                    os.unlink(tmp_file_path)
                except Exception:
                    pass  # Ignore cleanup errors
        except subprocess.CalledProcessError as e:
            stderr_msg = e.stderr.decode("utf-8", errors="replace") if e.stderr else ""
            raise RuntimeError(
                f"tpm2_nvwrite failed. You may need elevated permissions (root) or access to /dev/tpmrm0.\n"
                f"stderr:\n{stderr_msg}"
            ) from e
        
        return digest
    
    @staticmethod
    def _extract_mrtd_from_tdx_quote(quote_bytes: bytes) -> Optional[bytes]:
        """
        Extract MRTD (Measurement Register Table Digest) from TDX quote
        
        TDX quote structure:
        - Quote header (variable size, typically 48 bytes)
        - TD report (144 bytes) - contains MRTD at offset 0x80 (128 bytes)
        - Signature data (variable size)
        
        MRTD is a 48-byte SHA384 digest located at offset 0x80 within the TD report.
        
        Args:
            quote_bytes: Raw TDX quote bytes
            
        Returns:
            MRTD bytes (48 bytes) or None if extraction fails
        """
        try:
            # TD report is 144 bytes and typically starts after the quote header
            # The quote header is typically 48 bytes for TDX quotes
            # MRTD is at offset 0x80 (128 bytes) from the start of the TD report
            
            # Try different possible offsets for TD report start
            # Common TDX quote header sizes: 48, 64, or 80 bytes
            possible_header_sizes = [48, 64, 80]
            
            for header_size in possible_header_sizes:
                if len(quote_bytes) < header_size + 144:
                    continue
                
                # TD report starts after header
                td_report_start = header_size
                td_report_end = td_report_start + 144
                
                if len(quote_bytes) < td_report_end:
                    continue
                
                # Extract TD report
                td_report = quote_bytes[td_report_start:td_report_end]
                
                # MRTD is at offset 0x80 (128 bytes) within TD report, 48 bytes long
                mrtd_offset = 128
                mrtd_size = 48
                
                if len(td_report) >= mrtd_offset + mrtd_size:
                    mrtd = td_report[mrtd_offset:mrtd_offset + mrtd_size]
                    logger.debug(f"Extracted MRTD using header size {header_size} bytes")
                    return mrtd
            
            # If standard offsets don't work, try to find TD report by looking for known patterns
            # TD report typically starts with version field (4 bytes) and other known fields
            # For now, log a warning and return None
            logger.warning(f"Could not extract MRTD from quote (length: {len(quote_bytes)} bytes)")
            logger.debug(f"Quote first 100 bytes (hex): {quote_bytes[:100].hex()}")
            return None
            
        except Exception as e:
            logger.error(f"Error extracting MRTD: {e}")
            logger.exception("Exception details:")
            return None
    
    @staticmethod
    def _fetch_vcek_cert_chain_pem() -> bytes:
        """
        Fetch VCEK cert and chain from Azure THIM endpoint (metadata service).
        
        Returns:
            PEM bytes concatenating vcekCert + certificateChain
            
        Raises:
            RuntimeError: If THIM endpoint is unavailable or response is invalid
        """
        url = f"{IMDS_BASE}/metadata/THIM/amd/certification"
        try:
            j = AttestationQuoteGenerator._http_get_json(url, IMDS_HDRS)
        except Exception as e:
            raise RuntimeError(f"Failed to fetch VCEK cert chain from THIM endpoint: {e}")
        
        vcek = j.get("vcekCert", "")
        chain = j.get("certificateChain", "")
        if not vcek or not chain:
            raise RuntimeError(
                f"THIM response missing vcekCert/certificateChain. Keys present: {list(j.keys())}"
            )
        
        pem = (vcek + "\n" + chain + "\n").encode("utf-8")
        return pem
    
    @staticmethod
    def _build_maa_report_field(raw_snp_report: bytes, vcek_chain_pem: bytes, tpm_quote: Optional[Dict[str, bytes]] = None) -> str:
        """
        Build the outer MAA request field 'report' as base64url(inner_json_bytes),
        where inner JSON has SnpReport (base64url of raw SNP report bytes) and
        VcekCertChain (standard base64 of PEM bytes), and optionally TPM quote data.
        
        Note: MAA's "report" field is NOT the raw 1184-byte SNP report.
        It is base64url( JSON( { "SnpReport": b64url(raw_report), "VcekCertChain": b64(pem_chain), ... } ) )
        
        Args:
            raw_snp_report: Raw 1184-byte SNP report bytes
            vcek_chain_pem: VCEK certificate chain as PEM bytes
            tpm_quote: Optional TPM quote dictionary with 'message', 'signature', and 'pcrs' keys
            
        Returns:
            Base64URL-encoded JSON string ready for MAA attestation request
        """
        inner = {
            "SnpReport": AttestationQuoteGenerator._b64url(raw_snp_report),
            "VcekCertChain": AttestationQuoteGenerator._b64_std(vcek_chain_pem),
        }
        
        # Add TPM quote data if provided
        if tpm_quote:
            inner["TpmQuote"] = {
                "message": AttestationQuoteGenerator._b64url(tpm_quote['message']),
                "signature": AttestationQuoteGenerator._b64url(tpm_quote['signature']),
                "pcrs": AttestationQuoteGenerator._b64url(tpm_quote['pcrs'])
            }
            logger.debug("TPM quote data added to MAA report field")
        
        inner_bytes = json.dumps(inner, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return AttestationQuoteGenerator._b64url(inner_bytes)
    
    @staticmethod
    def _hash_file_and_extend_pcr(file_path: str, pcr_index: int = 23) -> bytes:
        """
        Read a file, compute its SHA256 hash, and extend it into a TPM PCR.
        
        This method:
        1. Reads the file content
        2. Computes SHA256 hash (32 bytes)
        3. Extends the hash into the specified PCR using tpm2_pcrextend
        
        Args:
            file_path: Path to the file to hash
            pcr_index: PCR index to extend (default: 23 for user mode/runtime data)
            
        Returns:
            SHA256 hash digest (32 bytes)
            
        Raises:
            RuntimeError: If file cannot be read, tpm2_pcrextend is not available, or extend fails
        """
        logger.debug(f"Hashing file and extending PCR {pcr_index}: {file_path}")
        
        # Read file content
        try:
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            with open(file_path_obj, 'rb') as f:
                file_content = f.read()
            
            logger.debug(f"File read successfully, length: {len(file_content)} bytes")
        except Exception as e:
            raise RuntimeError(f"Failed to read file {file_path}: {e}") from e
        
        # Compute SHA256 hash (32 bytes)
        digest = hashlib.sha256(file_content).digest()
        logger.debug(f"SHA256 hash computed: {digest.hex()}")
        
        # Check if tpm2_pcrextend is available
        if not AttestationQuoteGenerator._have_cmd("tpm2_pcrextend"):
            raise RuntimeError(
                "tpm2_pcrextend not found. Install tpm2-tools (e.g., 'sudo apt-get install tpm2-tools')."
            )
        
        # Extend hash into PCR using tpm2_pcrextend
        # Format: tpm2_pcrextend <pcr_index>:sha256=<hash_hex>
        hash_hex = digest.hex()
        cmd = [
            "tpm2_pcrextend",
            f"{pcr_index}:sha256={hash_hex}"
        ]
        
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
            logger.info(f"Successfully extended file hash into PCR {pcr_index}")
        except subprocess.CalledProcessError as e:
            stderr_msg = e.stderr.decode("utf-8", errors="replace") if e.stderr else ""
            raise RuntimeError(
                f"tpm2_pcrextend failed. You may need elevated permissions (root) or access to /dev/tpmrm0.\n"
                f"Command: {' '.join(cmd)}\n"
                f"stderr:\n{stderr_msg}"
            ) from e
        
        return digest
    
    @staticmethod
    def _read_akpub_from_vtpm() -> bytes:
        """
        Read the vTPM Attestation Key (AK) public key from NV index 0x81000003.
        
        Returns:
            AK public key as PEM bytes
            
        Raises:
            RuntimeError: If tpm2_readpublic is not available or read fails
        """
        logger.debug("Reading vTPM AK public key from NV index 0x81000003")
        
        if not AttestationQuoteGenerator._have_cmd("tpm2_readpublic"):
            raise RuntimeError(
                "tpm2_readpublic not found. Install tpm2-tools (e.g., 'sudo apt-get install tpm2-tools')."
            )
        
        # Create temporary file for AK public key output
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pem') as akpub_file:
            akpub_path = akpub_file.name
        
        try:
            # Read AK public key
            cmd = [
                "tpm2_readpublic",
                "-c", "0x81000003",  # AK context handle
                "-f", "pem",         # Output format: PEM
                "-o", akpub_path     # Output file
            ]
            
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
            
            # Read the AK public key
            with open(akpub_path, 'rb') as f:
                akpub_pem = f.read()
            
            logger.info("vTPM AK public key read successfully")
            logger.debug(f"AK public key length: {len(akpub_pem)} bytes")
            
            return akpub_pem
            
        except subprocess.CalledProcessError as e:
            stderr_msg = e.stderr.decode("utf-8", errors="replace") if e.stderr else ""
            raise RuntimeError(
                f"tpm2_readpublic failed. You may need elevated permissions (root) or access to /dev/tpmrm0.\n"
                f"Command: {' '.join(cmd)}\n"
                f"stderr:\n{stderr_msg}"
            ) from e
        finally:
            # Clean up temporary file
            try:
                os.unlink(akpub_path)
            except Exception:
                pass  # Ignore cleanup errors
    
    @staticmethod
    def _generate_tpm_quote(nonce: bytes, pcr_list: list = [15, 16, 22, 23]) -> Dict[str, bytes]:
        """
        Generate a TPM quote using the vTPM's attestation key.
        
        This method:
        1. Uses tpm2_quote to generate a quote with specified PCRs
        2. Returns the quote message, signature, and PCR values
        
        Args:
            nonce: Nonce bytes for freshness (will be converted to hex)
            pcr_list: List of PCR indices to quote (default: [15, 16, 22, 23])
            
        Returns:
            Dictionary with keys:
                - 'message': Quote message bytes
                - 'signature': Quote signature bytes
                - 'pcrs': PCR values bytes
                
        Raises:
            RuntimeError: If tpm2_quote is not available or quote generation fails
        """
        logger.debug(f"Generating TPM quote with PCRs: {pcr_list}, nonce length: {len(nonce)} bytes")
        
        # Check if tpm2_quote is available
        if not AttestationQuoteGenerator._have_cmd("tpm2_quote"):
            raise RuntimeError(
                "tpm2_quote not found. Install tpm2-tools (e.g., 'sudo apt-get install tpm2-tools')."
            )
        
        # Convert nonce to hex string
        nonce_hex = nonce.hex()
        
        # Build PCR selection string (e.g., "sha256:15,16,22,23")
        pcr_selection = "sha256:" + ",".join(map(str, pcr_list))
        
        # Create temporary files for quote outputs
        with tempfile.NamedTemporaryFile(delete=False, suffix='.msg') as msg_file, \
             tempfile.NamedTemporaryFile(delete=False, suffix='.sig') as sig_file, \
             tempfile.NamedTemporaryFile(delete=False, suffix='.pcrs') as pcrs_file:
            
            msg_path = msg_file.name
            sig_path = sig_file.name
            pcrs_path = pcrs_file.name
        
        try:
            # Generate TPM quote
            # AK context handle: 0x81000003 (vTPM attestation key)
            cmd = [
                "tpm2_quote",
                "-c", "0x81000003",  # AK context handle
                "-l", pcr_selection,  # PCR selection
                "-q", nonce_hex,       # Nonce (hex string)
                "-m", msg_path,       # Message output file
                "-s", sig_path,       # Signature output file
                "-o", pcrs_path,      # PCR values output file
                "-g", "sha256"       # Hash algorithm
            ]
            
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
            
            # Read the output files
            with open(msg_path, 'rb') as f:
                message = f.read()
            with open(sig_path, 'rb') as f:
                signature = f.read()
            with open(pcrs_path, 'rb') as f:
                pcrs = f.read()
            
            logger.info(f"TPM quote generated successfully")
            logger.debug(f"Quote message length: {len(message)} bytes")
            logger.debug(f"Quote signature length: {len(signature)} bytes")
            logger.debug(f"PCR values length: {len(pcrs)} bytes")
            
            return {
                'message': message,
                'signature': signature,
                'pcrs': pcrs
            }
            
        except subprocess.CalledProcessError as e:
            stderr_msg = e.stderr.decode("utf-8", errors="replace") if e.stderr else ""
            raise RuntimeError(
                f"tpm2_quote failed. You may need elevated permissions (root) or access to /dev/tpmrm0.\n"
                f"Command: {' '.join(cmd)}\n"
                f"stderr:\n{stderr_msg}"
            ) from e
        finally:
            # Clean up temporary files
            for tmp_path in [msg_path, sig_path, pcrs_path]:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass  # Ignore cleanup errors
    
    @staticmethod
    def generate_sev_quote(nonce: bytes) -> bytes:
        """
        Generate SEV-SNP attestation quote for Azure MAA with PCR measurements
        
        This implementation:
        1. Hashes tee_server.py and extends it into PCR 23 (user mode/runtime data)
        2. Generates a TPM quote including PCR 23 and other relevant PCRs (15, 16, 22)
        3. Reads the SNP report from TPM NV index using tpm2_nvread
        4. Extracts the raw 1184-byte SNP report
        5. Fetches the VCEK certificate chain from Azure THIM endpoint
        6. Builds the MAA report field format (base64url of JSON containing SnpReport, VcekCertChain, and TPM quote)
        
        Args:
            nonce: Nonce bytes used for TPM quote generation and attestation
            
        Returns:
            Bytes representation of the MAA report field (base64url-encoded JSON string as bytes)
            This can be directly used with Azure Attestation Service's attest/SevSnpVm endpoint
            
        Raises:
            RuntimeError: If tpm2_nvread is not available, TPM read fails, or THIM endpoint is unavailable
            Exception: For other errors during quote generation
        """
        logger.info("Generating SEV-SNP attestation quote with PCR measurements")
        logger.debug(f"Nonce length: {len(nonce)} bytes")
        
        try:
            # Step 1: Hash tee_server.py and extend into PCR 23
            try:
                # Determine the path to tee_server.py relative to this file
                current_file = Path(__file__)
                # Navigate from src/attestation/azure_attestation.py to src/server/tee_server.py
                tee_server_path = current_file.parent.parent / "server" / "tee_server.py"
                logger.debug(f"Hashing tee_server.py and extending PCR 23: {tee_server_path}")
                file_hash = AttestationQuoteGenerator._hash_file_and_extend_pcr(str(tee_server_path), pcr_index=23)
                file_hash_b64 = AttestationQuoteGenerator._b64_std(file_hash)
                print(f"TEE_SERVER_HASH_BASE64: {file_hash_b64}")
                logger.info(f"tee_server.py hash extended into PCR 23: {file_hash.hex()}")
                logger.info(f"tee_server.py hash (base64): {file_hash_b64}")
            except Exception as e:
                logger.warning(f"Failed to hash and extend tee_server.py into PCR: {e}")
                logger.debug("Continuing with quote generation despite PCR extend failure")
            
            # Step 2: Generate TPM quote with PCR 23 (and other relevant PCRs)
            tpm_quote = None
            try:
                logger.debug("Generating TPM quote with PCRs 15, 16, 22, 23")
                tpm_quote = AttestationQuoteGenerator._generate_tpm_quote(nonce, pcr_list=[15, 16, 22, 23])
                logger.info("TPM quote generated successfully")
            except Exception as e:
                logger.warning(f"Failed to generate TPM quote: {e}")
                logger.debug("Continuing with quote generation despite TPM quote failure")
            
            # Step 3: Read SNP report from TPM NV index
            logger.debug("Reading SNP report from TPM NV index")
            nv_blob = AttestationQuoteGenerator._read_nv_blob()
            
            # Step 4: Extract raw 1184-byte SNP report
            logger.debug("Extracting raw SNP report from NV blob")
            raw_report = AttestationQuoteGenerator._extract_snp_report(nv_blob)
            logger.debug(f"Extracted SNP report, length: {len(raw_report)} bytes")
            
            # Step 5: Fetch VCEK certificate chain from Azure THIM endpoint
            logger.debug("Fetching VCEK certificate chain from Azure THIM endpoint")
            vcek_chain_pem = AttestationQuoteGenerator._fetch_vcek_cert_chain_pem()
            logger.debug(f"Fetched VCEK cert chain, length: {len(vcek_chain_pem)} bytes")
            
            # Step 6: Build MAA report field (base64url of JSON with SnpReport, VcekCertChain, and optionally TPM quote)
            logger.debug("Building MAA report field")
            report_field = AttestationQuoteGenerator._build_maa_report_field(
                raw_report, 
                vcek_chain_pem,
                tpm_quote=tpm_quote
            )
            
            # Convert to bytes for return (the report_field is a base64url string)
            quote_bytes = report_field.encode('utf-8')
            logger.info(f"SEV-SNP quote generated successfully, report field length: {len(quote_bytes)} bytes")
            return quote_bytes
            
        except RuntimeError as e:
            logger.error(f"Failed to generate SEV quote: {e}")
            logger.exception("Runtime error details:")
            raise
        except Exception as e:
            logger.error(f"Failed to generate SEV quote: {e}")
            logger.exception("Exception details:")
            raise 
        
    @staticmethod
    def generate_tdx_quote(nonce: bytes) -> bytes:
        """
        Generate TDX attestation quote using Azure IMDS endpoint
        
        This implementation:
        1. Hashes tee_server.py and writes it to TPM NV index 0x01400002 (for inclusion in attestation)
        2. Reads Azure HCL attestation report from TPM NV index 0x01400001 (2600 bytes)
        3. Extracts the embedded 1024-byte TDREPORT (Intel TDX payload)
        4. POSTs TDREPORT to Azure IMDS /acc/tdquote to obtain the quote
        5. Extracts MRTD from TDREPORT and logs it
        
        Args:
            nonce: Nonce bytes (currently not used by Azure IMDS endpoint, but kept for API compatibility)
            
        Returns:
            Raw TDX quote bytes (decoded from base64url response)
            
        Raises:
            RuntimeError: If tpm2_nvread is not available, TPM read fails, or IMDS call fails
            Exception: For other errors during quote generation
        """
        logger.info("Generating TDX attestation quote")
        logger.debug(f"Nonce length: {len(nonce)} bytes (note: nonce not currently used by IMDS endpoint)")
        
        try:
            # Hash tee_server.py and write to TPM NV index 0x01400002
            # This hash will be included in the attestation quote report data
            try:
                # Determine the path to tee_server.py relative to this file
                current_file = Path(__file__)
                # Navigate from src/attestation/azure_attestation.py to src/server/tee_server.py
                tee_server_path = current_file.parent.parent / "server" / "tee_server.py"
                logger.debug(f"Hashing tee_server.py and writing to NV index: {tee_server_path}")
                file_hash = AttestationQuoteGenerator._hash_file_and_write_to_nv(str(tee_server_path))
                file_hash_b64 = AttestationQuoteGenerator._b64_std(file_hash)
                print(f"TEE_SERVER_HASH_BASE64: {file_hash_b64}")
                logger.info(f"tee_server.py hash written to NV index {NV_REPORT_DATA}: {file_hash.hex()}")
                logger.info(f"tee_server.py hash (base64): {file_hash_b64}")
            except Exception as e:
                logger.warning(f"Failed to hash and write tee_server.py to NV index: {e}")
                logger.debug("Continuing with quote generation despite file hash write failure")
            
            # Read HCL attestation report from vTPM
            logger.debug("Reading HCL attestation report from TPM NV index")
            hcl_blob = AttestationQuoteGenerator._read_hcl_report_from_vtpm()
            logger.debug(f"HCL report read, length: {len(hcl_blob)} bytes")
            
            # Extract TDREPORT from HCL report
            logger.debug("Extracting TDREPORT from HCL report")
            tdreport = AttestationQuoteGenerator._extract_tdreport(hcl_blob)
            logger.debug(f"TDREPORT extracted, length: {len(tdreport)} bytes")
            
            # Extract MRTD from TDREPORT and print/log it
            try:
                mrtd = AttestationQuoteGenerator._extract_mrtd_from_tdreport(tdreport)
                mrtd_b64 = AttestationQuoteGenerator._b64_std(mrtd)
                print(f"MRTD_BASE64: {mrtd_b64}")
                logger.info(f"MRTD extracted from TDREPORT: {mrtd_b64}")
            except Exception as e:
                logger.warning(f"Could not extract MRTD from TDREPORT: {e}")
            
            # Call Azure IMDS to get the quote
            logger.debug("Calling Azure IMDS tdquote endpoint")
            quote_b64url = AttestationQuoteGenerator._get_tdquote_from_imds(tdreport)
            logger.debug(f"Quote received from IMDS, length: {len(quote_b64url)} characters")
            
            # Decode base64url quote to bytes
            # Replace base64url characters and add padding if needed
            quote_b64 = quote_b64url.replace('-', '+').replace('_', '/')
            padding = len(quote_b64) % 4
            if padding:
                quote_b64 += '=' * (4 - padding)
            
            quote_bytes = base64.b64decode(quote_b64)
            logger.info(f"TDX quote generated successfully, length: {len(quote_bytes)} bytes")
            
            return quote_bytes
            
        except RuntimeError as e:
            logger.error(f"Failed to generate TDX quote: {e}")
            logger.exception("Runtime error details:")
            raise
        except Exception as e:
            logger.error(f"Failed to generate TDX quote: {e}")
            logger.exception("Exception details:")
            raise
