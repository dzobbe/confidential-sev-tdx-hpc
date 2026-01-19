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
from typing import Dict, Optional, Tuple
import requests

# Set up logger for this module
logger = logging.getLogger(__name__)

# SEV-SNP constants
TPM_NV_INDEX_SNP = "0x01400001"
SNP_REPORT_OFFSET = 32
SNP_REPORT_SIZE = 1184

# Azure Instance Metadata Service (IMDS) endpoint
IMDS_BASE = "http://169.254.169.254"
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
            
            logger.debug(f"Azure Attestation Service response status: {response.status_code}")
            
            if response.status_code != 200:
                error_msg = f"Azure Attestation Service returned status {response.status_code}"
                try:
                    error_detail = response.json()
                    error_msg += f": {error_detail}"
                    logger.error(f"Azure Attestation Service error response: {error_detail}")
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
    def _build_maa_report_field(raw_snp_report: bytes, vcek_chain_pem: bytes) -> str:
        """
        Build the outer MAA request field 'report' as base64url(inner_json_bytes),
        where inner JSON has SnpReport (base64url of raw SNP report bytes) and
        VcekCertChain (standard base64 of PEM bytes).
        
        Note: MAA's "report" field is NOT the raw 1184-byte SNP report.
        It is base64url( JSON( { "SnpReport": b64url(raw_report), "VcekCertChain": b64(pem_chain) } ) )
        
        Returns:
            Base64URL-encoded JSON string ready for MAA attestation request
        """
        inner = {
            "SnpReport": AttestationQuoteGenerator._b64url(raw_snp_report),
            "VcekCertChain": AttestationQuoteGenerator._b64_std(vcek_chain_pem),
        }
        inner_bytes = json.dumps(inner, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return AttestationQuoteGenerator._b64url(inner_bytes)
    
    @staticmethod
    def generate_sev_quote(nonce: bytes) -> bytes:
        """
        Generate SEV-SNP attestation quote for Azure MAA
        
        This implementation:
        1. Reads the SNP report from TPM NV index using tpm2_nvread
        2. Extracts the raw 1184-byte SNP report
        3. Fetches the VCEK certificate chain from Azure THIM endpoint
        4. Builds the MAA report field format (base64url of JSON containing SnpReport and VcekCertChain)
        
        Args:
            nonce: Nonce bytes (currently not used in SNP report extraction, but kept for API compatibility)
            
        Returns:
            Bytes representation of the MAA report field (base64url-encoded JSON string as bytes)
            This can be directly used with Azure Attestation Service's attest/SevSnpVm endpoint
            
        Raises:
            RuntimeError: If tpm2_nvread is not available, TPM read fails, or THIM endpoint is unavailable
            Exception: For other errors during quote generation
        """
        logger.info("Generating SEV-SNP attestation quote")
        logger.debug(f"Nonce length: {len(nonce)} bytes")
        
        try:
            # Read SNP report from TPM NV index
            logger.debug("Reading SNP report from TPM NV index")
            nv_blob = AttestationQuoteGenerator._read_nv_blob()
            
            # Extract raw 1184-byte SNP report
            logger.debug("Extracting raw SNP report from NV blob")
            raw_report = AttestationQuoteGenerator._extract_snp_report(nv_blob)
            logger.debug(f"Extracted SNP report, length: {len(raw_report)} bytes")
            
            # Fetch VCEK certificate chain from Azure THIM endpoint
            logger.debug("Fetching VCEK certificate chain from Azure THIM endpoint")
            vcek_chain_pem = AttestationQuoteGenerator._fetch_vcek_cert_chain_pem()
            logger.debug(f"Fetched VCEK cert chain, length: {len(vcek_chain_pem)} bytes")
            
            # Build MAA report field (base64url of JSON with SnpReport and VcekCertChain)
            logger.debug("Building MAA report field")
            report_field = AttestationQuoteGenerator._build_maa_report_field(raw_report, vcek_chain_pem)
            
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
        
    def generate_tdx_quote(nonce: bytes) -> bytes:
        """
        Generate TDX attestation quote using Intel Trust Authority Client library
        
        Uses AzureTDXAdapter from inteltrustauthorityclient to collect TDX evidence
        from the TEE environment.
        
        Args:
            nonce: Nonce bytes to include in the quote
            
        Returns:
            Raw TDX quote bytes
            
        Raises:
            ImportError: If Intel Trust Authority Client library is not installed
            Exception: If evidence collection fails (e.g., not in TDX environment,
                      missing permissions, or TDX not properly configured)
        """
        logger.info("Generating TDX attestation quote")
        logger.debug(f"Nonce length: {len(nonce)} bytes")
        
        # Import TDX-specific libraries only when needed (not available on SEV machines)
        try:
            from inteltrustauthorityclient.tdx.tdx_adapter import TDXAdapter
            from inteltrustauthorityclient.tdx.azure.azure_tdx_adapter import AzureTDXAdapter
        except ImportError as e:
            logger.error(f"Intel Trust Authority Client library not available: {e}")
            logger.error("TDX libraries are only available on TDX-enabled machines")
            raise ImportError(
                "Intel Trust Authority Client library is not installed or not available. "
                "This library is only available on TDX-enabled machines. "
                f"Original error: {e}"
            )
        
        try:
            # Create Azure TDX adapter
            # Note: user_data is optional, can be None or base64-encoded string
            logger.debug("Creating AzureTDXAdapter instance")
            adapter = AzureTDXAdapter(user_data=None)
            
            # Collect evidence (quote) from TDX TEE
            # The nonce is passed to include it in the quote
            logger.debug("Collecting evidence from TDX TEE")
            evidence = adapter.collect_evidence(nonce=nonce)
            logger.debug(f"Evidence collected, type: {type(evidence)}")
            logger.debug(f"Evidence object attributes: {[attr for attr in dir(evidence) if not attr.startswith('_')]}")
            
            # Extract quote from evidence object
            # The quote field may be base64-encoded or raw bytes
            if hasattr(evidence, 'quote'):
                logger.debug("Evidence object has 'quote' attribute")
                quote_value = evidence.quote
                logger.debug(f"Quote value type: {type(quote_value)}, length: {len(quote_value) if hasattr(quote_value, '__len__') else 'N/A'}")
                
                # Handle base64-encoded quote
                if isinstance(quote_value, str):
                    logger.debug("Quote is string, attempting base64 decode")
                    try:
                        # Try to decode base64
                        quote_bytes = base64.b64decode(quote_value)
                        logger.info(f"Successfully decoded base64 quote, length: {len(quote_bytes)} bytes")
                        return quote_bytes
                    except Exception as e:
                        logger.warning(f"Base64 decode failed: {e}, trying base64url")
                        # If decoding fails, might be base64url encoded
                        try:
                            # Replace base64url characters
                            quote_b64 = quote_value.replace('-', '+').replace('_', '/')
                            # Add padding if needed
                            padding = len(quote_b64) % 4
                            if padding:
                                quote_b64 += '=' * (4 - padding)
                            quote_bytes = base64.b64decode(quote_b64)
                            logger.info(f"Successfully decoded base64url quote, length: {len(quote_bytes)} bytes")
                            return quote_bytes
                        except Exception as e2:
                            logger.error(f"Failed to decode quote as base64 or base64url: {e2}")
                            logger.exception("Decode exception details:")
                            raise ValueError(f"Failed to decode quote: {str(e2)}")
                elif isinstance(quote_value, bytes):
                    # Already bytes, return directly
                    logger.info(f"Quote is already bytes, length: {len(quote_value)} bytes")
                    return quote_value
                else:
                    # Try to convert to bytes
                    logger.warning(f"Quote is unexpected type {type(quote_value)}, attempting conversion")
                    return bytes(quote_value)
            else:
                logger.warning("Evidence object does not have 'quote' attribute, searching alternatives")
                # If quote field not found, try common alternative field names
                for field_name in ['tdx_quote', 'raw_quote', 'evidence', 'report']:
                    if hasattr(evidence, field_name):
                        logger.debug(f"Found alternative field: {field_name}")
                        field_value = getattr(evidence, field_name)
                        if isinstance(field_value, bytes):
                            logger.info(f"Using {field_name} as bytes, length: {len(field_value)} bytes")
                            return field_value
                        elif isinstance(field_value, str):
                            logger.info(f"Using {field_name} as string, attempting to decode")
                            logger.debug(f"Field value type: {type(field_value)}, length: {len(field_value)}")
                            # Try base64 decode first
                            try:
                                quote_bytes = base64.b64decode(field_value)
                                logger.info(f"Successfully decoded {field_name} as base64, length: {len(quote_bytes)} bytes")
                                return quote_bytes
                            except Exception as e:
                                logger.debug(f"Base64 decode failed for {field_name}: {e}, trying base64url")
                                # If decoding fails, might be base64url encoded
                                try:
                                    # Replace base64url characters
                                    quote_b64 = field_value.replace('-', '+').replace('_', '/')
                                    # Add padding if needed
                                    padding = len(quote_b64) % 4
                                    if padding:
                                        quote_b64 += '=' * (4 - padding)
                                    quote_bytes = base64.b64decode(quote_b64)
                                    logger.info(f"Successfully decoded {field_name} as base64url, length: {len(quote_bytes)} bytes")
                                    return quote_bytes
                                except Exception as e2:
                                    logger.warning(f"Failed to decode {field_name} as base64 or base64url: {e2}")
                                    logger.debug(f"Field value preview (first 100 chars): {field_value[:100]}")
                                    # Continue to next field instead of failing immediately
                                    continue
                
                # If no quote found, raise error
                logger.error("Evidence object does not contain a quote field")
                logger.error(f"Available attributes: {dir(evidence)}")
                raise ValueError("Evidence object does not contain a quote field")
        except ImportError as e:
            logger.error(f"Import error: Intel Trust Authority Client library not available: {e}")
            logger.exception("Import exception details:")
            raise
        except Exception as e:
            logger.error(f"Failed to generate TDX quote: {e}")
            logger.exception("Exception details:")
            raise
