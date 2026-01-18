#!/usr/bin/env python3
"""
Test script to verify TEE HPC tutorial setup
"""

import sys
import os
import requests
from dotenv import load_dotenv

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

load_dotenv()


def test_imports():
    """Test that all required modules can be imported"""
    print("Testing imports...")
    try:
        from src.attestation.azure_attestation import AzureAttestationVerifier, AttestationQuoteGenerator
        from src.attestation.mutual_attestation import MutualAttestationSession
        from src.client.desktop_client import TEEHPCClient
        from src.server.tee_server import app
        from src.hpc_job.job import HPCJob
        print("✓ All imports successful")
        return True
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        return False


def test_environment_variables():
    """Test that required environment variables are set"""
    print("\nTesting environment variables...")
    required_vars = [
        'AZURE_ATTESTATION_ENDPOINT',
        'SEV_VM_URL',
        'TDX_VM_URL'
    ]
    
    missing = []
    for var in required_vars:
        if not os.getenv(var):
            missing.append(var)
    
    if missing:
        print(f"✗ Missing environment variables: {', '.join(missing)}")
        print("  Create a .env file with these variables")
        return False
    else:
        print("✓ All required environment variables are set")
        return True


def test_server_connectivity():
    """Test connectivity to TEE servers"""
    print("\nTesting server connectivity...")
    
    sev_url = os.getenv('SEV_VM_URL', 'http://localhost:8080')
    tdx_url = os.getenv('TDX_VM_URL', 'http://localhost:8081')
    
    results = {}
    
    # Test SEV server
    try:
        response = requests.get(f"{sev_url}/health", timeout=5)
        if response.status_code == 200:
            print(f"✓ SEV server reachable at {sev_url}")
            results['sev'] = True
        else:
            print(f"✗ SEV server returned status {response.status_code}")
            results['sev'] = False
    except requests.exceptions.RequestException as e:
        print(f"✗ Cannot connect to SEV server at {sev_url}: {e}")
        results['sev'] = False
    
    # Test TDX server
    try:
        response = requests.get(f"{tdx_url}/health", timeout=5)
        if response.status_code == 200:
            print(f"✓ TDX server reachable at {tdx_url}")
            results['tdx'] = True
        else:
            print(f"✗ TDX server returned status {response.status_code}")
            results['tdx'] = False
    except requests.exceptions.RequestException as e:
        print(f"✗ Cannot connect to TDX server at {tdx_url}: {e}")
        results['tdx'] = False
    
    return all(results.values())


def test_azure_endpoint():
    """Test Azure Attestation Service endpoint format"""
    print("\nTesting Azure Attestation Service endpoint...")
    
    endpoint = os.getenv('AZURE_ATTESTATION_ENDPOINT')
    
    if not endpoint:
        print("✗ AZURE_ATTESTATION_ENDPOINT not set")
        return False
    
    # Validate endpoint format
    if not endpoint.startswith('https://') or not endpoint.endswith('.attest.azure.net'):
        print(f"⚠ Warning: Azure endpoint format may be incorrect: {endpoint}")
        print("  Expected format: https://<name>.attest.azure.net")
        return False
    
    print("✓ Azure endpoint format looks correct")
    print("  Note: No authentication required - endpoints are public")
    return True


def test_quote_generation():
    """Test attestation quote generation"""
    print("\nTesting attestation quote generation...")
    
    try:
        from src.attestation.azure_attestation import AttestationQuoteGenerator
        import secrets
        
        nonce = secrets.token_bytes(32)
        
        sev_quote = AttestationQuoteGenerator.generate_sev_quote(nonce)
        tdx_quote = AttestationQuoteGenerator.generate_tdx_quote(nonce)
        
        if sev_quote and tdx_quote:
            print("✓ Quote generation works")
            print(f"  SEV quote length: {len(sev_quote)} bytes")
            print(f"  TDX quote length: {len(tdx_quote)} bytes")
            return True
        else:
            print("✗ Quote generation failed")
            return False
    except Exception as e:
        print(f"✗ Quote generation error: {e}")
        return False


def main():
    """Run all tests"""
    print("="*70)
    print("TEE HPC Tutorial - Setup Verification")
    print("="*70)
    
    tests = [
        ("Module Imports", test_imports),
        ("Environment Variables", test_environment_variables),
        ("Server Connectivity", test_server_connectivity),
        ("Azure Endpoint", test_azure_endpoint),
        ("Quote Generation", test_quote_generation),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n✗ Test '{name}' crashed: {e}")
            results.append((name, False))
    
    print("\n" + "="*70)
    print("Test Summary")
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✓ All tests passed! Setup is complete.")
        return 0
    else:
        print("\n⚠ Some tests failed. Please review the errors above.")
        print("  See SETUP.md for detailed setup instructions.")
        return 1


if __name__ == '__main__':
    sys.exit(main())
