"""
VeriTrace RFC 3161 Time-Stamp Authority (TSA) Client
Provides cryptographically certified external UTC timestamps for ledger records.
"""
import urllib.request
import ssl
import base64
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List

from pyasn1.type import univ
from pyasn1.codec.der import encoder, decoder
from pyasn1_modules import rfc3161, rfc2459, rfc5652

from cryptography import x509

SHA256_OID = univ.ObjectIdentifier('2.16.840.1.101.3.4.2.1')
IST_TZ = timezone(timedelta(hours=5, minutes=30))

DEFAULT_TSA_SERVERS = [
    "https://freetsa.org/tsr",
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com"
]


def _format_gentime(gentime_str: str) -> tuple:
    """
    Converts GeneralizedTime (e.g. '20260907110903Z') to:
    - ISO 8601 string in UTC
    - Human-readable formatted string in Indian Standard Time (IST)
    """
    try:
        clean = str(gentime_str).rstrip('Z')
        if '.' in clean:
            clean, frac = clean.split('.')
            dt = datetime.strptime(clean, "%Y%m%d%H%M%S")
        else:
            dt = datetime.strptime(clean, "%Y%m%d%H%M%S")
        dt_utc = dt.replace(tzinfo=timezone.utc)
        dt_ist = dt_utc.astimezone(IST_TZ)
        ist_str = dt_ist.strftime("%d %b %Y, %I:%M:%S %p IST")
        return dt_utc.isoformat(), ist_str
    except Exception:
        s = str(gentime_str)
        return s, s


def _extract_cert_info(signed_data) -> Dict[str, Any]:
    """Extracts X.509 certificate metadata from CMS SignedData structure."""
    cert_info = {}
    try:
        if signed_data['certificates'].isValue and len(signed_data['certificates']) > 0:
            c = signed_data['certificates'][0]
            c_der = encoder.encode(c)
            x = x509.load_der_x509_certificate(c_der)
            
            sub_cn, sub_o = None, None
            for attr in x.subject:
                if attr.oid == x509.NameOID.COMMON_NAME:
                    sub_cn = str(attr.value)
                elif attr.oid == x509.NameOID.ORGANIZATION_NAME:
                    sub_o = str(attr.value)
                    
            iss_cn, iss_o = None, None
            for attr in x.issuer:
                if attr.oid == x509.NameOID.COMMON_NAME:
                    iss_cn = str(attr.value)
                elif attr.oid == x509.NameOID.ORGANIZATION_NAME:
                    iss_o = str(attr.value)
                    
            cert_info = {
                "tsa_common_name": sub_cn or "TSA Signer",
                "tsa_org": sub_o or "Trusted TSA",
                "issuer_common_name": iss_cn,
                "issuer_org": iss_o,
                "cert_serial_hex": hex(x.serial_number)
            }
    except Exception:
        pass
    return cert_info


def request_timestamp_token(data_hash_hex: str, tsa_urls: Optional[List[str]] = None, timeout: float = 3.5) -> Dict[str, Any]:
    """
    Sends SHA-256 hex hash to an RFC 3161 Time-Stamp Authority.
    Returns certified UTC timestamp token metadata.
    """
    urls = tsa_urls or DEFAULT_TSA_SERVERS
    hash_bytes = bytes.fromhex(data_hash_hex)
    
    # Construct RFC 3161 TimeStampReq
    req = rfc3161.TimeStampReq()
    req['version'] = 1
    algo_id = rfc2459.AlgorithmIdentifier()
    algo_id['algorithm'] = SHA256_OID
    
    msg_imprint = rfc3161.MessageImprint()
    msg_imprint['hashAlgorithm'] = algo_id
    msg_imprint['hashedMessage'] = hash_bytes
    req['messageImprint'] = msg_imprint
    req['certReq'] = True
    
    der_req = encoder.encode(req)
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    for url in urls:
        try:
            http_req = urllib.request.Request(
                url,
                data=der_req,
                headers={"Content-Type": "application/timestamp-query"}
            )
            with urllib.request.urlopen(http_req, context=ctx, timeout=timeout) as resp:
                resp_bytes = resp.read()
                
            resp_asn1, _ = decoder.decode(resp_bytes, asn1Spec=rfc3161.TimeStampResp())
            status = int(resp_asn1['status']['status'])
            if status != 0:
                continue
                
            # Parse TSTInfo
            tst_token = resp_asn1['timeStampToken']
            content_info, _ = decoder.decode(encoder.encode(tst_token), asn1Spec=rfc5652.ContentInfo())
            signed_data, _ = decoder.decode(content_info['content'], asn1Spec=rfc5652.SignedData())
            econtent = signed_data['encapContentInfo']['eContent']
            tst_info, _ = decoder.decode(econtent.asOctets(), asn1Spec=rfc3161.TSTInfo())
            
            gen_time_utc, gen_time_ist = _format_gentime(str(tst_info['genTime']))
            tst_b64 = base64.b64encode(resp_bytes).decode('ascii')
            cert_info = _extract_cert_info(signed_data)
            
            return {
                "success": True,
                "tsa_url": url,
                "certified_utc": gen_time_utc,
                "certified_ist": gen_time_ist,
                "token_serial": str(tst_info['serialNumber']),
                "tsa_policy": str(tst_info['policy']),
                "cert_info": cert_info,
                "tst_token_b64": tst_b64,
                "status": "CERTIFIED"
            }
        except Exception:
            continue
            
    return {
        "success": False,
        "tsa_url": None,
        "certified_utc": None,
        "certified_ist": None,
        "tst_token_b64": None,
        "status": "OFFLINE_FALLBACK"
    }


def verify_timestamp_token(tst_token_b64: str, expected_hash_hex: str) -> Dict[str, Any]:
    """
    Decodes and validates a stored RFC 3161 timestamp token against the expected record hash.
    """
    try:
        resp_bytes = base64.b64decode(tst_token_b64)
        resp_asn1, _ = decoder.decode(resp_bytes, asn1Spec=rfc3161.TimeStampResp())
        status = int(resp_asn1['status']['status'])
        if status != 0:
            return {"valid": False, "reason": f"TSA responded with non-zero status: {status}"}
            
        tst_token = resp_asn1['timeStampToken']
        content_info, _ = decoder.decode(encoder.encode(tst_token), asn1Spec=rfc5652.ContentInfo())
        signed_data, _ = decoder.decode(content_info['content'], asn1Spec=rfc5652.SignedData())
        econtent = signed_data['encapContentInfo']['eContent']
        tst_info, _ = decoder.decode(econtent.asOctets(), asn1Spec=rfc3161.TSTInfo())
        
        imprint_hash_hex = bytes(tst_info['messageImprint']['hashedMessage']).hex()
        if imprint_hash_hex.lower() != expected_hash_hex.lower():
            return {
                "valid": False,
                "reason": f"TSA imprint hash mismatch: {imprint_hash_hex} != {expected_hash_hex}"
            }
            
        gen_time_utc, gen_time_ist = _format_gentime(str(tst_info['genTime']))
        cert_info = _extract_cert_info(signed_data)
        
        return {
            "valid": True,
            "certified_utc": gen_time_utc,
            "certified_ist": gen_time_ist,
            "serial_number": str(tst_info['serialNumber']),
            "tsa_policy": str(tst_info['policy']),
            "cert_info": cert_info
        }
    except Exception as e:
        return {
            "valid": False,
            "reason": f"Failed to parse or verify RFC 3161 token: {str(e)}"
        }
