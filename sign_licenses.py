#!/usr/bin/env python3
"""Sign GitHub `private` HWID list using RSA private key stored in Actions Secret.
Output format is compatible with DKM_LICENSE_LIST_V1.
"""
import base64, datetime as dt, hashlib, json, os, re
from pathlib import Path
from xml.etree import ElementTree as ET
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

ROOT = Path(__file__).resolve().parent
FMT = 'DKM_LICENSE_LIST_V1'

def hash_hwid(hwid):
    return hashlib.sha256(('DKM_HWID|' + hwid).encode('utf-8')).hexdigest()

def load_key():
    raw = os.environ['DKM_RSA_PRIVATE_KEY']
    xml = base64.b64decode(raw, validate=True).decode('utf-8')
    root = ET.fromstring(xml)
    def n(name):
        return int.from_bytes(base64.b64decode(root.findtext(name)), 'big')
    numbers = rsa.RSAPrivateNumbers(p=n('P'), q=n('Q'), d=n('D'), dmp1=n('DP'), dmq1=n('DQ'), iqmp=n('InverseQ'), public_numbers=rsa.RSAPublicNumbers(e=n('Exponent'), n=n('Modulus')))
    return numbers.private_key()

def main():
    records, seen = [], set()
    for lineno, raw in enumerate((ROOT / 'private').read_text(encoding='utf-8-sig').splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('|')
        if len(parts) != 3:
            raise ValueError(f'Line {lineno}: expected HWID|dd-MM-yyyy|Note')
        hwid, date, note = (s.strip() for s in parts)
        hwid = hwid.replace(' ', '').upper()
        if not re.fullmatch(r'[A-Z0-9-]{8,100}', hwid):
            raise ValueError(f'Line {lineno}: invalid HWID')
        if hwid in seen:
            raise ValueError(f'Line {lineno}: duplicate HWID')
        seen.add(hwid)
        expires = dt.datetime.strptime(date, '%d-%m-%Y').replace(tzinfo=dt.timezone.utc) + dt.timedelta(days=1)
        digest = hash_hwid(hwid)
        records.append({'id':'HWID-'+digest[:12], 'keyHash':'', 'hwidHash':digest, 'expiryUtc':expires.strftime('%Y-%m-%dT%H:%M:%S.0000000Z'), 'status':'active'})
    issued = dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f') + '0Z'
    payload = {'format':FMT, 'issuedUtc':issued, 'licenses':records}
    payload_bytes = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    key = load_key()
    sig = key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    key.public_key().verify(sig, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    envelope = {'format':FMT, 'payload':base64.b64encode(payload_bytes).decode(), 'signature':base64.b64encode(sig).decode()}
    (ROOT / 'licenses.json').write_text(json.dumps(envelope, indent=2)+'\n', encoding='utf-8')
    print(f'SIGNED OK: {len(records)} HWIDs')

if __name__ == '__main__':
    main()
