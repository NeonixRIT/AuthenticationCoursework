import asn1tools # For ASN1 encoding/decoding
import datetime
import impacket.krb5.crypto as crypto # For encryption/decryptio
import scapy.all as scapy # For packet parsing

from pprint import pprint

MESSAGE_TYPES = {
    0x61: 'Ticket',
    0x62: 'Authenticator',
    0x63: 'EncTicketPart',
    0x6A: 'AS-REQ',
    0x6B: 'AS-REP',
    0x6C: 'TGS-REQ',
    0x6D: 'TGS-REP',
    0x6E: 'AP-REQ',
    0x6F: 'AP-REP',
    0x74: 'KRB-SAFE',
    0x75: 'KRB-PRIV',
    0x76: 'KRB-CRED',
    0x79: 'EncASRepPart',
    0x7A: 'EncTGSRepPart',
    0x7B: 'EncPRepPart',
    0x7C: 'EncKrbPrivPart',
    0x7D: 'EncKrbCredPart',
    0x7E: 'KRB-ERROR',
}

ASN1_KRB5 = asn1tools.compile_files('krb5.asn', 'der')

AS_REQ_TEMPLATE = {
    'msg-type': 10,
    'padata':
    [
        {
            'padata-type': 2, # pA-ENC-TIMESTAMP
            'padata-value':
            {
                'cipher': # Encrypted with the client's key T=1
                {
                    'patimestamp': datetime.datetime.now(),
                },
                'etype': 23
            }
        },
        {
            'padata-type': 128, # PA-DATA pA-PAC-REQUEST
            'padata-value': b'0\x05\xa0\x03\x01\x01\xff'
        }
    ],
    'pvno': 5,
    'req-body': {
        'addresses': [{'addr-type': 20, 'address': b'DESKTOP-VI4396B '}],
        'cname': {'name-string': ['charlie'], 'name-type': 1},
        'etype': [23],
        'kdc-options': (b'@\x81\x00\x10', 32),
        'nonce': 0,
        'realm': 'CSEC',
        'rtime': datetime.datetime(2037, 9, 13, 2, 48, 5),
        'sname': {'name-string': ['krbtgt', 'CSEC'], 'name-type': 2},
        'till': datetime.datetime(2037, 9, 13, 2, 48, 5)
    }
}

TGS_REQ_TEMPLATE = {
    'msg-type': 12,
    'padata':
    [
        {
            'padata-type': 1, # PA-DATA pA-TGS-REQ
            'padata-value':
            {
                'ap-options': (b'\x00\x00\x00\x00', 32),
                'authenticator':
                {
                    'cipher': # Field's value encrypted with session key from AS-REP
                    {
                        'authenticator-vno': 5,
                        'cname': {'name-string': ['charlie'], 'name-type': 1},
                        'crealm': 'CSEC.472.LAB1',
                        'ctime': datetime.datetime.now(),
                        'cusec': 0,
                        'seq-number': 0
                    },
                    'etype': 23
                },
                'msg-type': 14,
                'pvno': 5,
                'ticket': # TGT Copied from AS-REP
                {
                    'enc-part':
                    {
                        'cipher': b'',
                        'etype': 23,
                        'kvno': 2
                    },
                    'realm': 'CSEC.472.LAB1',
                    'sname':
                    {
                        'name-string': ['krbtgt', 'CSEC.472.LAB1'],
                        'name-type': 2
                    },
                    'tkt-vno': 5
                }
            }
        },
        {
            'padata-type': 167, # PA-DATA pA-PAC-OPTIONS
            'padata-value': b'0\t\xa0\x07\x03\x05\x00@\x00\x00\x00'
        }
    ],
    'pvno': 5,
    'req-body':
    {
        'etype': [23],
        'kdc-options': (b'@\x81\x00\x00', 32),
        'nonce': 0,
        'realm': 'CSEC.472.LAB1',
        'sname': {'name-string': ['cifs', 'FILESERVER'], 'name-type': 2},
        'till': datetime.datetime(2037, 9, 13, 2, 48, 5)
    }
}

AP_REQ_TEMPLATE = {
    'ap-options': (b' \x00\x00\x00', 32),
    'authenticator':
    {
        'cipher': # Field's value encrypted with session key from TGS-REP T=11
        {
            'authenticator-vno': 5,
            # 'authorization-data':
            # [
            #     {
            #         'ad-data': b'0g0\x0f\xa0\x04\x02\x02\x00\x81\xa1\x07'
            #                    b'\x04\x050\x03\x02\x01\x170'
            #                    b'\x0e\xa0\x04\x02\x02\x00\x8f\xa1'
            #                    b'\x06\x04\x04\x00@\x00\x000D\xa0\x04\x02'
            #                    b'\x02\x00\x90\xa1<\x04:c\x00i\x00f'
            #                    b'\x00s\x00/\x00F\x00I\x00L\x00E\x00S\x00E'
            #                    b'\x00R\x00V\x00E\x00R\x00@\x00C\x00S\x00E'
            #                    b'\x00C\x00.\x004\x007\x002\x00.\x00L\x00A'
            #                    b'\x00B\x001\x00',
            #         'ad-type': 1
            #     }
            # ],
            'cksum':
            {
                'checksum': b'\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                            b'\x00\x00\x00\x00\x00\x00\x00\x00"\x00\x00\x00',
                'cksumtype': 32771
            },
            'cname': {'name-string': ['charlie'], 'name-type': 1},
            'crealm': 'CSEC.472.LAB1',
            'ctime': datetime.datetime.now(),
            'cusec': 0,
            'seq-number': 0,
            'subkey':
            {
                'keytype': 23,
                'keyvalue': b''
            }
        },
        'etype': 23
    },
    'msg-type': 14,
    'pvno': 5,
    'ticket': # Auth Ticket Copied from TGS-REP
    {
        'enc-part':
        {
            'cipher': b'',
            'etype': 23,
            'kvno': 1
        },
        'realm': 'CSEC.472.LAB1',
        'sname': {'name-string': ['cifs', 'FILESERVER'], 'name-type': 2},
        'tkt-vno': 5
    }
}


class RC4_HMAC_MD5:
    def __init__(self):
        self.__handle = crypto._RC4()

    def encrypt(self, T: int, data: bytes, key: str, nonce: bytes | None = None) -> tuple[bytes, bytes]:
        if isinstance(key, str):
            key = crypto._RC4().string_to_key(key, '', None)
        elif isinstance(key, bytes):
            tmp = crypto._RC4().string_to_key('', '', None)
            tmp.contents = key
            key = tmp
        return self.__handle.encrypt(key, T, data, nonce)

    def decrypt(self, data: bytes, key: str | bytes) -> bytes:
        if isinstance(key, str):
            key = crypto._RC4().string_to_key(key, '', None)
        elif isinstance(key, bytes):
            tmp = crypto._RC4().string_to_key('', '', None)
            tmp.contents = key
            key = tmp

        T = 1
        while T < 16:
            try:
                return self.__handle.decrypt(key, T, data)
            except crypto.InvalidChecksum:
                T += 1
        raise crypto.InvalidChecksum('Failed to decrypt data')


def is_PAC_required(username, krb_host_addr):
    # Send init packet
    # Checks if PAC is required
    as_init = dict(AS_REQ_TEMPLATE)
    as_init['req-body']['cname']['name-string'] = [username]
    del as_init['padata']

    packet_data = ASN1_KRB5.encode('AS-REQ', as_init)
    packet_data = len(packet_data).to_bytes(4, 'big') + packet_data

    socket = scapy.socket.socket(scapy.socket.AF_INET, scapy.socket.SOCK_STREAM)
    socket.connect(krb_host_addr)
    print('Sending init packet...')
    socket.send(packet_data)
    as_rep_err = socket.recv(8192)
    if len(as_rep_err) > 4:
        if as_rep_err[4] == 0x7E:
            return True
        return False
    else:
        return True

def get_TGT(username, password, nonce, cipher, krb_host_addr):
    as_req = dict(AS_REQ_TEMPLATE)
    now =  datetime.datetime.now()
    now = (now - datetime.timedelta(microseconds=now.microsecond))
    now = (now + datetime.timedelta(hours=5))
    as_req['padata'][0]['padata-value']['cipher']['patimestamp'] = now
    as_req['padata'][0]['padata-value']['cipher'] = ASN1_KRB5.encode('PA-ENC-TS-ENC', as_req['padata'][0]['padata-value']['cipher'])
    as_req['padata'][0]['padata-value']['cipher'] = cipher.encrypt(1, as_req['padata'][0]['padata-value']['cipher'], password)
    as_req['padata'][0]['padata-value'] = ASN1_KRB5.encode('PA-ENC-TIMESTAMP', as_req['padata'][0]['padata-value'])

    as_req['req-body']['cname']['name-string'] = [username]
    as_req['req-body']['nonce'] = nonce
    packet_data = ASN1_KRB5.encode('AS-REQ', AS_REQ_TEMPLATE)
    packet_data = len(packet_data).to_bytes(4, 'big') + packet_data

    socket = scapy.socket.socket(scapy.socket.AF_INET, scapy.socket.SOCK_STREAM)
    socket.connect(krb_host_addr)
    socket.send(packet_data)
    as_rep = socket.recv(8192)
    as_rep = ASN1_KRB5.decode(MESSAGE_TYPES[as_rep[4]], as_rep[4:])
    ticket_granting_ticket = as_rep['ticket']
    enc_client_tgs_key = as_rep['enc-part']['cipher']
    client_tgs_key = ASN1_KRB5.decode('EncASRepPart', cipher.decrypt(enc_client_tgs_key, password))['key']['keyvalue']
    return ticket_granting_ticket, client_tgs_key


def get_ST(username, nonce, cipher, krb_host_addr, ticket_granting_ticket, client_tgs_key):
    tgs_req = dict(TGS_REQ_TEMPLATE)
    tgs_req['padata'][0]['padata-value']['ticket'] = ticket_granting_ticket
    now =  datetime.datetime.now()
    now_microsec = now.microsecond
    now = (now - datetime.timedelta(microseconds=now.microsecond))
    now = (now + datetime.timedelta(hours=5))
    tgs_req['padata'][0]['padata-value']['authenticator']['cipher']['ctime'] = now
    tgs_req['padata'][0]['padata-value']['authenticator']['cipher']['cusec'] = now_microsec
    tgs_req['padata'][0]['padata-value']['authenticator']['cipher']['seq-number'] = nonce + 1
    tgs_req['padata'][0]['padata-value']['authenticator']['cipher']['cname']['name-string'] = [username]

    tgs_req['padata'][0]['padata-value']['authenticator']['cipher'] = cipher.encrypt(7, ASN1_KRB5.encode('Authenticator', tgs_req['padata'][0]['padata-value']['authenticator']['cipher']), client_tgs_key)
    tgs_req['padata'][0]['padata-value'] = ASN1_KRB5.encode('AP-REQ', tgs_req['padata'][0]['padata-value'])

    tgs_req['req-body']['nonce'] = nonce + 1

    packet_data = ASN1_KRB5.encode('TGS-REQ', tgs_req)
    packet_data = len(packet_data).to_bytes(4, 'big') + packet_data
    socket = scapy.socket.socket(scapy.socket.AF_INET, scapy.socket.SOCK_STREAM)
    socket.connect(krb_host_addr)
    socket.send(packet_data)
    tgs_rep = socket.recv(8192)
    tgs_rep = ASN1_KRB5.decode(MESSAGE_TYPES[tgs_rep[4]], tgs_rep[4:])
    service_ticket = tgs_rep['ticket']
    enc_client_service_key = tgs_rep['enc-part']['cipher']
    client_service_key = ASN1_KRB5.decode('EncTGSRepPart', cipher.decrypt(enc_client_service_key, client_tgs_key))['key']['keyvalue']
    return service_ticket, client_service_key


def build_AP_REQ(username, nonce, cipher, service_ticket, client_service_key):
    ap_req = dict(AP_REQ_TEMPLATE)
    ap_req['ticket'] = service_ticket
    now =  datetime.datetime.now()
    now_microsec = now.microsecond
    now = (now - datetime.timedelta(microseconds=now.microsecond))
    now = (now + datetime.timedelta(hours=5))
    ap_req['authenticator']['cipher']['ctime'] = now
    ap_req['authenticator']['cipher']['cusec'] = now_microsec
    ap_req['authenticator']['cipher']['seq-number'] = nonce + 2
    ap_req['authenticator']['cipher']['cname']['name-string'] = [username]
    client_service_subkey = crypto.get_random_bytes(16)
    ap_req['authenticator']['cipher']['subkey']['keyvalue'] = client_service_subkey
    ap_req_raw = dict(ap_req)

    ap_req['authenticator']['cipher'] = cipher.encrypt(7, ASN1_KRB5.encode('Authenticator', ap_req['authenticator']['cipher']), client_service_key)
    packet_data = ASN1_KRB5.encode('AP-REQ', ap_req)
    return ap_req_raw, packet_data, client_service_subkey


def generate_auth_payload(username, password, nonce, cipher, krb_host_addr):
    do_pac = is_PAC_required(username, krb_host_addr)
    print(f'PAC Required: {do_pac}')
    if not do_pac:
        raise NotImplementedError("Auth w/o PAC not supported.")

    print('Sending AS-REQ...')
    tgt, ctgs_key = get_TGT(username, password, nonce, cipher, krb_host_addr)
    print('Recieved AS-REP')
    print(f'\tClient/TGS Session Key: {ctgs_key.hex()}')
    print(f'\tTicket Granting Ticket: {tgt['enc-part']['cipher'].hex()[:20]}...')

    print('Sending TGS-REQ...')
    st, cs_key = get_ST(username, nonce, cipher, krb_host_addr, tgt, ctgs_key)
    print('Recieved TGS-REP')
    print(f'\tClient/Service Session Key: {cs_key.hex()}')
    print(f'\tService Ticket: {st['enc-part']['cipher'].hex()[:20]}...')

    print('Generating AP-REQ...')
    ap_req_data, ap_req_payload, cs_subkey = build_AP_REQ(username, nonce, cipher, st, cs_key)
    print('Generated AP-REQ')
    print(f'\tClient/Service Session Subkey: {cs_subkey.hex()}')
    print(f'\tAP-REQ Payload: {ap_req_payload.hex()[:20]}...')
    print()
    print('AP-REQ Data:')
    pprint(ap_req_data)
    return ap_req_data, ap_req_payload, cs_key, cs_subkey


def main():
    username = 'charlie'
    password = 'NewStudent123'
    nonce = 0x0a + int(crypto.get_random_bytes(3).hex(), 16)
    rc4 = RC4_HMAC_MD5()
    krb_host_addr = ('192.168.1.103', 88)
    ap_req_data, ap_req_payload, cs_key, cs_subkey = generate_auth_payload(username, password, nonce, rc4, krb_host_addr)


if __name__ == '__main__':
    main()
