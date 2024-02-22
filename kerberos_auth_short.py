import asn1tools # For ASN1 encoding/decoding
import datetime
import impacket.krb5.crypto as crypto # For encryption/decryptio
import scapy.all as scapy # For packet parsing

from pprint import pprint

username = 'charlie'
password = 'NewStudent123'

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
FULL_TICKET_EXCH = {'KRB_AS_REQ', 'KRB_AS_REP', 'KRB_TGS_REQ', 'KRB_TGS_REP'}

AS_REP_T = 8
TGS_REP_T = 8

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
                    'patimestamp': datetime.datetime(2024, 2, 20, 21, 16, 14),
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
        'nonce': 171697655,
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
                        'cksum':
                        {
                            'checksum': b'\xed\xa9+\xfc\xfa\xa2\x19S\x1d\xb8\xc0\xab'
                                        b'\xa8c\xf4\xd7',
                            'cksumtype': 7
                        },
                        'cname': {'name-string': ['charlie'], 'name-type': 1},
                        'crealm': 'CSEC.472.LAB1',
                        'ctime': datetime.datetime(2024, 2, 20, 21, 16, 14),
                        'cusec': 1512,
                        'seq-number': 171697600
                    },
                    'etype': 23
                },
                'msg-type': 14,
                'pvno': 5,
                'ticket': # TGT Copied from AS-REP
                {
                    'enc-part':
                    {
                        'cipher': b'iG\x8dn\xe0\xf8\x1c^m#\xd6*\x16\xf4@\x86'
                                  b'\\\x1aWjC,\xe5$\xa4\xb8(d]k\x8cO'
                                  b')\xbe\xf4\xa9\xa9*\xcd=,\x08kG'
                                  b'\x9f\x88:\x15\xfe\xb3\x962\x06\x0cF\x8e'
                                  b'^\xe6\xbe\xbb\x9a~)K\xae\xb4\xd7!'
                                  b'\xf5E5\xff\xca\xaf\xe7\xf6\xd7$v\x90'
                                  b'\x87T\x1bo\x8e\x96\xde\x80\xe7\x10\xa4l'
                                  b'Q)\x92\x95\xf4\xb6\xf1\xab\xe8$H\xac'
                                  b'\x875\xaaN\xc8T\xe9])\xa3eU&\n\x14\x9c'
                                  b'\xfe\x05\xcf\xd7\xe7J\x8a\xe2\x11\xbce\xb1'
                                  b'\xe4\xb1\xb0\xab^\xd7\xa3\xe4L\xe1hW'
                                  b'\xa7\x8cV"A\xf1::b\xf7\xed\x93'
                                  b'\x98\x7fS\x9dX1q\x8a\xf65K\x18G\x02\xb5j'
                                  b'\xb9l\xbfq\xf8\xcd\xcb19y\xc1\xce'
                                  b'\xab.\x96/\x9ej\xd9\x83d\xbc\x08\xed'
                                  b'\x0e\x1c%\xc0\xe4}\x1c(\xd8V\xdc]'
                                  b'^\x81@\x92b\x0f\x07\xd0:\x16\x00^'
                                  b'\xfc\x80\xdd\x95\xcf\x19\xf7`\\nvk|P\xbdv'
                                  b'\xf0\x8fx\xe9]\xe8\x9a33\x03\xae<'
                                  b'\x1eY5\xf1E#\x06z\xef\x92\x18\xb8'
                                  b'\x0e\xc0Q2/\xac\xd5\x99j7\xc0\x12'
                                  b'\xf3!\x0e\x85\x14K#\x8c\x83%`\x1d'
                                  b'\x8a7\xfd\xe7\x8b\x12\xed\x04\x04\xab\xcbF'
                                  b',\xe0\xc2_\xe6:\x17\xdb\xc9\xd0T\x86'
                                  b'&C\xceKd#-G\x98\xe4\\\x0f\xe4<\xc0\xd3'
                                  b'\x14\xf31\xe0\x7f\r\xef\xfc*"\xf6\xb4'
                                  b'\xb7r\xd8\x92\xde\xed4\xfe+\x89t>'
                                  b'R\xcf~\xe6D,\xdeB^w7\x13F,\xb1\xd4'
                                  b' \x9c\xc6\xe8\xde\x84\x96\x17HA\x82c'
                                  b'\x93Yd\x89\x10\xb1\xc58\xa9$\xa5\x97'
                                  b'\xac\xd8f\xee\xe7g\xf1\x1d\x96\xfcC\xc1'
                                  b'\xa7-\x82\x8d\xfd\x04\xeaN\xd8(i@'
                                  b'\xe1\xb5;\xa0/d\xcf\xf6\xa0\x87C+\rL/\xad'
                                  b'\xbf|\n\x8e\x96#\x05\x95\x0f$K\x01'
                                  b'\x91\xaa\xde\xa3\x0f\xb4\xa0\x1f0-\x99\xfe'
                                  b'\xa1\xf7\xee\xe8&\x90\xe7\xeb\xe3\x11U\x17'
                                  b'G\xe3\xb3\x02FI\xce\x8c\xcb\xf6\x84\xc7'
                                  b'\x0e\xf8\xbe\xc9\xf8\xc9\xc2\xb9O}\x19\xa0'
                                  b'y .\x99\x99\xe1\xd9o\xbe\x1c4\xef'
                                  b'\x1ew\x8c?\x9c\xfe\xd0\xa2u\xfa7\xaf'
                                  b'\x8f\t-\xf1XuC-\xb5\x1ew\x82l\xd1,\x81'
                                  b'8\x91.Od\x1a\x9e\xd2\xd4\xe6\x8b\xd1'
                                  b"\xba\xba\x08\xf7\xb8\x81\x94\xdf'C\x19_"
                                  b'\x7f\xe07\x9c\xd9\x97\xb3\xefG\x8a\xf0\xdb'
                                  b'Y\xc3\xf2;\xfa\xa7m\xd6\xefSZ\xc0'
                                  b'\x85*\xacy\x99\x9d\xebcX\xe1\xdd^'
                                  b'\xec\xfc\x11\x06\xc6\xb4\x04 \x01\xac\xb30'
                                  b"ai'\xd7\xeb\xbc2c\x920\xd7\xcbd\r\xe9\xbf"
                                  b'\xe7\xd1!bd#\xfc\xb3\x03,\x96\xb4'
                                  b'\xae\xf6s\xe4!\xd8~To\x80\xb8d\x93:R*'
                                  b'5\x08\x00_!\x9d\x00\x08\xfc+\x10|'
                                  b'\xa5\xb4\x00\x9d\x13\xc9H\x18j/\x0c\x7f'
                                  b'\\%\x00\xc8{>n\x8c\x99"\x84\x8e'
                                  b'\xe7\x87\xc30\xd9inV\xa0\xfaZ-jC\xc6\xd9'
                                  b'Juk9fB\xc7_\xe2\x0cC.2\xc3\x91\x97'
                                  b'\x92Y\x82\xa2\xff\xa8\x06\x15\xef]\xe0\x08'
                                  b'\xbbl\t\xc3_\x98x}Fn\xac^\xdf\xe1=\x9c'
                                  b'\xc9\x0e\xde\xc5$,H\x8c\xdb\x9e\x82\xc7'
                                  b'\xdar\xbb\xd0G\xe3\xd58\xbd%n\x0b'
                                  b'\x0cXx\xf7J\xfa\xd6 \xa4\x11)c[-\x00;'
                                  b'\x87r\xd7\xfb\xce\xadl\xd4nG\xd6\r'
                                  b'h\x13H\x9c\xba\x01\xb3\x03\x02\x84\xfeb'
                                  b'\x89\xa6\x91\xee\xf1\xd6\xfa\xa9'
                                  b'\x918\n\x9e\x1e\x92\x7f\x12~\xb8\xbf#'
                                  b'\xa6\xa6_\xaf_p/\x13>\xde\x9a\xa6!b\x9aN'
                                  b'QxI\x9d\xb8\xc4^%\xa5\xb1M\xaf1\rv\x07'
                                  b'&\x081`\x16\x1cYM\xe1Q\x8c\xaa'
                                  b'\xd3\xaf\xf1GF\x0f;F\xce\xc8x\xaeT#9\x03'
                                  b'6Zr\xca\x0c\xd0\xba\x1c\xb2\x82`\xeb'
                                  b'\x1c\xc4\x0f\xc0Kr\xfcsa\xcf\x91-'
                                  b'\xcd\xf4\xe09\xa2\x14C\xc1\xc9\xd1\xd1\x8c'
                                  b'l\xe9\x02\x19]\xc6C8R\x9a,a\xd8',
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
        'enc-authorization-data':
        {
            # Encrypted with session key from AS-REP T=4
            'cipher':
            [
                {
                    'ad-data': b'0A0?\xa0\x04\x02\x02\x00\x8d\xa17\x0450301\xa0\x03'
                               b'\x02\x01\x00\xa1*\x04(\x01\x00\x00\x00\x00 \x00\x00\xfa'
                               b'\xee\x89a\xb4\xb8\xfc\xd3\xb9N\xf1\xfc\xa2\x8e3[!`\xe8X\xd4'
                               b'\xfd\xd7{\xbf\x05 \xda\xbb\x1c\xef<',
                    'ad-type': 1
                }
            ],
            'etype': 23
        },
        'etype': [23, 24, -135],
        'kdc-options': (b'@\x81\x00\x00', 32),
        'nonce': 171697600,
        'realm': 'CSEC.472.LAB1',
        'sname': {'name-string': ['cifs', 'FILESERVER'], 'name-type': 2},
        'till': datetime.datetime(2037, 9, 13, 2, 48, 5)
    }
}

AP_REQ_TEMPLATE = {
    'ap-options': (b' \x00\x00\x00', 32),
    'authenticator':
    {
        'cipher': # Field's value encrypted with session key from TGS-REP
        {
            'authenticator-vno': 5,
            'authorization-data':
            [
                {
                    'ad-data': b'0g0\x0f\xa0\x04\x02\x02\x00\x81\xa1\x07'
                               b'\x04\x050\x03\x02\x01\x170'
                               b'\x0e\xa0\x04\x02\x02\x00\x8f\xa1'
                               b'\x06\x04\x04\x00@\x00\x000D\xa0\x04\x02'
                               b'\x02\x00\x90\xa1<\x04:c\x00i\x00f'
                               b'\x00s\x00/\x00F\x00I\x00L\x00E\x00S\x00E'
                               b'\x00R\x00V\x00E\x00R\x00@\x00C\x00S\x00E'
                               b'\x00C\x00.\x004\x007\x002\x00.\x00L\x00A'
                               b'\x00B\x001\x00',
                    'ad-type': 1
                }
            ],
            'cksum':
            {
                'checksum': b'\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                            b'\x00\x00\x00\x00\x00\x00\x00\x00"\x00\x00\x00',
                'cksumtype': 32771
            },
            'cname': {'name-string': ['charlie'], 'name-type': 1},
            'crealm': 'CSEC.472.LAB1',
            'ctime': datetime.datetime(2024, 2, 20, 21, 16, 14),
            'cusec': 1513,
            'seq-number': 171526098,
            'subkey':
            {
                'keytype': 23,
                'keyvalue': b'\xce\x03\xfcE\x80C\x1b<\xce\xe7\xcf\xedF\x96.&'
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
            'cipher': b'\x9a\x8fI<\x04\x89Gfpq\xbe\x14o\x9ek\xb3'
                      b']\x82\x0e\x9c\xb2)P\xe3\xbbLPI'
                      b'\xa9Z\x8a\xd2,$!T\xd8\x11}\x1c'
                      b'\xc2\xe4\xe1\xa0-7\x13\xca,#\xf2#kw3\xcf'
                      b'\xafJ\xe6:8I\x8b\x935\xbdc\xe0}\xd4C0'
                      b'\x9c\xd1v\xab\x0c;MS\xb1b4\xa8\x8bNR\xa9'
                      b'8\xb3\xdf;x\n7bi\x85\rl\xa7\xe2=\xdf'
                      b'\xd4\x12$\xbb\xf5\xcf\xb7t\xe0\xfc\x02\xb4'
                      b'[\t\x0c2\xa06\x93S\x87\x0c%\xda\x18"Jt'
                      b'\xcbv\x9ew\x9f\x8e\xed5\x0fw<\x18'
                      b'\xa8A\xfai\x0ej\x84\x0bj\xd1Bx'
                      b'\x0b\xc3\\\x9f^\xef\xa9\xa8\xca\xed>T'
                      b'\x81}\x80\x97\x83D\xea\xc7\x10o\x7f\x1b'
                      b'\xdb\xebi\xd7\xbf\xe9C\x7f\xba\xd7\x9e\x88'
                      b'\xa4<\xf0\x19\x94\x00\xe5\x90\xf8\x15|\x12'
                      b"\xc0\x05}\x9b\xf0'bu\x82\x7f\xf7\x8b"
                      b'6\xf8\x17\xf8\xec8\xfb*\xb1\x05\xd4#'
                      b'\x98\x1d\x05/\x92\x93n\x92\xe6q\x8f\xae'
                      b'\xe9b\xa4nPn\xcd\x1f/\x80\xc4\xc2'
                      b'\xbfA\x99\xd7\x8a@l\x9c/g+m\x937>\x9b'
                      b'\xa1\x1e\\\x86\xbc\xb3\xe7\xb6yz:A'
                      b'\xbb\xd9\x8e(B\xd4[U\x98\xa2\xde\x92'
                      b'u\x8b%y\xd7\xc2\x82\x9e\x93kC\x03'
                      b'\xecNF\xa0\xd3\x06\xfaG1\x0b\xa5\xc4'
                      b'03\xa2e\x93/\x80\x8b\xf2\x7fM\x8f'
                      b'J\xb4\x1c_y:\x1c\xb7b=P(\xc4\x95\xa6_'
                      b'\xc6\xfb\x92\xd6\x0e\x91>\x03'
                      b'\x15\xc3\xd1\xbb\xb7\xb6\x1e\xcf'
                      b'\xeeQ\x9b\xac\xff\xd6\x90\xea#N\x94>'
                      b'\x95E\x90\xa5\xfb\xd9"Dc"\x9b%'
                      b'\x1c\x9cN\x0fQJ\x14%\x92\xf5\xbe\xfa'
                      b'\xb0\x1aP\x83\x92y\xc0\xae\xb41%j'
                      b'f\x13\xb7HQo\xb6F\xf3\xa4\x9c\x0c'
                      b'\xbd\x0bzU\xa2\x85J\xd4\x8a<1\xac'
                      b'\xea\x95?\xa0\x9f\xb1\xa1Z,A3\xd1'
                      b'-\xef\xe5\xb2\xddv\x1bp\x04\xf9\x012'
                      b'\x00\xc4\xd6\xd2\x8eg\xfai\xdb\xc3\xab\x87'
                      b'\xad#\xaaA\xad\xce<\x8c\xac\xd2\xf7"'
                      b'a/\xcbl\x94\x94m\x90\x9e\xf3\x86\x06'
                      b'f\xd9\x14!\xad\xdc\xee\x84\xbc\xcb\xdf+'
                      b'\xfe\xd4/!\x08Dnm\xe9\x1f\xb2\x01|\xc9w@'
                      b'\x04\xc4\xd7\x89 \xb8B\xfa\xd2\xf1\r\x88'
                      b'\xbd\xc1\x90;/\x0e\xb1P\xbb\x9b\x9a\x08'
                      b'\xb2o\x96%\x9a\x1d.7\xe0\xde\xbbd'
                      b'\x0c\xae\xe6`\xc5\xae\xd9\x83\xcf2Z\xa6'
                      b'\xcc\xdbd\xa7\xfa\x1e\xbe\xed\x05\xbfS\xca'
                      b'\xc0z\x9fj0\xb9\xfb\xfa\x10[\xc3\xa5'
                      b'\xcb\xac\xf40\x8c\xb5LX\xeen\x85='
                      b'\x10\xa5\x8f\xcb\xecu\x083y\xec9h'
                      b'\x93\x9e\xf3\x82m\xd6\x98\xa8\x99[\x9e\xe8'
                      b'\x14\x91\xf1\xc8r\xb0\x80\x04\xc1\xb9,d'
                      b"\x9c\xf8-\x13~T'4\xf3\x0b\xe0^X&\xb8\x0c"
                      b'\xd3/\xc7y\xea\xb3\xdd\xa2\xee%\xf0z'
                      b'.KY\x0c3\xdba\xb5\xd4~\x90\x0b+\xa3:Q'
                      b'\xda\xaa\x1f\xe8\xf1ov\xaa\xfc\x0bwL'
                      b'H\x85(A0Z<\xee\x85\xa8\xe8%s>\xbc\xa6'
                      b'\x9el\x8ba\xbfg\x81\xd1\x9eFU\xbc'
                      b'\xddZ\x13\xc7)WSFs\xb2A\x9e'
                      b'\x95\x83\xc3\x14\xefee\xf5s\xbbXM'
                      b'\xfd \xcaHZf\xe8\xdc\xa9\xb3\xd9\xe3'
                      b'\x83\x00Uy\x9b\xcb\x0b\xa3\xf9\xb7\x8d\xfe'
                      b'\x84\x8d]\x0e\xf3[t\xb6G\x8dpZ'
                      b'\xaf\xf8\x88\xb0XX\xfb\x89|) 4\xe9z\xa5T'
                      b'u.\x18U<\xf7\xf2\xa8[\x9dF\xc4'
                      b'\xc2\x0f\xb3\xa3\xefo\x12\x13\xbb\x9e\x92g'
                      b'~E\x16n0,\x01\xc7Pu;\x8e\xf8%\xae>'
                      b'\xd5\xe7\x86M?U\xbb:n\x9eU29\xa3\x0bW'
                      b'\xf0\x0b\x00\xbd\x16\x03$\xc0\x0f\x95"~'
                      b'f\xd6\x11\xb5\x01z^;\xe8\x98\xa3\x11'
                      b'\xd77\xf4\xa8\xe4`\xa7\x99\xfao$\xa5'
                      b'\x8eI&\t:\xa4:Z6MS\r\xd3\xc5Y\xe6\xe2F=O'
                      b'\xb2Dp:\x80\x9bd|ikD\xa9\t\r\x94\x90'
                      b'\xd0fi\xf9\\\r1\xfd;\xae\x04\xa6\xc2\x9cHl'
                      b'\x91\xea<\x8fw}\xaeY\x10\x83$\xa0'
                      b';\x91\xc3\xc4&w\x96&\x10\x84\xc7\x0f'
                      b'\xa0\x8c\xd0NC\xd5\x16\xbb\x8b\xae\xe4V'
                      b'\xe0\xb2\xb1\x8b\xcb1\xdf\xd2\xb3_g\x87'
                      b'\xdf\x88S\xae\x1c\x94\xc1\xd9\xc6\x9f\x9aO'
                      b'b|\x1a:\x07(\xeb',
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

    def encrypt(self, T: int, data: bytes, key: str, nonce: bytes | None = None, chksum_type: crypto.Cksumtype | int = crypto.Cksumtype.HMAC_MD5) -> tuple[bytes, bytes]:
        if isinstance(key, str):
            key = crypto._RC4().string_to_key(key, '', None)
        elif isinstance(key, bytes):
            tmp = crypto._RC4().string_to_key('', '', None)
            tmp.contents = key
            key = tmp
        chksum = crypto.make_checksum(chksum_type, key, T, data)
        return self.__handle.encrypt(key, T, data, nonce), chksum

    def decrypt(self, data: bytes, key: str | bytes) -> bytes:
        T = 1
        while T < 16:
            try:
                if isinstance(key, str):
                    key = crypto._RC4().string_to_key(key, '', None)
                elif isinstance(key, bytes):
                    tmp = crypto._RC4().string_to_key('', '', None)
                    tmp.contents = key
                    key = tmp
                return self.__handle.decrypt(key, T, data)
            except crypto.InvalidChecksum:
                T += 1
        raise crypto.InvalidChecksum('Failed to decrypt data')


# embeded_data = TGS_REQ_TEMPLATE['padata'][0]['padata-value']
# pprint(ASN1_KRB5.decode(MESSAGE_TYPES[embeded_data[0]], embeded_data))


socket = scapy.socket.socket(scapy.socket.AF_INET, scapy.socket.SOCK_STREAM)
socket.connect(('192.168.1.102', 88))
as_req = dict(AS_REQ_TEMPLATE)
as_req['padata'][0]['padata-value']['cipher']['patimestamp'] = datetime.datetime.now()
as_req['padata'][0]['padata-value']['cipher'] = ASN1_KRB5.encode('PA-ENC-TS-ENC', as_req['padata'][0]['padata-value']['cipher'])
as_req['padata'][0]['padata-value']['cipher'] = RC4_HMAC_MD5().encrypt(1, as_req['padata'][0]['padata-value']['cipher'], password)[0]
as_req['padata'][0]['padata-value'] = ASN1_KRB5.encode('PA-ENC-TIMESTAMP', as_req['padata'][0]['padata-value'])

as_req['req-body']['cname']['name-string'] = [username]
as_req['req-body']['nonce'] = int(crypto.get_random_bytes(4).hex(), 16)
packet_data = ASN1_KRB5.encode('AS-REQ', AS_REQ_TEMPLATE)
packet_data = len(packet_data).to_bytes(4, 'big') + packet_data
socket.send(packet_data)
result = socket.recv(4096)
print(result)
exit()

'''
Do Authentication
1. Send AS-REQ w/ template
2. Receive AS-REP
3. Parse AS-REP for TGS/Client key and TGT
4. Send TGS-REQ w/ template
5. Receive TGS-REP
6. Parse TGS-REP for Client/Server key and Ticket
7. Send AP-REQ w/ template
'''
def generate_auth_packet(packets: dict):
    '''
    1. Get Session key between TGS and Client from AS-REP using user's key.
    2. Get Ticket from TGS-REP.
    3. Get Session key between Client and Server from TGS-REP using Client/TGS session key.
    '''
    cipher = RC4_HMAC_MD5()
    # 1
    # Extract encrypted key from AS-REP packet data
    enc_client_TGS_key = packets['KRB_AS_REP'][0]['Kerberos']['KRB_AS_REP'].encPart['EncryptedData'].cipher.val
    # Decrypt encrypted key using user's password
    # This is a special key derivation using NTLM hash of user's password as a seed
    # NTLM hash is MD4(UTF-16-LE(password))
    # Decrypt encrypted data using user's password
    decrypted_data = cipher.decrypt(9, enc_client_TGS_key, password)
    # Extract Session Key from ASN1 encoded data
    client_TGS_key = ASN1_KRB5.decode(MESSAGE_TYPES[decrypted_data[0]], decrypted_data)['key']['keyvalue']
    print(client_TGS_key.hex())
    exit()
    # 2
    # Extract Ticket from TGS-REP packet data
    auth_ticket = scapy.raw(packets['KRB_TGS_REP'][0]['Kerberos']['KRB_TGS_REP'].ticket)
    # extract data from ASN1 encoded ticket to dictionary representation of ticket
    ticket_data = ASN1_KRB5.decode('Ticket', auth_ticket)

    # 3
    # Extract encrypted key from TGS-REP packet data
    enc_client_server_key = packets['KRB_TGS_REP'][0]['Kerberos']['KRB_TGS_REP'].encPart['EncryptedData'].cipher.val
    # Decrypt encrypted data using client/TGS session key learned in step 1
    decrypted_data = crypto._RC4().decrypt(client_TGS_key, TGS_REP_T, enc_client_server_key)
    # Extract Session Key from ASN1 encoded data
    client_server_key = ASN1_KRB5.decode(MESSAGE_TYPES[decrypted_data[0]], decrypted_data)['key']['keyvalue']