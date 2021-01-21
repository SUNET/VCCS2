import unittest

from bson import ObjectId

from vccs.server.db import PasswordCredential, RevokedCredential, Status


class TestCredential(unittest.TestCase):
    def setUp(self):
        self.data = {
            '_id': ObjectId('54042b7a9b3f2299bb9d5546'),
            'credential': {
                'status': 'active',
                'derived_key': '65d27b345ceafe533c3314e021517a84be921fa545366a755d998d140bb6e596fd8'
                '7b61296a60eb8a17a1523350869ee97b581a1b75ba77b3d625d3281186fc5',
                'version': 'NDNv1',
                'iterations': 50000,
                'key_handle': 8192,
                'salt': 'd393c00d56d3c6f0fcf32421395427d2',
                'kdf': 'PBKDF2-HMAC-SHA512',
                'type': 'password',
                'credential_id': '54042b7aafce77049473096a',
            },
            'revision': 1,
        }

    def test_from_dict(self):
        cred = PasswordCredential.from_dict(self.data)
        assert cred.key_handle == 8192

    def test_to_dict_from_dict(self):
        cred1 = PasswordCredential.from_dict(self.data)
        cred2 = PasswordCredential.from_dict(cred1.to_dict())
        assert cred1.to_dict() == cred2.to_dict()
        assert cred2.to_dict() == self.data


class TestRevokedCredential(unittest.TestCase):
    def setUp(self):
        self.old_data = {
            'status': 'revoked',
            'credential_id': '4712',
            'key_handle': 1,
            'type': 'password',
            'kdf': 'PBKDF2-HMAC-SHA512',
            'derived_key': '599ab85b4539b3475...040ab2df0f',
            'version': 'NDNv1',
            'revocation_info': {
                'timestamp': 1608286347,
                'client_ip': '172.16.10.1',
                'reason': 'Testing',
                'reference': '',
            },
            'iterations': 50000,
            'salt': '6bcd35c5f9d306494cc166a183f3da91',
        }

        self.data = {
            '_id': ObjectId('54042b7a9b3f2299bb9d5546'),
            'credential': {
                'status': 'active',
                'type': 'password',
                'credential_id': '54042b7aafce77049473096a',
                'reason': 'a reason',
                'reference': 'a reference'
            },
            'revision': 1,
        }

    def test_from_dict_backwards_compat(self):
        cred = RevokedCredential.from_dict_backwards_compat(self.old_data)
        assert cred.status == Status.DISABLED

    def test_to_dict_from_dict(self):
        rev_cred1 = RevokedCredential.from_dict(self.data)
        rev_cred2 = RevokedCredential.from_dict(rev_cred1.to_dict())
        assert rev_cred1.to_dict() == rev_cred2.to_dict()
        assert rev_cred2.to_dict() == self.data
