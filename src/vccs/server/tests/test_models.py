# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import field, asdict
from enum import Enum, unique
from typing import Dict, Any, Mapping
from unittest import TestCase
from bson import ObjectId
from pydantic import Field
from pydantic.dataclasses import dataclass

__author__ = 'lundberg'

from pydantic.main import BaseModel


@unique
class Status(str, Enum):
    ACTIVE: str = 'active'
    DISABLED: str = 'disabled'


@unique
class Version(str, Enum):
    NDNv1: str = 'NDNv1'


@unique
class KDF(str, Enum):
    PBKDF2_HMAC_SHA512: str = 'PBKDF2-HMAC-SHA512'


class CredType(str, Enum):
    PASSWORD: str = 'password'
    REVOKED: str = 'revoked'


class Credential(BaseModel):
    credential_id: str
    status: Status
    type: CredType
    revision: int = 1
    obj_id: ObjectId = Field(default_factory=ObjectId, alias='_id')

    class Config:
        # only check that obj_id is an instance of ObjectId
        arbitrary_types_allowed = True

    @classmethod
    def from_dict(cls: CredType[Credential], data: Mapping[str, Any]) -> Credential:
        """ Construct element from a data dict in database format. """

        _data = dict(data)  # to not modify callers data
        if 'credential' in _data:
            # move contents from 'credential' to top-level of dict
            _data.update(_data.pop('credential'))
        return cls(**_data)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert instance to database format.

        Example of database format:

        {
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
        """
        data = self.dict(by_alias=True)
        # Extract the _id and revision
        obj_id = data.pop('_id')
        revision = data.pop('revision')
        return {
            '_id': obj_id,
            'revision': revision,
            'credential': data,
        }


class PasswordCredential(Credential):
    derived_key: str
    iterations: int
    kdf: KDF
    key_handle: int
    salt: str
    version: Version


class ModelTests(TestCase):

    def setUp(self) -> None:
        self.credential_doc = {
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

    def test_credential(self):
        cred = PasswordCredential.from_dict(self.credential_doc)
        assert isinstance(cred.status, Enum)
        assert isinstance(cred.version, Enum)
        assert isinstance(cred.kdf, Enum)
        assert isinstance(cred.type, Enum)
        assert cred.to_dict() == self.credential_doc
