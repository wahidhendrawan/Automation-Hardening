import unittest
from unittest.mock import MagicMock, patch
import sys
import os
import io

# Mock boto3 before importing aws_harden
mock_boto3 = MagicMock()
sys.modules['boto3'] = mock_boto3
mock_botocore = MagicMock()
sys.modules['botocore'] = mock_botocore
sys.modules['botocore.exceptions'] = MagicMock()
import botocore.exceptions
sys.modules['botocore.exceptions'].NoCredentialsError = type('NoCredentialsError', (Exception,), {})
sys.modules['botocore.exceptions'].ClientError = type('ClientError', (Exception,), {})

# Add the cloud directory to the path
sys.path.append(os.path.join(os.getcwd(), 'cloud'))

import aws_harden

class TestS3Audit(unittest.TestCase):
    def test_audit_s3_public_access_parity(self):
        # Mock boto3 client
        mock_s3 = MagicMock()

        # Mock list_buckets
        buckets = [
            {'Name': 'public-bucket'},
            {'Name': 'private-bucket'}
        ]
        mock_s3.list_buckets.return_value = {'Buckets': buckets}

        # Mock get_bucket_acl
        def mocked_get_bucket_acl(Bucket):
            if Bucket == 'public-bucket':
                return {
                    'Grants': [
                        {
                            'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}
                        }
                    ]
                }
            else:
                return {'Grants': []}

        mock_s3.get_bucket_acl.side_effect = mocked_get_bucket_acl

        # Configure mock_boto3.client to return our mock_s3
        mock_boto3.client.return_value = mock_s3

        # Capture output
        with patch('sys.stdout', new=io.StringIO()) as fake_out:
            aws_harden.audit_s3_public_access()
            output = fake_out.getvalue()

        self.assertIn("WARNING: Bucket 'public-bucket' has PUBLIC access!", output)
        self.assertIn("Bucket 'private-bucket' is private.", output)
        self.assertEqual(mock_s3.get_bucket_acl.call_count, 2)

    def test_audit_s3_public_access_exception_propagation(self):
        # Mock boto3 client
        mock_s3 = MagicMock()

        # Mock list_buckets
        buckets = [{'Name': 'error-bucket'}]
        mock_s3.list_buckets.return_value = {'Buckets': buckets}

        # Mock get_bucket_acl to raise an unexpected Exception
        mock_s3.get_bucket_acl.side_effect = Exception("Unexpected Error")

        # Configure mock_boto3.client to return our mock_s3
        mock_boto3.client.return_value = mock_s3

        # Capture output
        with patch('sys.stdout', new=io.StringIO()) as fake_out:
            aws_harden.audit_s3_public_access()
            output = fake_out.getvalue()

        self.assertIn("[!] Error: Unexpected Error", output)

if __name__ == "__main__":
    unittest.main()
