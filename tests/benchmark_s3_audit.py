import time
import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Mock boto3 before importing aws_harden
mock_boto3 = MagicMock()
sys.modules['boto3'] = mock_boto3
mock_botocore = MagicMock()
sys.modules['botocore'] = mock_botocore
sys.modules['botocore.exceptions'] = MagicMock()

# Add the cloud directory to the path
sys.path.append(os.path.join(os.getcwd(), 'cloud'))

import aws_harden

def benchmark_audit_s3_public_access(num_buckets=10, delay=0.1):
    print(f"Benchmarking with {num_buckets} buckets and {delay}s delay per call...")

    # Mock boto3 client
    mock_s3 = MagicMock()

    # Mock list_buckets
    buckets = [{'Name': f'bucket-{i}'} for i in range(num_buckets)]
    mock_s3.list_buckets.return_value = {'Buckets': buckets}

    # Mock get_bucket_acl with a delay
    def mocked_get_bucket_acl(Bucket):
        time.sleep(delay)
        return {'Grants': []}

    mock_s3.get_bucket_acl.side_effect = mocked_get_bucket_acl

    # Configure mock_boto3.client to return our mock_s3
    mock_boto3.client.return_value = mock_s3

    start_time = time.time()
    aws_harden.audit_s3_public_access()
    end_time = time.time()

    duration = end_time - start_time
    print(f"Total time: {duration:.4f} seconds")
    return duration

if __name__ == "__main__":
    benchmark_audit_s3_public_access()
