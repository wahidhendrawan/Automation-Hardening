import boto3
from botocore.exceptions import NoCredentialsError, ClientError
import concurrent.futures

def run_audit():
    print("[*] Running AWS Audit...")

    # Check 1: S3 Buckets Public Access
    audit_s3_public_access()

def audit_s3_public_access():
    print("[*] Checking S3 Buckets for public access...")
    s3 = boto3.client('s3')

    try:
        response = s3.list_buckets()
        if 'Buckets' in response:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                # Wrap execution in futures to ensure exceptions are captured and re-raised
                futures = [executor.submit(check_bucket_acl, s3, bucket['Name']) for bucket in response['Buckets']]
                for future in concurrent.futures.as_completed(futures):
                    future.result()
        else:
            print("[+] No buckets found.")
    except NoCredentialsError:
        print("[!] No AWS credentials found. Please configure ~/.aws/credentials.")
    except ClientError as e:
        print(f"[!] AWS Client Error: {e}")
    except Exception as e:
        print(f"[!] Error: {e}")

def check_bucket_acl(s3, bucket_name):
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        public = False
        for grant in acl['Grants']:
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                public = True
                break

        if public:
             print(f"[!] WARNING: Bucket '{bucket_name}' has PUBLIC access!")
        else:
             print(f"[+] Bucket '{bucket_name}' is private.")

    except ClientError as e:
        print(f"[!] Could not check bucket '{bucket_name}': {e}")
