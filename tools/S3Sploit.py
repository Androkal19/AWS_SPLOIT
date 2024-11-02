from tabulate import tabulate
import boto3
import json
import os
from botocore.exceptions import ClientError

def check_bucket_policy(bucket_name,access_key_id, secret_access_key):
    """
    Check if a bucket policy is set for an S3 bucket. If not, set the provided policy.
    
    Parameters:
        bucket_name (str): The name of the S3 bucket.
        policy (dict): The bucket policy in JSON format.
        access_key_id (str): AWS Access Key ID.
        secret_access_key (str): AWS Secret Access Key.
        
    Returns:
        str: Message indicating whether the bucket policy was set or not.
    """
    s3_client = boto3.client('s3', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    
    try:
        response = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy = response['Policy']
        print("Bucket policy already set:")
        return policy
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            print("No bucket policy set for the bucket.")
            return None
        else:
            print("Error checking bucket policy:", e)
            return None
        
def set_bucket_policy(bucket_name,access_key_id, secret_access_key):
    """
    Set a sample bucket policy for the given S3 bucket.
    """
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*"
            }
        ]
    }

    s3_client = boto3.client('s3', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    try:
        # Set the bucket policy
        s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy_document))
        print("Bucket policy set successfully.")
    except ClientError as e:
        print("Error setting bucket policy:", e)

def get_aws_credentials():
    return 'access_key', 'Secret_access_key'

def check_bucket_public_access(bucket_name, access_key_id, secret_access_key):
    s3 = boto3.client('s3', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    try:
        response = s3.get_bucket_policy(Bucket=bucket_name)
        policy = response['Policy']
        if '"Effect": "Allow"' in policy and '"Principal": "*"' in policy:
            return f"The bucket {bucket_name} allows public access."
        else:
            return f"The bucket {bucket_name} does not allow public access."
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            return f"No bucket policy found for {bucket_name}"
        else:
            return f"Error retrieving bucket policy for {bucket_name}: {e}"

def check_bucket_encryption(bucket_name, access_key_id, secret_access_key):
    s3 = boto3.client('s3', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    try:
        response = s3.get_bucket_encryption(Bucket=bucket_name)
        if 'ServerSideEncryptionConfiguration' in response:
            return f"The bucket {bucket_name} has encryption enabled."
        else:
            return f"The bucket {bucket_name} does not have encryption enabled or no encryption configuration is set."
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            return f"No encryption configuration found for {bucket_name} Bucket."
        else:
            return f"Error retrieving encryption configuration for {bucket_name}: {e}"

def check_and_enable_versioning(bucket_name, access_key_id, secret_access_key):
    """
    Check if versioning is enabled for the bucket. If not, prompt the user to enable it.
    
    Parameters:
        bucket_name (str): The name of the S3 bucket.
        access_key_id (str): AWS Access Key ID.
        secret_access_key (str): AWS Secret Access Key.
        
    Returns:
        str: Message indicating whether versioning was enabled or not.
    """
    s3 = boto3.client('s3', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    try:
        response = s3.get_bucket_versioning(Bucket=bucket_name)
        if 'Status' in response and response['Status'] == 'Enabled':
            return f"Versioning is already enabled for the bucket {bucket_name}."
        else:
            # Prompt the user to enable versioning
            enable_versioning = input(f"Versioning is not enabled for the bucket {bucket_name}. Do you want to enable it? (y/n): ")
            if enable_versioning.lower() == 'y':
                # Enable versioning
                s3.put_bucket_versioning(
                    Bucket=bucket_name,
                    VersioningConfiguration={
                        'Status': 'Enabled'
                    }
                )
                return f"Versioning has been enabled for the bucket {bucket_name}."
            else:
                return "Versioning was not enabled."
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketConfiguration':
            return f"No versioning configuration found for {bucket_name}"
        else:
            return f"Error retrieving versioning configuration for {bucket_name}: {e}"


def check_server_access_logging(bucket_name, access_key_id, secret_access_key):
    s3 = boto3.client('s3', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    try:
        response = s3.get_bucket_logging(Bucket=bucket_name)
        if 'LoggingEnabled' in response:
            logging_config = response['LoggingEnabled']
            logging_bucket = logging_config['TargetBucket']
            logging_prefix = logging_config['TargetPrefix']
            return f"Server access logging is enabled for the bucket {bucket_name}. Logs are being stored in bucket '{logging_bucket}' with prefix '{logging_prefix}'."
        else:
            return f"Server access logging is not enabled for the bucket {bucket_name}."
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketLogging':
            return f"No server access logging configuration found for {bucket_name}"
        else:
            return f"Error retrieving server access logging configuration for {bucket_name}: {e}"

def check_bucket_acl_misconfiguration(bucket_name, access_key_id, secret_access_key):
    s3 = boto3.client('s3', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    try:
        response = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in response['Grants']:
            if 'URI' in grant['Grantee']:
                return f"The bucket {bucket_name} has ACL misconfiguration allowing public access."
        return f"The bucket {bucket_name} does not have ACL misconfiguration."
    except s3.exceptions.ClientError as e:
        return f"Error retrieving bucket ACL for {bucket_name}: {e}"

def check_bucket_name_disclosure(access_key_id, secret_access_key):
    try:
        s3 = boto3.client('s3', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
        response = s3.list_buckets()
        buckets = [bucket['Name'] for bucket in response['Buckets']]
        for bucket_name in buckets:
            response = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in response['Grants']:
                if 'URI' in grant['Grantee']:
                    return f"The bucket name '{bucket_name}' is publicly accessible."
        return "No bucket name disclosure found."
    except boto3.exceptions.ClientError as e:
        return f"Error accessing S3: {e}"

def check_bucket_mfa_delete(bucket_name, access_key_id, secret_access_key):
    s3 = boto3.client('s3', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    try:
        response = s3.get_bucket_versioning(Bucket=bucket_name)
        if 'MFADelete' in response and response['MFADelete'] == 'Enabled':
            return f"MFA delete is enabled for the bucket {bucket_name}."
        else:
            return f"MFA delete is not enabled for the bucket {bucket_name}."
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketConfiguration':
            return f"No versioning configuration found for {bucket_name}"
        else:
            return f"Error retrieving versioning configuration for {bucket_name}: {e}"

def check_object_permission(bucket_name, access_key_id, secret_access_key):
    s3 = boto3.client('s3', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    try:
        response = s3.list_objects_v2(Bucket=bucket_name)
        if 'Contents' in response:
            objects = response['Contents']
            permissions = []
            for obj in objects:
                key = obj['Key']
                response = s3.get_object_acl(Bucket=bucket_name, Key=key)
                for grant in response['Grants']:
                    grantee = grant['Grantee']
                    permission = grant['Permission']
                    if grantee['Type'] == 'Group' and grantee['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        permissions.append(f"The object {key} in bucket {bucket_name} is publicly accessible with permission: {permission}")
                    elif grantee['Type'] == 'CanonicalUser':
                        canonical_user_id = grantee['ID']
                        permissions.append(f"The object {key} in bucket {bucket_name} is accessible by canonical user {canonical_user_id} with permission: {permission}")
                    elif grantee['Type'] == 'AmazonCustomerByEmail':
                        email_address = grantee['EmailAddress']
                        permissions.append(f"The object {key} in bucket {bucket_name} is accessible by Amazon customer with email {email_address} with permission: {permission}")
                    elif grantee['Type'] == 'Group' and grantee['URI'] == 'http://acs.amazonaws.com/groups/s3/LogDelivery':
                        permissions.append(f"The object {key} in bucket {bucket_name} is accessible by AWS S3 log delivery group with permission: {permission}")
                    else:
                        permissions.append(f"The object {key} in bucket {bucket_name} has an unknown grantee type with permission: {permission}")
            return '\n'.join(permissions)
        else:
            return f"No objects found in bucket {bucket_name}"
    except s3.exceptions.ClientError as e:
        return f"Error accessing S3: {e}"

def check_and_enable_block_public_access(bucket_name, access_key_id, secret_access_key):
    """
    Check the block public access settings for a bucket. If disabled, prompt the user to enable it.
    
    Parameters:
        bucket_name (str): The name of the S3 bucket.
        access_key_id (str): AWS Access Key ID.
        secret_access_key (str): AWS Secret Access Key.
        
    Returns:
        str: Message indicating whether block public access was enabled or not.
    """
    s3 = boto3.client('s3', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        block_public_access = response['PublicAccessBlockConfiguration']
        if block_public_access['BlockPublicAcls'] or block_public_access['IgnorePublicAcls'] or block_public_access['RestrictPublicBuckets']:
            return f"Block public access is already enabled for the bucket {bucket_name}."
        else:
            # Prompt the user to enable block public access
            enable_access = input(f"Block public access is disabled for the bucket {bucket_name}. Do you want to enable it? (y/n): ")
            if enable_access.lower() == 'y':
                # Enable block public access
                s3.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        'BlockPublicAcls': True,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    }
                )
                return f"Block public access has been enabled for the bucket {bucket_name}."
            else:
                return "Block public access was not enabled."
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            return f"No block public access configuration found for {bucket_name}"
        else:
            return f"Error retrieving block public access configuration for {bucket_name}: {e}"


def check_bucket_cors(bucket_name, access_key_id, secret_access_key):
    s3 = boto3.client('s3', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    try:
        response = s3.get_bucket_cors(Bucket=bucket_name)
        cors_rules = response['CORSRules']
        if cors_rules:
            cors_config = f"CORS configuration found for the bucket {bucket_name}:\n"
            for rule in cors_rules:
                cors_config += json.dumps(rule, indent=2) + "\n"
            return cors_config.strip()
        else:
            return f"No CORS configuration found for the bucket {bucket_name}"
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchCORSConfiguration':
            return f"No CORS configuration found for {bucket_name}"
        else:
            return f"Error retrieving CORS configuration for {bucket_name}: {e}"

def check_object_ownership(bucket_name, access_key_id, secret_access_key):
    s3 = boto3.client('s3', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    try:
        response = s3.list_objects_v2(Bucket=bucket_name)
        if 'Contents' in response:
            objects = response['Contents']
            ownership_info = []
            for obj in objects:
                key = obj['Key']
                response_acl = s3.get_object_acl(Bucket=bucket_name, Key=key)
                owner_id = response_acl['Owner']['ID']
                ownership_info.append(f"The object {key} in bucket {bucket_name} is owned by user with ID: {owner_id}")
            return '\n'.join(ownership_info)
        else:
            return f"No objects found in bucket {bucket_name}"
    except s3.exceptions.ClientError as e:
        return f"Error accessing S3: {e}"

def check_intelligent_tiering_archive(bucket_name, access_key_id, secret_access_key):
    s3 = boto3.client('s3', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    try:
        response = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        rules = response.get('Rules', [])
        for rule in rules:
            transitions = rule.get('Transitions', [])
            for transition in transitions:
                if transition.get('StorageClass', '') == 'INTELLIGENT_TIERING_ARCHIVE':
                    return f"Intelligent-Tiering Archive configuration found for the bucket {bucket_name}"
        return f"No Intelligent-Tiering Archive configuration found for the bucket {bucket_name}"
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
            return f"No lifecycle configuration found for {bucket_name}"
        else:
            return f"Error retrieving lifecycle configuration for {bucket_name}: {e}"


if __name__ == "__main__":
    access_key_id, secret_access_key = get_aws_credentials()
    s3 = boto3.client('s3', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    try:
        response = s3.list_buckets()
        buckets = [bucket['Name'] for bucket in response['Buckets']]
        # Iterate through each bucket
        for bucket_name in buckets:
            print(f"Checking bucket: {bucket_name}")
        
            # Check if bucket policy is set
            existing_policy = check_bucket_policy(bucket_name, access_key_id, secret_access_key)

            # If policy doesn't exist, set it
            if not existing_policy:
                set_bucket_policy(bucket_name,access_key_id,secret_access_key)
                
            
            enable_access_message = check_and_enable_block_public_access(bucket_name, access_key_id, secret_access_key)
            print(enable_access_message)
                
        results = []
        max_bucket_name_length = max(len(bucket_name) for bucket_name in buckets)  # Calculate the maximum length of bucket name
        for bucket_name in buckets:
            row = [
                bucket_name.center(max_bucket_name_length),  # Center-align the bucket name
                check_bucket_policy(bucket_name, access_key_id, secret_access_key),
                check_bucket_public_access(bucket_name, access_key_id, secret_access_key),
                check_bucket_encryption(bucket_name, access_key_id, secret_access_key),
                check_and_enable_versioning(bucket_name, access_key_id, secret_access_key),
                check_server_access_logging(bucket_name, access_key_id, secret_access_key),
                check_bucket_acl_misconfiguration(bucket_name, access_key_id, secret_access_key),
                check_bucket_name_disclosure(access_key_id, secret_access_key),
                check_bucket_mfa_delete(bucket_name, access_key_id, secret_access_key),
                check_object_permission(bucket_name, access_key_id, secret_access_key),
                check_and_enable_block_public_access(bucket_name, access_key_id, secret_access_key),
                check_bucket_cors(bucket_name, access_key_id, secret_access_key),
                check_object_ownership(bucket_name, access_key_id, secret_access_key),
                check_intelligent_tiering_archive(bucket_name, access_key_id, secret_access_key)
            ]
            results.append(row)
        
        headers = [
            "Bucket Name", "Policy", "Public Access", "Encryption",
            "Versioning", "Logging", "ACL Misconfiguration", "Bucket Name Disclosure",
            "MFA Delete", "Object Permission", "Block Public Access", "CORS",
            "Object Ownership", "Intelligent Tiering Archive"
        ]
        table_data = []
        for header, row in zip(headers, zip(*results)):
            table_data.extend([[header, value] for value in row])
        
        output_data = tabulate(table_data, headers=["Category", "Value"], tablefmt="grid", colalign=("left", "left"))
        
        output_folder = "outputs/"
        output_file_path = os.path.join(output_folder, f"{bucket_name}_analysis.txt")

        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

        with open(output_file_path, "w") as file:
            file.write(output_data)

        print(f"Output saved to '{output_file_path}'")

    except Exception as e:
        print(f"An error occurred: {e}")





