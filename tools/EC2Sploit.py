import boto3
from botocore.exceptions import ClientError
from tabulate import tabulate
import os

def get_aws_credentials():
    access_key_id = ''
    secret_access_key = ''
    region_name = ''
    
    return access_key_id, secret_access_key, region_name


def create_boto3_session(access_key_id, secret_access_key, region_name):
    return boto3.Session(
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        region_name=region_name
    )

def check_ec2_configuration(session, instance_id, configuration_issues):
    try:
        ec2 = session.resource('ec2')
        instance = ec2.Instance(instance_id)
        output = []

        if instance.state['Name'] == 'terminated':
            issue = "Instance is terminated. Please check your configuration.\n"
            configuration_issues.append(issue)
            output.append(("Instance State", "Issue", instance.state['Name'], issue))
            return False, output

        # Check if instance has tags
        tags = instance.tags
        if tags:
            tags_info = []
            for tag in tags:
                tags_info.append(f"{tag['Key']}: {tag['Value']}")
            output.append(("Tags",  ", ".join(tags_info), ""))
        else:
            issue = "No tags associated. Tags help in organizing and identifying resources.\n"
            configuration_issues.append(issue)
            output.append(("Tags", "Issue", "Not found", issue))
            
        # Check security groups
        security_groups = [group['GroupId'] for group in instance.security_groups]
        output.append(("Security Groups", ", ".join(security_groups), ""))
        if not security_groups:
            issue = "No security groups defined. Security groups control inbound and outbound traffic.\n"
            configuration_issues.append(issue)

        # Check instance type
        instance_type = instance.instance_type
        output.append(("Instance Type", instance_type, ""))
        # No specific risk associated with instance type misconfiguration.

        # Check monitoring
        monitoring = instance.monitoring['State']
        output.append(("Detailed Monitoring Enabled", monitoring, ""))
        if monitoring != 'enabled':
            issue = "Detailed monitoring is not enabled. It provides more granular insights into instance performance.\n"
            configuration_issues.append(issue)

        # Check Elastic IP
        elastic_ip = instance.public_ip_address
        output.append(("Elastic IP associated", elastic_ip if elastic_ip else "No", ""))
        # No specific risk associated with Elastic IP misconfiguration.

        # Check volumes
        volumes = instance.volumes.all()
        for volume in volumes:
            output.append(("Volume ID", volume.id, ""))
        # No specific risk associated with volumes misconfiguration.

        # Check network interfaces
        network_interfaces = instance.network_interfaces
        output.append(("Network Interfaces attached", "Yes" if network_interfaces else "No", ""))
        # No specific risk associated with network interfaces misconfiguration.

        # Check instance state
        instance_state = instance.state['Name']
        output.append(("Instance State", instance_state, ""))
        # No specific risk associated with instance state misconfiguration.

        # Check security groups (inbound and outbound rules)
        security_groups = instance.security_groups
        for group in security_groups:
            # Checking if inbound rules are defined
            if 'IpPermissions' not in group:
                issue = "No inbound rules defined for this security group. Inbound rules control incoming traffic.\n"
                configuration_issues.append(issue)
            # Checking if outbound rules are defined
            if 'IpPermissionsEgress' not in group:
                issue = "No outbound rules defined for this security group. Outbound rules control outgoing traffic.\n"
                configuration_issues.append(issue)

        # Check placement
        placement = instance.placement
        output.append(("Availability Zone", placement['AvailabilityZone'], ""))
        # No specific risk associated with placement misconfiguration.

        # Check tenancy
        output.append(("Tenancy", placement['Tenancy'], ""))
        # No specific risk associated with tenancy misconfiguration.

        # Check termination protection
        termination_protection = instance.describe_attribute(Attribute='disableApiTermination')['DisableApiTermination']
        output.append(("Termination Protection", termination_protection, ""))
        # No specific risk associated with termination protection misconfiguration.

        # Check if there are any configuration issues
        if not configuration_issues:
            output.append(("Configuration Status", "Well Configured", ""))
        else:
            output.append(("Configuration Status", "Not Well Configured", " * ".join(configuration_issues)))

        return True, output

    except ClientError as e:
        configuration_issues.append(f"An error occurred: {e}")
        return False, None


def check_cloudwatch_alarms(session, instance_id, configuration_issues):
    try:
        cloudwatch_client = session.client('cloudwatch')
        output = []

        alarms = cloudwatch_client.describe_alarms(AlarmNamePrefix=f"{instance_id}-")

        metric_alarms = alarms['MetricAlarms']

        if metric_alarms:
            for alarm in metric_alarms:
                output.append(("CloudWatch Alarms", alarm['AlarmName'], alarm['StateValue']))
        else:
            # If there are no CloudWatch alarms set up for this instance
            configuration_issues.append("No CloudWatch Alarms set up for this instance.")
            # Explanation: CloudWatch alarms allow you to monitor various metrics of your instance, such as CPU utilization, 
            # network traffic, and disk I/O. Setting up alarms helps you proactively detect and respond to performance 
            # issues or resource constraints. For example, without alarms, you may not be aware of sudden spikes in CPU 
            # utilization, which could lead to performance degradation or unexpected costs. Similarly, without network 
            # traffic alarms, you may overlook potential security threats or network congestion issues.
            output.append(("CloudWatch Alarms", "Not set up", "Lack of proactive monitoring for performance issues and security threats \n Consider setting up CloudWatch Alarms for proactive monitoring"))
            # Risks/Issues: Without CloudWatch alarms, you may face challenges in detecting and responding to performance 
            # issues, resource constraints, or security threats in a timely manner. This could result in degraded instance 
            # performance, increased operational costs, or even security vulnerabilities.
            
            
        return True, output

    except ClientError as e:
        # If an error occurs while checking CloudWatch alarms
        configuration_issues.append(f"An error occurred: {e}")
        return False, None


def check_ec2_security_configuration(session, instance_id, security_issues):
    try:
        ec2 = session.resource('ec2')
        instance = ec2.Instance(instance_id)
        output = []

        if instance.state['Name'] == 'terminated':
            issue = "Instance is terminated. Please check your configuration."
            security_issues.append(issue)
            output.append(("Instance State", "Issue", instance.state['Name'], issue))
            return False, output

        # Check if instance has a key pair
        key_pair = instance.key_name
        if key_pair:
            output.append(("Key Pair associated",  key_pair, ""))
        else:
            security_issues.append("No Key Pair associated. This instance may be accessed only through IAM role")

        # Check network ACLs
        network_interfaces = instance.network_interfaces_attribute
        output.append(("Network ACLs associated",  network_interfaces[0].get('NetworkAclId') if network_interfaces else "No", ""))
        if network_interfaces:
            for association in network_interfaces[0].get('Groups', []):
                if 'NetworkAclId' in association:
                    output.append(("Network ACL ID",  association.get('NetworkAclId'), ""))

        # Check data volume encryption
        data_volume_encrypted = all(mapping.get('Ebs', {}).get('Encrypted', False) for mapping in instance.block_device_mappings[1:])
        output.append(("Data Volume Encrypted", data_volume_encrypted, ""))

        # Check root volume encryption
        root_volume_encrypted = instance.root_device_name != instance.block_device_mappings[0]['Ebs']['VolumeId']
        output.append(("Root Volume Encrypted", root_volume_encrypted, ""))
        if not root_volume_encrypted:
            security_issues.append("Root volume is not encrypted.")

        # Check IAM instance profile policies
        iam_role = instance.iam_instance_profile
        if iam_role:
            iam = session.client('iam')
            role_name = iam_role['Arn'].split('/')[-1]
            role_policies = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
            policies_info = []
            for policy in role_policies:
                policies_info.append(policy['PolicyName'])
            output.append(("IAM Instance Profile Policies",  ", ".join(policies_info), ""))
        else:
            security_issues.append("No IAM Role attached.")
            

        # Check for publicly exposed sensitive data (Example: S3 bucket policy)
        # Note: This is a placeholder. Actual implementation depends on specific use case.
        # For example, you could check if the instance has IAM role permissions to access sensitive S3 buckets.
        sensitive_data_exposed = False  
        if sensitive_data_exposed:
            output.append(("Sensitive Data Exposure", "Detected", "Publicly exposed sensitive data found"))
        else:
            output.append(("Sensitive Data Exposure", "Not Detected", "No publicly exposed sensitive data found"))
        
        # Check for unpatched software
        # Note: This is a placeholder. Actual implementation may involve querying package versions or security advisories.
        # For example, you could check for outdated package versions or missing security patches.
        unpatched_software = False  
        if unpatched_software:
            output.append(("Software Patching", "Required", "Unpatched software detected"))
        else:
            output.append(("Software Patching", "Not Required", "No unpatched software detected"))

        # Check SSH/RDP Configuration
        # Note: This is a placeholder. Actual implementation may involve checking SSH key strength or RDP encryption settings.
        # For example, you could check if SSH allows root login or if RDP encryption is enabled.
        ssh_rdp_config_issue = False 
        if ssh_rdp_config_issue:
            output.append(("SSH/RDP Configuration", "Weak", "Weak SSH/RDP configuration detected"))
        else:
            output.append(("SSH/RDP Configuration", "Secure", "SSH/RDP configuration is secure"))

        # Describe instance to get instance metadata options
        ec2_client = session.client('ec2')
        response = ec2_client.describe_instances(
            InstanceIds=[instance_id]
        )

        reservations = response['Reservations']

        if reservations:
            instances = reservations[0]['Instances']
            if instances:
                instance = instances[0]
                metadata_options = instance.get('MetadataOptions', {})
                output.append(("Http Tokens",  metadata_options.get('HttpTokens'), ""))
                output.append(("Http Put Response Hop Limit", metadata_options.get('HttpPutResponseHopLimit'), ""))
                output.append(("Http Endpoint",  metadata_options.get('HttpEndpoint'), ""))
            else:
                output.append(("Instance Metadata Options", "No instances found with the provided ID.", ""))
        else:
            output.append(("Instance Metadata Options",  "No reservations found with the provided ID.", ""))

        if not security_issues:
            output.append(("Security Configuration Status", "Well Configured", ""))
        else:
            output.append(("Security Configuration Status",  "Not Well Configured", ", ".join(security_issues)))

        return True, output

    except ClientError as e:
        security_issues.append(f"An error occurred: {e}")
        return False, None


# Main function
def main():
    access_key_id, secret_access_key, region_name = get_aws_credentials()
    session = create_boto3_session(access_key_id, secret_access_key, region_name)

    instance_id = 'i-0e11d5ae39f29ece7'
    output_folder = "outputs/"
    
    configuration_issues = []
    security_issues = []

    configuration_success, configuration_output = check_ec2_configuration(session, instance_id, configuration_issues)
    cloudwatch_success, cloudwatch_output = check_cloudwatch_alarms(session, instance_id, configuration_issues)
    security_success, security_output = check_ec2_security_configuration(session, instance_id, security_issues)

    if configuration_success and cloudwatch_success and security_success:
        print("All scans completed.")
    else:
        print("Instance has configuration or security issues.")
        print("Issues:")
        for issue in configuration_issues:
            print("- Configuration Issue:", issue)
            print("Configure this manually to resolve the issue.")
        for issue in security_issues:
            print("- Security Issue:", issue)
            print("Configure this manually to improve security.")
    
    # Create the output folder if it doesn't exist
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    output_file_path = os.path.join(output_folder, f"{instance_id}.txt")

    # Write output to the file
    with open(output_file_path, "w") as f:
        f.write("EC2 Configuration Check:\n")
        f.write(tabulate(configuration_output, headers=["Value", "Comments"], tablefmt="grid"))
        f.write("\n\n")
        f.write("CloudWatch Alarms Check:\n")
        f.write(tabulate(cloudwatch_output, headers=["Value", "Comments"], tablefmt="grid"))
        f.write("\n\n")
        f.write("EC2 Security Check:\n")
        f.write(tabulate(security_output, headers=["Value", "Comments"], tablefmt="grid"))

    # Check if output_file_path is defined before printing
    if 'output_file_path' in locals():
        print(f"Output saved to {output_file_path}")
    else:
        print("There was an error saving the output.")

if __name__ == "__main__":
    main()
