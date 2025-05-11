

---

# **AWS Instance and S3 Bucket Misconfiguration Scanner**

## **Overview**

The **AWS Instance and S3 Bucket Misconfiguration Scanner** is a security tool designed to scan AWS resources and identify potential misconfigurations that could lead to security vulnerabilities. The tool focuses on detecting common misconfigurations in **EC2 instances** and **S3 buckets**, helping organizations maintain security best practices and reduce their attack surface.

## **Features**

- **EC2 Instance Security Check**:
  - Identifies instances with public IP exposure.
  - Verifies security group rules to detect overly permissive inbound/outbound traffic.
  - Alerts on instances missing key security configurations (e.g., no IAM role, unencrypted volumes).

- **S3 Bucket Misconfiguration Detection**:
  - Identifies public buckets and objects that are readable or writable by everyone.
  - Detects misconfigured bucket policies and ACLs.
  - Alerts on unencrypted buckets and lack of versioning.

- **Report Generation**:
  - Generates detailed security reports on identified misconfigurations.
  - Suggests remediation steps for each finding.

## **Prerequisites**

Before running the tool, ensure you have the following:

- **AWS CLI** configured with appropriate permissions.
  - Ensure the IAM user has permissions for `ec2:DescribeInstances`, `ec2:DescribeSecurityGroups`, `s3:ListBuckets`, `s3:GetBucketAcl`, `s3:GetBucketPolicy`, and other relevant actions.
- **Python 3.x** installed on your system.
- **Boto3** AWS SDK for Python:
  ```bash
  pip install boto3
  ```

## **Installation**

1. **Clone the repository** to your local machine:
   ```bash
   git clone https://github.com/Androkal19/AWS_SPLOIT.git
   cd AWS_SPLOIT
   ```

2. **Install required dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## **Usage**


1. **Combined EC2 & S3 Scan**:
   ```bash
   python AWS_Sploit.py
   ```

2. **Report**:  
   After running the tool, a detailed report in `.txt` format will be generated in the `/output` directory, summarizing all the findings.

## **Output**

Below is a snippet of what the report might look like:

![Screenshot 2024-05-04 170721](https://github.com/user-attachments/assets/40dfbede-5c73-4724-8cb0-f95c960f66b8)

## **Future Enhancements**

- Support for scanning additional AWS services such as RDS, Lambda, and CloudFront.
- Integration with cloud security monitoring tools for continuous detection.
- Automated remediation capabilities.

## **License**

This project is licensed under the **Apache License 2.0** - see the [LICENSE](LICENSE) file for details.

---

## **Contact**

For any questions or support, feel free to contact:  
- **Name**: Androkal  
- **Email**: androkal28@gmail.com  
- **GitHub**: (https://github.com/Androkal19)

---


---

# **AWS Misconfiguration Scan Report**
 
**AWS Region**: us-east-1

---

## **EC2 Instance Findings**

![Screenshot 2024-05-04 170540](https://github.com/user-attachments/assets/720e93ab-f975-4f8a-9c1e-834e7f4ae90d)

### **Recommendations**:
- Restrict SSH access to trusted IP ranges (avoid 0.0.0.0/0).
- Assign IAM roles to instances to manage permissions securely.

---

## **S3 Bucket Findings**

![Screenshot 2024-05-04 170618](https://github.com/user-attachments/assets/ea8396d1-ce6a-4b26-897c-312ce3cd195d)

### **Recommendations**:
- Disable public access to buckets unless absolutely necessary.
- Enable encryption and versioning for sensitive data.

---

## **Summary**

The scan detected ** EC2 misconfigurations** and ** S3 misconfigurations**. It is recommended to address high and critical risk issues immediately to prevent potential security breaches.

For more detailed guidance, refer to **AWS security best practices** [here](https://docs.aws.amazon.com/security/).

---
