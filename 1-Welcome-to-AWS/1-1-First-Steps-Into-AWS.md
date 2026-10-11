# TryHackMe - AWS Cloud Fundamentals Writeup

> **Platform:** TryHackMe  
> **Challenge:** AWS Cloud Fundamentals  
> **Category:** Cloud Security | AWS | CloudShell | AWS CLI | IAM

---

# Overview

This room introduces the fundamentals of working with **Amazon Web Services (AWS)** through the TryHackMe cloud lab environment.

The objective is to become familiar with the AWS Management Console, understand how cloud lab environments work, and execute basic commands using AWS CloudShell and the AWS Command Line Interface (CLI).

Unlike traditional penetration testing challenges, this room focuses on **cloud administration, identity verification, credential configuration, and AWS service enumeration**.

These skills provide a foundation for cloud security monitoring, IAM security assessments, cloud incident response, and identifying misconfigurations in AWS environments.

---

# AWS Environment Setup

The first step is provisioning the AWS lab environment provided by TryHackMe.

The environment can be started through the Cloud Details interface.

### Environment Initialization

1. Open the Cloud Details window.
2. Click **Generate Environment** to provision the AWS lab.
3. Wait until the environment state becomes `Ready`.
4. Open the **Credentials** tab.
5. Launch the AWS Console using the provided link.
6. Log in using the supplied credentials.

After logging in, the AWS account name is displayed in the top-right corner of the console.

```text
Account Name: LabRoom
```

This confirms that the lab environment is accessible.

**Key takeaway:** Always verify the active AWS account before performing administrative or security-related operations.

---

# AWS Management Console Overview

The AWS Management Console provides a web-based interface for accessing and managing cloud services.

Several interface components are particularly important when working with AWS.

### Services Search

The service search feature allows users to locate AWS services such as:

* Amazon EC2
* Amazon S3
* AWS Identity and Access Management (IAM)
* AWS CloudShell
* AWS CloudTrail

### Region Selection

AWS resources are distributed across geographical regions. The selected region determines which regional resources are displayed and where many operations are executed.

The default region used by the TryHackMe lab in this exercise is:

```text
us-east-1
```

This corresponds to the US East (N. Virginia) region.

### Account Menu

The account menu provides access to account-related information and identity details.

### CloudShell

CloudShell provides a browser-based terminal for interacting with AWS services without installing the CLI locally.

**Key takeaway:** Understanding the console interface, active account, and selected region helps prevent mistakes when managing cloud resources.

---

# AWS CloudShell

AWS CloudShell is a browser-based command-line environment integrated with the AWS Management Console.

It allows users to execute AWS CLI commands using the credentials available to the active session.

This is useful for quick administrative checks, troubleshooting, resource enumeration, and security investigations.

## Verifying the Current AWS Identity

The first command executed in CloudShell is:

```bash
aws sts get-caller-identity
```

This command queries AWS Security Token Service (STS) to identify the caller making the request.

Example output:

```json
{
    "UserId": "EXAMPLE_USER_ID",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/example-user"
}
```

The response contains three important fields.

| Field | Description |
|---|---|
| `UserId` | Identifier of the calling identity |
| `Account` | AWS account ID |
| `Arn` | Amazon Resource Name identifying the caller |

The command serves a similar purpose to `whoami` on Linux, although it returns additional account and identity information.

## Checking the AWS CLI Configuration

The following command displays the effective CLI configuration:

```bash
aws configure list
```

The output can include:

```text
NAME       : VALUE
profile    : <not set>
access_key : ****************EXAMPLE
secret_key : ****************EXAMPLE
region     : us-east-1
```

CloudShell can obtain credentials from its execution environment, so manually configuring access keys is not necessarily required.

## Checking the Current Region

The current region can be checked using an environment variable:

```bash
echo $AWS_DEFAULT_REGION
```

Example output:

```text
us-east-1
```

Alternatively, AWS CLI can query the region associated with an availability zone:

```bash
aws ec2 describe-availability-zones \
  --output text \
  --query 'AvailabilityZones[0].[RegionName]'
```

**Key takeaway:** CloudShell provides a convenient way to verify identity, inspect configuration, and interact with AWS services directly from the browser.

---

# AWS CLI Installation and Configuration

The AWS Command Line Interface allows users to manage AWS resources from a terminal.

Before using it locally, the installation can be verified with:

```bash
aws --version
```

Example output:

```text
aws-cli/2.x.x Python/3.x.x Linux
```

The exact version depends on the installed environment.

## Configuring AWS CLI

The interactive configuration command is:

```bash
aws configure
```

It prompts for four values:

```text
AWS Access Key ID
AWS Secret Access Key
Default region name
Default output format
```

Example configuration:

```text
Default region name: us-east-1
Default output format: json
```

After configuration, the settings can be verified:

```bash
aws configure list
```

The current identity can then be confirmed:

```bash
aws sts get-caller-identity
```

This helps establish which identity and AWS account the CLI is using.

**Security note:** Never publish real access keys, secret keys, session tokens, or unredacted AWS configuration files in a public GitHub repository. Use temporary credentials or IAM roles where appropriate.

---

# AWS CLI Profiles and Environment Variables

AWS CLI supports multiple configuration methods, allowing users to work with different accounts and environments.

Understanding these methods is important when switching between lab, development, and production accounts.

## AWS Configuration Files

The two main configuration files are:

```text
~/.aws/credentials
~/.aws/config
```

The credentials file stores authentication credentials, while the config file stores settings such as regions and output formats.

Example credentials file:

```ini
[default]
aws_access_key_id = EXAMPLE_ACCESS_KEY
aws_secret_access_key = EXAMPLE_SECRET_KEY

[thm-user]
aws_access_key_id = EXAMPLE_ACCESS_KEY
aws_secret_access_key = EXAMPLE_SECRET_KEY
```

Example config file:

```ini
[default]
region = us-east-1
output = json

[profile thm-user]
region = eu-west-1
output = text
```

These are illustrative examples, not working credentials.

## Using a Named Profile

A named profile can be selected with the `--profile` parameter.

```bash
aws sts get-caller-identity --profile thm-user
```

This allows commands to run using the selected profile's configuration and credentials.

## Using Environment Variables

AWS CLI can also obtain configuration values from environment variables.

```bash
export AWS_DEFAULT_REGION="us-east-1"
```

Authentication-related variables can include:

```bash
export AWS_ACCESS_KEY_ID="EXAMPLE_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="EXAMPLE_SECRET_KEY"
export AWS_SESSION_TOKEN="EXAMPLE_SESSION_TOKEN"
```

Only set credentials that you are authorized to use, and avoid placing real secrets in shell history or public scripts.

## Configuration Precedence

AWS CLI settings can come from command-line options, environment variables, configuration files, and other credential providers.

For example, an explicitly supplied `--region` option overrides the configured default region for that command.

Credential selection and non-credential configuration have separate precedence rules, so the effective settings should be verified when troubleshooting authentication problems.

**Key takeaway:** Profiles help separate AWS environments, while environment variables provide an alternative way to configure command execution.

---

# AWS CLI Command Structure

AWS CLI commands follow a consistent structure:

```bash
aws <service> <operation> [options]
```

The components are:

* **Service:** The AWS service being accessed, such as `ec2`, `s3`, or `iam`.
* **Operation:** The action to perform, such as `describe-regions` or `list-groups`.
* **Options:** Additional parameters controlling the command's behavior.

Common options include:

| Option | Purpose |
|---|---|
| `--region` | Selects the AWS region |
| `--profile` | Selects a named profile |
| `--output` | Specifies the output format |
| `--query` | Filters results using JMESPath |

## Listing AWS Regions

The following command retrieves the available AWS regions:

```bash
aws ec2 describe-regions \
  --query "Regions[].RegionName" \
  --output text
```

This is useful for understanding the geographical scope of AWS resources and selecting the appropriate region for further operations.

## Exploring EC2 Commands

The first available EC2 command identified in the exercise is:

```text
accept-address-transfer
```

To inspect available EC2 operations in your own CLI installation, use:

```bash
aws ec2 help
```

Command availability and ordering can vary by AWS CLI version.

---

# IAM Enumeration

AWS Identity and Access Management (IAM) controls access to AWS resources through users, groups, roles, and policies.

During the exercise, the following command is used to list IAM groups:

```bash
aws iam list-groups
```

Example output:

```json
{
    "Groups": [
        {
            "Path": "/",
            "GroupName": "AWS101",
            "Arn": "arn:aws:iam::123456789012:group/AWS101"
        },
        {
            "Path": "/",
            "GroupName": "LabReadOnly",
            "Arn": "arn:aws:iam::123456789012:group/LabReadOnly"
        }
    ]
}
```

The example illustrates how AWS CLI returns structured information about IAM groups.

Group names and identifiers depend on the lab environment.

## Security Relevance

IAM enumeration can help an authorized security analyst understand:

* Which groups exist in an account.
* How users and roles are organized.
* Whether permissions follow least-privilege principles.
* Whether excessive permissions or risky trust relationships require further review.

Listing groups alone does not reveal all effective permissions. A proper assessment also requires examining attached and inline policies, group memberships, role trust policies, and applicable permission boundaries.

**Key takeaway:** IAM visibility is fundamental to cloud security because excessive permissions can increase the impact of compromised credentials.

---

# S3 Bucket Enumeration

Amazon Simple Storage Service (S3) is an object storage service commonly used for files, application data, backups, logs, and static website content.

The following command lists the S3 buckets accessible to the current identity:

```bash
aws s3 ls
```

Example output from the exercise:

```text
2026-10-08 02:20:44 firststeps-325107200175
```

The bucket name follows this pattern:

```text
firststeps-<ACCOUNT_ID>
```

The prefix identified in the exercise is:

```text
firststeps
```

This illustrates how resource names can contain recognizable prefixes and account-specific identifiers.

However, bucket naming conventions do not establish whether a bucket is public or insecure. Access permissions and bucket configuration must be assessed separately.

**Key takeaway:** S3 enumeration helps identify accessible storage resources and provides a starting point for authorized reviews of bucket policies, public access settings, and data exposure risks.

---

# Practical AWS Command Reference

The following commands summarize the core techniques covered in this room.

| Objective | Command |
|---|---|
| Check AWS CLI version | `aws --version` |
| Identify the active caller | `aws sts get-caller-identity` |
| Inspect CLI configuration | `aws configure list` |
| Configure the default profile | `aws configure` |
| Check the default region | `echo $AWS_DEFAULT_REGION` |
| List AWS regions | `aws ec2 describe-regions` |
| List IAM groups | `aws iam list-groups` |
| List accessible S3 buckets | `aws s3 ls` |
| Use a named profile | `aws sts get-caller-identity --profile thm-user` |
| View EC2 command help | `aws ec2 help` |

---

# Attack and Investigation Flow

Although this room focuses on cloud fundamentals rather than exploitation, the workflow resembles the initial stages of an authorized cloud security assessment.

```text
Provision AWS Lab Environment
            |
            v
Access AWS Management Console
            |
            v
Verify Account and Region
            |
            v
Open AWS CloudShell
            |
            v
Identify Current AWS Identity
            |
            v
Inspect CLI Configuration
            |
            v
Understand Profiles and Credentials
            |
            v
Explore AWS CLI Commands
            |
            v
Enumerate IAM Groups
            |
            v
List Accessible S3 Buckets
            |
            v
Review Cloud Security Implications
```

---

# Security Considerations

The exercises highlight several important considerations when working with AWS environments.

* **Identity verification:** Confirm the active account and caller before executing commands.
* **Credential protection:** Never expose access keys or session tokens in source control.
* **Least privilege:** Grant only the permissions required for each task.
* **Regional awareness:** Check the selected region before querying or modifying resources.
* **IAM review:** Investigate excessive permissions and risky access relationships.
* **S3 security:** Review bucket policies, public access settings, and data access controls.
* **Auditability:** Use appropriate AWS logging and monitoring services to track relevant activity.

These practices are particularly important for SOC analysts and cloud security engineers who monitor suspicious activity, investigate compromised identities, and assess cloud misconfigurations.

---

# Lessons Learned

This room establishes a foundation for working with AWS through both the Management Console and the command line. Using `aws sts get-caller-identity` provides a quick way to confirm the active identity and account, while `aws configure list` helps identify the effective CLI configuration.

The exercises also demonstrate how AWS CLI profiles, regions, and output filtering support efficient cloud administration. Basic IAM and S3 enumeration provides useful context for understanding cloud permissions and accessible resources.

From a security perspective, the most important lessons are to verify identity before performing operations, protect credentials, apply least privilege, and understand which cloud resources are accessible to a given identity. These fundamentals provide a starting point for more advanced AWS security assessments, cloud threat hunting, and incident response.

---

# Skills and Technologies

**Cloud Platform:** Amazon Web Services (AWS)  
**Command-Line Tools:** AWS CLI, AWS CloudShell  
**Identity and Access:** AWS STS, IAM  
**Cloud Services:** EC2, S3  
**Configuration:** AWS profiles, environment variables, regions  
**Security Concepts:** Identity verification, least privilege, credential security, cloud resource enumeration

---

# Challenge Answers

| Question | Answer |
|---|---|
| What is the account name? | `LabRoom` |
| What is the default lab region? | `us-east-1` |
| What fields does `aws sts get-caller-identity` return? | `UserId`, `Account`, `Arn` |
| What is the first available EC2 command in the exercise? | `accept-address-transfer` |
| What is the S3 bucket prefix? | `firststeps` |

---

**Learning Platform:** [TryHackMe](https://tryhackme.com/)  
**Focus:** AWS fundamentals, cloud administration, and foundational cloud security skills.
