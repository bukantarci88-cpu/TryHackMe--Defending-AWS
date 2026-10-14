# TryHackMe - AWS IAM Writeup

> **Platform:** TryHackMe  
> **Room:** AWS IAM  
> **Repository:** Defending AWS  
> **Category:** AWS Security | IAM | Identity Management | Access Control | Least Privilege

---

## Overview

Identity and Access Management (IAM) is a core part of AWS security. It controls who can access AWS resources, which actions they can perform, and under what conditions access is allowed.

This write-up covers IAM identities, policy types and structure, policy evaluation, credential security, and the Principle of Least Privilege (PoLP). It also records the practical exercises and answers from the room.

## Learning Objectives

- Understand AWS IAM identities and when to use them.
- Recognize common IAM policy types and how permissions are evaluated.
- Read the structure of a JSON IAM policy.
- Identify common AWS credential types and protect them.
- Apply the Principle of Least Privilege.

---

## Task 1 - Introduction

Security starts and ends with Identity and Access Management. AWS is no different: IAM provides the foundational concepts for controlling access to AWS resources.

## Task 2 - IAM Identities

AWS identities are entities within IAM that are authenticated to access resources based on their assigned permissions.

### Identity Types

| Identity | Description |
|---|---|
| **Root user** | The identity created with an AWS account. It has full access to all resources. |
| **IAM user** | A person or application identity that can have long-term credentials, such as a password or access keys. |
| **IAM group** | A collection of IAM users used to manage permissions for multiple users more easily. |
| **IAM role** | An identity that provides temporary credentials and a flexible way to grant access without relying on permanent credentials. |

### Security Best Practices

- Do not use the root user for everyday activities. Protect it with MFA and a strong password.
- For human users, prefer federated authentication such as single sign-on (SSO) where possible.
- Use groups to manage permissions for users consistently.
- Use IAM roles for AWS services such as EC2 and Lambda.
- Review identities and their assigned permissions regularly.

### Practical Exercise: Explore IAM

In the lab, generate the environment, sign in to the AWS Console using the provided credentials, and open **IAM**. Explore **Users**, **Groups**, **Roles**, and **Policies**.

You can inspect a user's ARN, permissions, group membership, MFA configuration, and access keys by selecting the user in **IAM → Users**.

The AWS CLI can also be used to list identities. Run commands from CloudShell or a configured AWS CLI profile, ensuring you are using the correct account and region.

```bash
# List IAM users
aws iam list-users

# List IAM groups
aws iam list-groups
```

### Room Answer

**Question:** What are the names of the groups the provided user belongs to, listed alphabetically?

**Answer:** `AWS103`, `LabReadOnly`

---

## Task 3 - Understanding Policies

IAM policies are JSON documents that define permissions. They specify which actions are allowed or denied, which resources the rules apply to, and any conditions that must be met.

### Policy Types

| Policy type | Purpose |
|---|---|
| **Identity-based policy** | The most common policy type; attached to IAM users, groups, or roles. |
| **Resource-based policy** | Attached to a resource, such as an S3 bucket policy. |
| **Permissions boundary** | Defines the maximum permissions that an identity-based policy can grant to a user or role. |
| **Service control policy (SCP)** | AWS Organizations guardrail that sets permissions limits for accounts, organizational units (OUs), or an organization. |
| **Session policy** | Limits permissions for a specific session, such as a programmatic role-assumption session. |

### Request Context: PARC

Before evaluating an access request, AWS gathers contextual information remembered by the mnemonic **PARC**:

- **P — Principal:** Who is making the request?
- **A — Action:** What operation is being requested?
- **R — Resource:** Which resource is being accessed?
- **C — Condition:** What contextual conditions apply?

### Permission Evaluation Concepts

- **Explicit deny:** An explicit deny overrides an allow.
- **Permissions boundaries:** These constrain the maximum permissions available to an identity.
- **Allow:** An action must be allowed by the applicable permissions and not blocked by a restriction.
- **Default deny:** If no applicable policy explicitly allows an action, access is denied by default.

### Security Best Practices

- Prefer IAM roles for applications and AWS services.
- Avoid overly broad, catch-all policies.
- Use explicit deny statements for important guardrails where appropriate.
- Grant regular users only the access needed for their daily tasks; use controlled role elevation for additional access, ideally with MFA.
- Assign workloads dedicated roles with service-specific permissions.
- Review policies regularly.

### Room Answers

**Question:** Which policy type is the most common?

**Answer:** `Identity-based`

**Question:** What contextual information does AWS gather before evaluating a request, in mnemonic order?

**Answer:** `Principal, Action, Resource, Condition`

**Question:** Name one security best practice for a regular user.

**Answer:** `MFA`

---

## Task 4 - Policy Structure

An IAM policy is a JSON document. Its main components define the policy language version and one or more statements describing access permissions.

### Main Components

| Component | Description |
|---|---|
| `Version` | Specifies the policy language version. The notes use `2012-10-17`. |
| `Statement` | The main required section containing one or more policy statements. |
| `Sid` | Optional statement identifier or short description. |
| `Effect` | Required; specifies `Allow` or `Deny` (case-sensitive). |
| `Principal` | Specifies the account, user, role, or other principal to which a statement applies when required by the policy type. |
| `Action` | The AWS API actions covered by the statement. |
| `Resource` | The resource or resources covered by the statement. |
| `Condition` | Optional conditions that determine when the statement applies. |

### Example 1: S3 Access

The room provides the following example policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "trylabS3Access",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions",
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::thm-bucket/*"
      ],
      "Condition": {
        "ArnLike": {
          "aws:PrincipalArn": "arn:aws:iam::111122223333:user/trylab"
        }
      }
    }
  ]
}
```

**Narrative:** This statement allows the principal matching the `trylab` user ARN to perform the listed S3 actions when the condition matches. The actions include listing a bucket and its versions, retrieving objects, and uploading objects. The resource in the supplied example is `arn:aws:s3:::thm-bucket/*`.

### Example 2: EC2 Termination Guardrail

The second example contains two statements:

- A `Deny` statement for `ec2:TerminateInstances` on all resources when the principal ARN does **not** match the `try-terminate-me` user.
- An `Allow` statement for `ec2:TerminateInstances` on all resources when the principal ARN matches the `try-terminate-me` user.

**Narrative:** The policy denies EC2 instance termination for principals other than `try-terminate-me`. The matching user is allowed by the second statement and is not matched by the first statement's deny condition.

### Policy-Writing Best Practices

- Specify exact API actions, such as `s3:ListBucket`, instead of broad patterns such as `s3:*`.
- Scope permissions to exact resources using ARNs wherever supported.
- Separate statements by resource type and required permissions.
- Use `Sid` values to make statements easier to understand.
- Use conditions to restrict access, for example with `aws:MultiFactorAuthPresent`, `aws:SourceIp`, or `aws:RequestedRegion`.
- Use explicit deny statements as guardrails for actions that must not occur.

### Room Answers

**Question:** In the first example, which action lets the `trylab` user retrieve objects from `thm-bucket`?

**Answer:** `s3:GetObject`

**Question:** In the second example, what is the result when `try-terminate-me` requests EC2 termination?

**Answer:** `Allow`

---

## Task 5 - Credentials

AWS credentials are used to authenticate an identity or provide access to AWS services.

### Common Credential Types

| Credential type | Description |
|---|---|
| **Console password** | A user-defined password used by the root user or an IAM user to access the AWS Management Console. |
| **Access keys** | Long-term credentials used for programmatic access. |
| **Temporary credentials** | Short-lived credentials issued through AWS Security Token Service (STS), which can provide limited permissions. |
| **Role credentials** | Temporary credentials commonly used by AWS compute services to access resources without storing long-term credentials on disk. |

### Practical Exercise: Create a User

In the lab:

1. Open **IAM → Users → Create user**.
2. Enter a username, such as `trylogme`, and configure console access as directed by the exercise.
3. Add the user to the `LogsReaders` group.
4. Review and create the user.
5. Retrieve the generated credentials when prompted. The lab notes indicate that they are shown only at that stage.
6. Open an incognito browser window and sign in as the new user using the account ID, username, and password.
7. Ensure the AWS region is set to `us-east-1`, then explore the resources available to the user.

### Credential Security Best Practices

- Do not create access keys for human users unless there is a clear requirement and the risks are understood.
- Prefer IAM roles and temporary STS credentials where possible.
- Rotate or remove long-lived access keys.
- Require MFA for sensitive operations.
- Protect credentials and never commit them to a public repository.

### Room Answers

**Question:** What is the prefix of the bucket found in the exercise?

**Answer:** `try-log-me`

**Question:** What flag is found inside the bucket?

**Answer:** `THM{MY_SECRET_STASH}`

---

## Task 6 - The Principle of Least Privilege

The **Principle of Least Privilege (PoLP)** means granting only the minimum permissions needed, for the minimum set of resources, for the minimum period of time.

### Practical Approaches

- Understand the user's or service's actual requirements. A broad request for administrator access may be reducible to a small set of specific actions on defined resources.
- Start with narrow action/resource combinations and expand only when a legitimate requirement is identified.
- Avoid wildcards unless their impact is fully understood; narrow permissions wherever possible.
- Use conditions to further restrict sensitive actions, such as requiring MFA.

### Practical Exercise

The room presents three examples. For each one, select the option that adheres to the Principle of Least Privilege. After all three examples are completed successfully, the lab provides a flag.

### Room Answer

**Question:** What flag is provided after completing all three exercises?

**Answer:** `THM{POLP_IT_DOWN}`

---

## Task 7 - Conclusion

This room introduces the core components of AWS IAM and the foundations of secure policy design.

### Key Takeaways

- IAM policies are a cornerstone of AWS security and should be designed carefully.
- Applying least privilege helps reduce the impact of common misconfigurations and attack patterns.
- When designing or troubleshooting permissions, consider **who** is requesting access, **what** action is requested, **which** resource is involved, and **under what conditions**.
- Credentials provide access to AWS resources and must be protected. Enforce MFA for sensitive operations.
- Avoid granting broad permissions with the intention of tightening them later.
- Prefer roles and temporary credentials for workloads, and regularly review permissions and long-lived credentials.

---

## Skills Practiced

- AWS IAM identity and group enumeration
- IAM policy types and JSON structure
- Access-policy reasoning and permission evaluation
- AWS CLI basics
- Credential-management security
- Least-privilege policy design

> **Lab note:** The commands, examples, group names, bucket prefix, and flags above reflect the room notes. Use credentials only in the authorized lab environment, and never publish real account credentials or access keys.
