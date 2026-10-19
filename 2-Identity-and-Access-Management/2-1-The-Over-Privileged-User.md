# AWS IAM Security & Remediation: Preventing Over-Privileged Access

This repository contains lab notes, commands, and findings from an AWS Identity and Access Management (IAM) security exercise. The lab explores the risks of over-privileged access, analyzes a real-world disaster, and demonstrates how to audit, remediate, and secure an AWS environment using least-privilege principles and permission boundaries.

---

## Task 1: Introduction
A developer named Carl joined the team and required AWS access. Due to time constraints, an administrator granted him full `AdministratorAccess` directly to his user account. This lab explores the dangers of such shortcuts and how to remediate them.

---

## Task 2: Real-World Incident — The Code Spaces Story
* **What Happened:** On June 17, 2014, Code Spaces (a code hosting and project management service built on AWS) was targeted by a DDoS attack as a diversion. While the team mitigated the traffic flood, an attacker gained access to the AWS management console (EC2 control panel) and demanded a ransom. When staff attempted to secure the account by changing passwords, the attacker—who had already created backdoor IAM logins—escalated and systematically destroyed the environment.
* **The Fallout:** Within 12 hours, the attacker deleted:
  * All EBS snapshots (disk backups)
  * All S3 buckets (object storage, including customer data)
  * All AMIs (machine images)
  * Multiple EC2 instances
  * Off-site backups
  
  *Result:* Code Spaces permanently shut down.
* **Core Failure:** The compromised identity possessed unrestricted administrative access with **no guardrails**, **no permission boundaries**, **no explicit deny policies**, **no MFA requirements**, and **no monitoring for IAM changes**.

> **Key Questions & Answers:**
> * **What was the initial type of attack used?** DDoS
> * **What was the misconfiguration that allowed the compromised identity to have such destructive powers?** Unrestricted administrative access

---

## Task 3: Identification & Auditing
The first step in securing an environment is auditing existing identities and their permissions.

### 1. Listing Users
```bash
# Store the account ID in a variable for convenience
$ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
$ echo $ACCOUNT_ID
227184855672

# List IAM users
$ aws iam list-users \
    --query "Users[*].[UserName,CreateDate]" \
    --output table

-----------------------------------------------
|                  ListUsers                  |
+---------------+-----------------------------+
|  227184855672 |  2026-03-16T15:32:51+00:00  |
|  carl-the-dev |  2026-03-17T07:03:30+00:00  |
|  ci-deployer  |  2026-03-17T07:03:30+00:00  |
+---------------+-----------------------------+
```

### 2. Checking Attached Policies
Checking policies attached to `carl-the-dev` revealed an over-permissive custom policy:
```bash
$ aws iam list-attached-user-policies --user-name carl-the-dev

{
    "AttachedPolicies": [
        {
            "PolicyName": "AWS201-DevCarlAdmin",
            "PolicyArn": "arn:aws:iam::227184855672:policy/AWS201-DevCarlAdmin"
        }
    ]
}
```

Inspecting the policy content:
```bash
$ aws iam get-policy-version \
    --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/AWS201-DevCarlAdmin \
    --version-id v1

{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "*",
                    "Resource": "*",
                    "Effect": "Allow",
                    "Sid": "OverPrivilegedAccess"
                }
            ]
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2026-03-17T07:04:08+00:00"
    }
}
```
> 🚩 **FINDING:** `"Action": "*"` and `"Resource": "*"` grant full unrestricted access to any resource in the account.

### 3. Checking Inline Policies and Groups
```bash
# Check inline policies (embedded directly into the identity)
$ aws iam list-user-policies --user-name carl-the-dev
{
    "PolicyNames": []
}

# Check group memberships
$ aws iam list-groups-for-user --user-name carl-the-dev
{
    "Groups": []
}
```
> 🚩 **FINDING:** Carl had no inline policies and belonged to **no groups**, violating security best practices by using direct policy attachments.

### Findings Summary (Carl's Capabilities)
If compromised, an attacker could:
* Delete any S3 bucket, EBS snapshot, or AMI.
* Terminate any EC2 instance.
* Modify or delete CloudTrail logs.
* Change security groups and network access controls.
* Access any secret in AWS Secrets Manager.

> **Key Questions & Answers:**
> * **What role does Carl have?** Developer
> * **What is the name of the group the ci-deployer user is part of?** Deployers

---

## Task 4: Remediation
To resolve the security risk, we follow a structured remediation approach:
1. Understand user requirements.
2. Remove the over-permissive policy.
3. Create a scoped policy with least-privilege permissions.
4. Attach the policy via a group.
5. Verify the remediation.

### Step 1: Detach the Over-Permissive Policy
```bash
$ aws iam detach-user-policy \
    --user-name carl-the-dev \
    --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/AWS201-DevCarlAdmin

$ aws iam list-attached-user-policies --user-name carl-the-dev
{
    "AttachedPolicies": []
}
```
*(At this stage, Carl has zero permissions, resulting in an implicit deny).*

### Step 2: Create a Scoped Policy
Carl only needs:
* Read/list access to `thm-app-data-` S3 bucket.
* EC2 describe permissions.
* Read-only access to specific CloudWatch logs.

```bash
$ aws iam create-policy \
      --policy-name AppAccess \
      --policy-document '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S3AppBucketReadOnly",
               "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:ListBucket"
                ],
                "Resource": [
                    "arn:aws:s3:::thm-app-data-'"$ACCOUNT_ID"'",
                    "arn:aws:s3:::thm-app-data-'"$ACCOUNT_ID"'/*"
                ]
            },
            {
                "Sid": "EC2DescribeOnly",
                "Effect": "Allow",
                "Action": [
                    "ec2:DescribeInstances",
                    "ec2:DescribeSecurityGroups",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeVpcs"
                ],
                "Resource": "*"
            },
            {
                "Sid": "CloudWatchLogsReadOnly",
                "Effect": "Allow",
                "Action": [
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams",
                    "logs:GetLogEvents",
                    "logs:FilterLogEvents"
                ],
                "Resource": "arn:aws:logs:us-east-1:'"$ACCOUNT_ID"':log-group:/aws/app/*"
            }
      ]
  }'
```

### Step 3: Attach Policy via Group
```bash
# Create the Developers group
$ aws iam create-group --group-name Developers

# Attach the scoped policy to the group
$ aws iam attach-group-policy \
  --group-name Developers \
  --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/AppAccess"

# Add Carl to the group
$ aws iam add-user-to-group \
    --group-name Developers \
    --user-name carl-the-dev
```

### Step 4: Verify Policy Simulation
```bash
# Store attached policy document in a variable
$ POLICY_DOC=$(aws iam get-policy-version \
    --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/AppAccess" \
    --version-id v1 \
    --query 'PolicyVersion.Document' --output json)

# Run policy simulation
$ aws iam simulate-custom-policy \
    --policy-input-list "$POLICY_DOC" \
    --action-names "s3:ListBucket" "s3:GetObject" \
    --resource-arns "arn:aws:s3:::thm-app-data-${ACCOUNT_ID}" \
    --query "EvaluationResults[*].[EvalActionName,EvalDecision]" \
    --output table

------------------------------
|    SimulateCustomPolicy    |
+----------------+-----------+
|  s3:ListBucket |  allowed  |
|  s3:GetObject  |  allowed  |
+----------------+-----------+
```

> **Key Questions & Answers:**
> * **In the policy that you attached to the Developers group, what actions are allowed for the S3 service (list alphabetically without the s3: prefix)?** GetObject,ListBucket
> * **If you run the policy simulation again but use the action name "s3:DeleteBucket", what is the result?** implicitDeny

---

## Task 5: Building Securely

To maintain a secure AWS environment moving forward, adhere to three core principles:
1. **Group-Based Permission Model:** Manage access at scale through groups rather than individual user attachments.
2. **Least-Privilege Policies:** Explicitly define permitted actions and resources.
3. **Permission Boundaries:** Set maximum limits on an identity's permissions as an extra safety guardrail.

### Example 1: Creating an Accounting Group
```bash
$ aws iam create-group --group-name Accounting

$ aws iam create-policy \
  --policy-name AccountingPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "S3AppAccess",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::thm-app-data-'"$ACCOUNT_ID"'",
                "arn:aws:s3:::thm-app-data-'"$ACCOUNT_ID"'/*"
            ]
        }
    ]
}'

$ aws iam attach-group-policy \
  --group-name Accounting \
  --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/AccountingPolicy"
```

### Example 2: Applying Permission Boundary Guardrails
A permission boundary is an IAM policy that sets the maximum permissions an identity can have, superseding other more permissive policies.

```bash
$ aws iam create-policy \
    --policy-name CarlBoundary \
    --policy-document '{
      "Version": "2012-10-17",
      "Statement": [
          {
              "Sid": "DenyCarlActions",
              "Effect": "Deny",
              "Action": [
                  "s3:GetObject",
                  "s3:PutObject",
                  "s3:ListBucket",
                  "s3:DeleteBucket",
                  "s3:ListAllMyBuckets"
              ],
              "Resource": "*"
          }
      ]
  }'

# Apply boundary to user
$ aws iam put-user-permissions-boundary \
    --user-name carl-the-dev \
    --permissions-boundary "arn:aws:iam::${ACCOUNT_ID}:policy/CarlBoundary"

# Verify attached boundary
$ aws iam get-user \
    --user-name carl-the-dev \
    --query "User.PermissionsBoundary"
```

> **Key Questions & Answers:**
> * **What mechanism allows you to set the maximum permissions for an identity even if it has more permissive policies attached?** Permission Boundaries

---

## Task 6: Conclusion & Key Takeaways
* **Never grant persistent administrative access** to human users.
* **Use groups** instead of direct policy attachments to manage permissions at scale.
* **Apply permission boundaries** as guardrails for key users and roles.
* **Audit policies regularly** to catch over-privileged access.
* **Learn from real-world incidents** like Code Spaces to prevent catastrophic misconfigurations.
