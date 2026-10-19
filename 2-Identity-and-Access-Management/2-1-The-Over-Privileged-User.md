AWS IAM Security & Remediation: Preventing Over-Privileged Access
This repository contains my lab notes, commands, and findings from an AWS Identity and Access Management (IAM) security exercise. The lab explores the risks of over-privileged access, analyzes a real-world disaster, and demonstrates how to audit, remediate, and secure an AWS environment using least-privilege principles and permission boundaries.

Task 1: Introduction
A developer named Carl joined the team and required AWS access. Due to time constraints, an overzealous administrator granted him full AdministratorAccess directly to his user account. This lab explores the dangers of such shortcuts and how to fix them.

Task 2: Real-World Incident — The Code Spaces Story
What Happened: On June 17, 2014, Code Spaces (a code hosting and project management service built on AWS) was targeted by a DDoS attack as a diversion. While the team mitigated the traffic flood, an attacker gained access to the AWS management console (EC2 control panel) and demanded a ransom. When staff attempted to secure the account by changing passwords, the attacker—who had already created backdoor IAM logins—escalated and systematically destroyed the environment.

The Fallout: Within 12 hours, the attacker deleted:

All EBS snapshots (disk backups)

All S3 buckets (object storage, including customer data)

All AMIs (machine images)

Multiple EC2 instances

Off-site backups

Result: Code Spaces permanently shut down.

Core Failure: The compromised identity possessed unrestricted administrative access with no guardrails, no permission boundaries, no explicit deny policies, no MFA requirements, and no monitoring for IAM changes.

Key Questions & Answers:

What was the initial type of attack used? DDoS (used as a smokescreen)

What was the misconfiguration? Unrestricted administrative access

Task 3: Identification & Auditing
The first step in securing an environment is auditing existing identities and their permissions.

1. Listing Users
Bash
# Store the account ID in a variable for convenience
$ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
$ echo $ACCOUNT_ID

# List IAM users
$ aws iam list-users --query "Users[*].[UserName,CreateDate]" --output table
2. Checking Attached Policies
Checking policies attached to carl-the-dev revealed an over-permissive custom policy:

Bash
$ aws iam list-attached-user-policies --user-name carl-the-dev
JSON
{
    "AttachedPolicies": [
        {
            "PolicyName": "AWS201-DevCarlAdmin",
            "PolicyArn": "arn:aws:iam::227184855672:policy/AWS201-DevCarlAdmin"
        }
    ]
}
Inspecting the policy content:

Bash
$ aws iam get-policy-version \
    --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/AWS201-DevCarlAdmin \
    --version-id v1
JSON
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
        }
    }
}
🚩 FINDING: "Action": "*" and "Resource": "*" grant full unrestricted access to any resource in the account.

3. Checking Inline Policies and Groups
Bash
# Check inline policies (embedded directly into the identity)
$ aws iam list-user-policies --user-name carl-the-dev

# Check group memberships
$ aws iam list-groups-for-user --user-name carl-the-dev
🚩 FINDING: Carl had no inline policies and belonged to no groups, violating security best practices by using direct policy attachments.

Findings Summary (Carl's Capabilities)
If compromised, an attacker could:

Delete any S3 bucket or EBS snapshots/AMIs.

Terminate any EC2 instance.

Modify or delete CloudTrail logs.

Change security groups and network access controls.

Access any secret in AWS Secrets Manager.

Key Questions & Answers:

What role does Carl have? Developer

What is the name of the group the ci-deployer user is part of? Deployers

Task 4: Remediation
To resolve the security risk, we follow a structured remediation approach:

Understand user requirements.

Remove the over-permissive policy.

Create a scoped policy with least-privilege permissions.

Attach the policy via a group.

Verify the remediation.

Step 1: Detach the Over-Permissive Policy
Bash
$ aws iam detach-user-policy \
    --user-name carl-the-dev \
    --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/AWS201-DevCarlAdmin
(At this stage, Carl has zero permissions, resulting in an implicit deny).

Step 2: Create a Scoped Policy
Carl only needs:

Read/list access to thm-app-data- S3 bucket.

EC2 describe permissions.

Read-only access to specific CloudWatch logs.

Bash
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
Step 3: Attach Policy via Group
Bash
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
Step 4: Verify Policy Simulation
Bash
$ POLICY_DOC=$(aws iam get-policy-version \
    --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/AppAccess" \
    --version-id v1 \
    --query 'PolicyVersion.Document' --output json)

$ aws iam simulate-custom-policy \
    --policy-input-list "$POLICY_DOC" \
    --action-names "s3:ListBucket" "s3:GetObject" \
    --resource-arns "arn:aws:s3:::thm-app-data-${ACCOUNT_ID}" \
    --query "EvaluationResults[*].[EvalActionName,EvalDecision]" \
    --output table
Key Questions & Answers:

What actions are allowed for the S3 service (list alphabetically without prefix)? GetObject, ListBucket

If you simulate with s3:DeleteBucket, what is the result? implicitDeny

Task 5: Building Securely (Best Practices)
To maintain a secure AWS environment moving forward, adhere to three core principles:

Group-Based Permission Model: Manage access at scale through groups rather than individual user attachments.

Least-Privilege Policies: Explicitly define permitted actions and resources.

Permission Boundaries: Set maximum limits on an identity's permissions as an extra safety guardrail.

Example: Applying a Permission Boundary Guardrail
Create a boundary policy to explicitly deny destructive actions on sensitive resources, then attach it to the user:

Bash
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

$ aws iam put-user-permissions-boundary \
    --user-name carl-the-dev \
    --permissions-boundary "arn:aws:iam::${ACCOUNT_ID}:policy/CarlBoundary"
Key Questions & Answers:

What mechanism allows you to set the maximum permissions for an identity even if it has more permissive policies attached? Permission Boundaries

Task 6: Conclusion & Key Takeaways
Never grant persistent administrative access to human users.

Use IAM groups instead of direct user policy attachments for scalable access management.

Apply permission boundaries as robust guardrails.

Audit IAM policies regularly.

Learn from real-world incidents to anticipate and prevent common misconfigurations.
