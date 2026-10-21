# AWS 2.1. The Over-Privileged User

### Task 1 - Introduction

A developer, named Carl, joined the team and needed access to AWS. An overzealous admin, with little time to spare, gave him full Administrator rights directly.

### Task 2 - Real-World Incident

Code Spaces was a company that provided code hosting and project management services built on AWS. It provided subversion and git hosting for development teams.

**What Happened**

![Attacker escalated and removed all CodeSpaces data.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1781259292038.png)

On June 17, 2014, Code Spaces was hit by a Distributed Denial-of-Service (DDoS) attack. This was not unusual for an internet-facing service, but the DDoS was only the opening move. While the company was focused on mitigating the traffic flood, the attacker had already gained access to the Code Spaces AWS management console, specifically, the EC2 control panel. The attacker left messages inside the console with a Hotmail address, demanding a ransom to stop the attack. When Code Spaces staff realized someone was inside their AWS console, they changed the panel passwords. But the attacker had already created multiple backdoor IAM logins. As soon as the attacker saw recovery attempts, they escalated and began deleting everything.

**The Fallout:** The attacker systematically deleted:

- All EBS snapshots (disk backups).
- All S3 buckets (object storage, including customer data).
- All AMIs (machine images).
- Multiple EC2 instances (running servers).

Within 12 hours, Code Spaces' production environment, backups, machine configurations, and even off-site backups were partially or completely destroyed. The company issued a final notice to customers stating that they could no longer operate and that the company would permanently shut down.

**Core Failure:** The attacker succeeded because the compromised identity had unrestricted administrative access to the entire AWS account. There were no guardrails, no permission boundaries, no explicit deny policies to prevent destructive actions, no MFA requirement for sensitive operations, and no monitoring or alerts for IAM changes.

**Answer the questions below**

> What was the initial type of attack used?
> 

DDoS

> What was the misconfiguration that allowed the compromised identity to have such destructive powers?
> 

Unrestricted administrative access

### Task 3 - Identification

1. Go get started, log in with the provided credentials.

2. List the users from the account.

![Lab account users](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1773742364304.png)

**Note:** To make life easier, you can store the account ID in a variable.

```bash
           $ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

$ echo $ACCOUNT_ID

227184855672
```

```bash
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

3. Check the attached policies for each user. User `carl-the-dev` has a very interesting policy attached.

```bash
           $ aws iam list-attached-user-policies \
    --user-name carl-the-dev

{
    "AttachedPolicies": [
        {
            "PolicyName": "AWS201-DevCarlAdmin",
            "PolicyArn": "arn:aws:iam::227184855672:policy/AWS201-DevCarlAdmin"
        }
    ]
}
```

4. Look at the policy content that is attached to the user Carl.

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

**FINDING:** `"Action": "*"` and `"Resource": "*"` are red flags; the policy grants full unrestricted access to any resource.

**Note:** A short reminder that policies are evaluated as follows: `Explicit Deny -> Explicit Allow -> Implicit Deny`

5. Another good practice when auditing is to check for inline policies as they do not appear in the managed policy list.

**Info:** AWS managed policies are standalone, reusable policies that can be attached to multiple users, groups, or roles. In contrast, inline policies are embedded directly into a single, specific IAM identity, maintaining a strict one-to-one relationship and cannot be shared.

```bash
           $ aws iam list-user-policies \
    --user-name carl-the-dev

{
    "PolicyNames": []
}
```

**FINDING:** In this case, no inline policy.

6. Also, check if the user is part of any groups.

```bash
           $ aws iam list-groups-for-user \
    --user-name carl-the-dev

{
    "Groups": []
}
```

**FINDING:** User is not in any group. This is an issue as direct policy attachment makes permission management at scale hard.

7. You can check the other users as well. `ci-deployer` user is a good example of applied security best practices.

**Findings Summary**

Carl (`carl-the-dev`) could potentially:

- Delete any S3 bucket.
- Terminate any EC2.
- Modify or delete CloudTrail logs.
- Delete EBS snapshots and AMIs.
- Change security groups and network access controls.
- Access any secret in Secrets Manager.

If this user's credentials are compromised in any way, the attacker would have full control, similar to the Code Spaces example.

**Answer the questions below**

> What role does Carl have?
> 

 Developer

~ $ aws iam get-user --user-name carl-the-dev

![image.png](AWS%202%201%20The%20Over-Privileged%20User/image.png)

> What is the name of the group the `ci-deployer` user is part of?
> 

 Deployers

~ $ aws iam list-groups-for-user --user-name ci-deployer

![image.png](AWS%202%201%20The%20Over-Privileged%20User/image%201.png)

### Task 4 - Remediation

Now that you have identified the problem, you can remediate it by having the following approach:

1. Understand the user requirements.
2. Remove the over-permissive policy.
3. Create a scoped policy with only the required permissions.
4. Attach the policy via a group.
5. Verify the remediation.

**Understanding Requirements**

For this lab, Carl has a developer role and needs:

- To be able to read and list S3 objects from the `thm-app-data-` bucket.
- Describe EC2 instances.
- Read CloudWatch Logs for debugging.

Before you proceed, take a moment to reflect on what the user actually needs versus the permissions they currently have.

**Removing Policies**

![Remove a user policy by selecting the policy and clicking remove.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1773743058621.png)

**Note:** The account ID is saved in a local variable from the previous task. Rerun the command from before if needed.

```bash
           $ aws iam detach-user-policy \
    --user-name carl-the-dev \
    --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/AWS201-DevCarlAdmin
```

At this point, the user has zero permissions, so he cannot do anything.

```bash
           $ aws iam list-attached-user-policies \
    --user-name carl-the-dev

{
    "AttachedPolicies": []
}
```

Since there is no policy attached, the evaluation hits an implicit deny.

**Creating Policies**

![AWS policy editor](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1773844840615.png)

In the AWS Console, you can create policies by using the Policy editor and selecting the appropriate services from the right-side menu. You can also edit the policy directly to add statements and customizations.

For this exercise, you will create a policy through CLI.

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

{
    "Policy": {
        "PolicyName": "AppAccess",
        "PolicyId": "ANPAU2BXNLZOIR6YSLCSO",
        "Arn": "arn:aws:iam::227184855672:policy/CarlAppAccess",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 0,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "CreateDate": "2026-03-17T11:53:53+00:00",
        "UpdateDate": "2026-03-17T11:53:53+00:00"
    }
}
```

**Attach Policy Via Group:** Create a group for developers.

```bash
           $ aws iam create-group \
    --group-name Developers

{
    "Group": {
        "Path": "/",
        "GroupName": "Developers",
        "GroupId": "AGPATJZKFZJ4MP6ST5AUO",
        "Arn": "arn:aws:iam::227184855672:group/Developers",
        "CreateDate": "2026-03-17T10:35:18+00:00"
    }
}
```

Attach the scoped policy to the group.

```bash
           $ aws iam attach-group-policy \
  --group-name Developers \
  --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/AppAccess"
```

Add the user `carl-the-dev` to the group.

```bash
           $ aws iam add-user-to-group \
    --group-name Developers \
    --user-name carl-the-dev
```

**Verify:** Verify group membership as you did before.

```bash
           $ aws iam list-groups-for-user \
    --user-name carl-the-dev

{
    "Groups": [
        {
            "Path": "/",
            "GroupName": "Developers",
            "GroupId": "AGPATJZKFZJ4MP6ST5AUO",
            "Arn": "arn:aws:iam::227184855672:group/Developers",
            "CreateDate": "2026-03-17T10:35:18+00:00"
        }
    ]
}
```

Verify group policies.

```bash
           $ aws iam list-attached-group-policies \
    --group-name Developers
{
    "AttachedPolicies": [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::227184855672:policy/AppAccess"
        }
    ]
}
```

First, you save the attached policy in a local variable.

```bash
           $ POLICY_DOC=$(aws iam get-policy-version \
    --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/AppAccess" \
    --version-id v1 \
    --query 'PolicyVersion.Document' --output json)
```

Then you simulate the policy against the required actions.

```bash
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

Good work. Who said scoping down wasn't easy?

**Answer the questions below**

> In the policy that you attached to the Developers group, what actions are allowed for the S3 service (list alphabetically without the s3: prefix)?
> 

 GetObject,ListBucket

> If you run the policy simulation again but use the action name "s3:DeleteBucket", what is the result?
> 

 implicitDeny

### Task 5 - Build It Securely

Now, let us see how you can build it in a secure way by following these three principles:

- Group-based permission model.
- Least-privilege policies.
- Permission boundaries guardrails.

**Group-Based Permission Model:** Manage permissions at scale by defining company roles through groups and assigning users to them. Create a department-specific group.

```bash
           $ aws iam create-group --group-name Accounting

{
    "Group": {
        "Path": "/",
        "GroupName": "Accounting",
        "GroupId": "AGPATJZKFZJ4BMVOS2TPL",
        "Arn": "arn:aws:iam::227184855672:group/Accounting",
        "CreateDate": "2026-03-17T10:52:50+00:00"
    }
}
```

**Least-Privilege Policies:** As covered in the introductory IAM room, this principle is at the core of security. It simply states that you must be specific about which actions are allowed on which resources.

The users from the Accounting department need read/write access to the `thm-app-data-` S3 bucket, so that is what you will provide them.

```bash
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

{
    "Policy": {
        "PolicyName": "AccountingPolicy",
        "PolicyId": "ANPAU2BXNLZOOGCCSPW2F",
        "Arn": "arn:aws:iam::227184855672:policy/AccountingPolicy",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 0,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "CreateDate": "2026-03-17T12:03:52+00:00",
        "UpdateDate": "2026-03-17T12:03:52+00:00"
    }
}
```

And attach it to the group.

```bash
           $ aws iam attach-group-policy \
  --group-name Accounting \
  --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/AccountingPolicy"
```

Now, every time a new person joins the Accounting department, and a user is created, you can just add the user to the `Accounting` group. Similarly, if someone needs their access revoked, you can just remove them from the group.

**Permission Boundaries Guardrails:** A permission boundary is an IAM policy that sets the maximum permissions an identity can have, superseding other more permissive policies.

This is an additional safeguard for key users and roles. Let's see this in action. Create a permission boundary.

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

{
    "Policy": {
        "PolicyName": "CarlBoundary",
        "PolicyId": "ANPAU2BXNLZONCQSYI2NM",
        "Arn": "arn:aws:iam::227184855672:policy/CarlBoundary",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 0,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "CreateDate": "2026-03-17T12:05:46+00:00",
        "UpdateDate": "2026-03-17T12:05:46+00:00"
    }
}
```

Apply the boundary to the user.

```bash
           $ aws iam put-user-permissions-boundary \
    --user-name carl-the-dev \
    --permissions-boundary "arn:aws:iam::${ACCOUNT_ID}:policy/CarlBoundary"
```

**Verification**

![Permission boundary on a user](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1773845458850.png)

Run the command to see the permission boundary attached to a user.

```bash
           $ aws iam get-user \
    --user-name carl-the-dev \
    --query "User.PermissionsBoundary"
{
    "PermissionsBoundaryType": "Policy",
    "PermissionsBoundaryArn": "arn:aws:iam::227184855672:policy/CarlBoundary"
}
```

**Answer the questions below**

> What mechanism allows you to set the maximum permissions for an identity even if it has more permissive policies attached?
> 

Permission Boundaries

### Task 6 - Conclusion

You went through the full lifecycle of an IAM over-privilege misconfiguration: from understanding why to identifying and remediating it. **Key Takeaways**

- Never grant persistent administrative access to human users.
- Use groups instead of direct policy attachment.
- Apply permission boundaries as guardrails.
- Audit policies regularly.
- Learn from real-world incidents the dangers, but also the remediations for common misconfigurations.
