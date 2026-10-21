# AWS Security 2.3. The Overpowered Role

### Task 1 - Introduction

An application runs on an EC2 instance. It has the basic requirements to read from a specific S3 bucket, but "someone" created an IAM role with S3 full access and wildcards in the policy. The application works, so nobody complained or revisited the permissions.

### Task 2 - Real-World Incident

Capital One is one of the largest banks in the United States. Like many companies, Capital One migrated to the cloud and ran applications, including a web application firewall (WAF), on EC2 instances. The EC2 instance role was never scoped down from broad access to S3 buckets holding customer application data.

![The phases of the attack explained: Initial access, privilege inventory, data exfiltration, fallout.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1781259399582.png)

The security incident attack chain was:

1. **Initial Access** - The attacker sent a crafted HTTP request to the WAF, exploiting an SSRF vulnerability to make arbitrary HTTP requests on internal addresses on behalf of the attacker.
2. **Credential Theft** - The attacker targeted the IMDS endpoint, and since the instance was running IMDSv1, there was no authentication required, and the response returned the role name. A second request using the identified role provided role credentials.
3. **Privilege Inventory** - With the temporary credentials, the attacker listed all buckets and identified the ones storing sensitive information.
4. **Exfiltration** - The attacker then used the S3 sync command to download sensitive information from the buckets, including names, dates of birth, Social Security numbers, credit scores, and bank accounts for over 100 million individuals.
5. **Discovery** - The breach was not detected by Capital One's own monitoring. It was discovered by an external security researcher who identified publicly posted data. The FBI was notified, and the attacker was identified through metadata in the exfiltrated files.

**Core Failures**

- **Over-privileged instance role** - The WAF role had broad S3 permissions.
- **IMDSv1 enabled** This is an insecure configuration because it returns role credentials in response to simple HTTP GET requests. Any well-crafted SSRF would be able to retrieve credentials unauthenticated.
- **No access control** - Per-bucket access control to limit requests to come from within the VPC, through VPC endpoints, would have prevented the stolen credentials from being used externally.

**Answer the questions below**

> What is one of the misconfigurations that led to the data breach and is the main theme of this room?
> 

over-privileged instance role

### Task 3 - Identification

First things first, save the account ID, as you will need it later. It is always convenient to save IDs and required details in environment variables.

```bash
$ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
```

**Find the EC2 Instance**

![Showing the THM lab instance](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1774370203753.png)

List all instances in the account and save the instance ID.

```bash
$ aws ec2 describe-instances \
    --filters "Name=instance-state-name,Values=running" \
    --query "Reservations[*].Instances[*].{ID:InstanceId,Name:Tags[?Key=='Name'],State:State.Name}" \
    --output table

------------------------------------
|         DescribeInstances        |
+----------------------+-----------+
|          ID          |   State   |
+----------------------+-----------+
|  i-0a91fac348b8b44e1 |  running  |
+----------------------+-----------+
|              Name              |
+---------+----------------------+
|   Key   |        Value         |
+---------+----------------------+
|  Name   |  webapp-server       |
+---------+----------------------+
```

**Check Instance Role:** First, grab the IAM instance profile details.

```bash
$ INSTANCE_ID=$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=webapp-server" "Name=instance-state-name,Values=running" \
    --query "Reservations[0].Instances[0].InstanceId" \
    --output text)

$ PROFILE_ARN=$(aws ec2 describe-instances \
    --instance-ids $INSTANCE_ID \
    --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" \
    --output text)
$ PROFILE_NAME=$(echo $PROFILE_ARN | awk -F'/' '{print $NF}')

$ ROLE_NAME=$(aws iam get-instance-profile \
    --instance-profile-name $PROFILE_NAME \
    --query "InstanceProfile.Roles[0].RoleName" \
    --output text)

$ echo "Role Name: $ROLE_NAME"

Role Name: WebAppOverPrivRole-304038454789$ echo "Instance Profile: $PROFILE_NAME"

Instance Profile: WebAppOverPrivProfile-304038454789
```

**Review Permissions:** First, let us look at the role policies.

![Showing the IAM role attached to the instance](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1774370203894.png)

```bash
$ aws iam list-attached-role-policies \
    --role-name $ROLE_NAME \
    --output json

{
    "AttachedPolicies": [
        {
            "PolicyName": "[REDACTED]",
            "PolicyArn": "arn:aws:iam::aws:policy/[REDACTED]"
        },
        {
            "PolicyName": "WebAppOverPrivS3Policy-304038454789",
            "PolicyArn": "arn:aws:iam::304038454789:policy/WebAppOverPrivS3Policy-304038454789"
        }
    ]
}
```

It is a good practice to also check the inline policies.

```bash
$ aws iam list-role-policies \
    --role-name $ROLE_NAME \
    --output table

------------------
|ListRolePolicies|
+----------------+
```

From the outputs, you can see that a managed policy needs further investigation.

```bash
$ POLICY_ARN=$(aws iam list-attached-role-policies \
    --role-name $ROLE_NAME \
    --query "AttachedPolicies[?contains(PolicyName,'OverPriv')].PolicyArn" \
    --output text)

$ POLICY_VERSION=$(aws iam get-policy \
    --policy-arn $POLICY_ARN \
    --query "Policy.DefaultVersionId" \
    --output text)

$ aws iam get-policy-version \
    --policy-arn $POLICY_ARN \
    --version-id $POLICY_VERSION \
    --query "PolicyVersion.Document" \
    --output json

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:*"
            ],
            "Resource": "*",
            "Effect": "Allow",
            "Sid": "OverPrivilegedS3Access"
        }
    ]
}
```

**FINDING:** The attached policy has broad S3 permissions. This means the role can perform any S3 action on any bucket.

**Test Over-Privileged Access:** Connect to the instance with SSM.

```bash
$ aws ssm start-session --target $INSTANCE_ID

Starting session with SessionId: 304038454789-o6qvjy5lct8lrak7hlynnnv2oe

sh-5.2$
```

In the instance terminal, see what buckets you can list.

```bash
sh-5.2$ aws s3 ls

2026-03-24 09:28:41 thm-finance-reports-304038454789
2026-03-24 09:28:41 thm-logs-archive-304038454789
2026-03-24 09:28:41 thm-webapp-data-304038454789
```

You should be able to list the web app bucket, but since the role is over-permissive, you can also list the finance bucket.

```bash
sh-5.2$ ACCOUNT_ID=$(curl -s http://169.254.169.254/latest/meta-data/identity-credentials/ec2/info | grep AccountId | cut -d'"' -f4)

sh-5.2$ aws s3 ls s3://thm-webapp-data-$ACCOUNT_ID/

                           PRE assets/
                           PRE config/
                           PRE logs/

sh-5.2$ aws s3 ls s3://thm-finance-reports-$ACCOUNT_ID/

                           PRE confidential/
                           PRE flag/

sh-5.2$ aws s3 cp s3://thm-finance-reports-$ACCOUNT_ID/flag/overpowered-role.txt -
```

**FINDING:** This confirms that the instance role is over-permissive and can access every bucket in the account.

**Check IMDS Configuration:** Still in the instance session, you see that IMDS also provides security credential details with no authentication.

```bash
sh-5.2$ curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/

WebAppOverPrivRole-304038454789

sh-5.2$ ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)

sh-5.2$ curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE

{
  "Code" : "Success",
  "LastUpdated" : "2026-03-24T16:19:26Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIAUNSQ2UYCRJQSSR46",
  "SecretAccessKey" : "m6K316Z2S+N2Jf5fIwpcYFE6ite4zkj7di9XnDly",
  "Token" : "IQoJb3JpZ2luX2VjENH[...]",
  "Expiration" : "2026-03-24T22:31:29Z"
}
```

Moving back to `CloudShell`, either by exiting the SSM session or opening another `CloudShell` tab, you can also check the IMDS configuration for the instance.

```bash
$ aws ec2 describe-instances \
    --instance-ids $INSTANCE_ID \
    --query "Reservations[0].Instances[0].MetadataOptions" \
    --output json

{
    "State": "applied",
    "HttpTokens": "optional",
    "HttpPutResponseHopLimit": 2,
    "HttpEndpoint": "enabled",
    "HttpProtocolIpv6": "disabled",
    "InstanceMetadataTags": "disabled"
}
```

**FINDING:** The `HttpTokens` field value is `optional`. This means IMDSv1 is allowed, which is insecure.

**Findings Summary**

- The instance allows for simple unauthenticated requests to IMDS.
- Through IMDSv1, you can retrieve credentials that can be used to assume the attached role.
- The role has an attached policy that allows broad S3 access.

**Answer the questions below**

> What is the name of the other policy attached to the instance role?
> 

**AmazonSSMManagedInstanceCore**

> Which flag was retrieved from the financial bucket?
> 

THM{YIPEE_KI_YAY}

### Task 4 - Remediation

Now that you understand the problem, it is time to fix it.

```bash
$ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

$ INSTANCE_ID=$(aws ec2 describe-instances \
      --filters "Name=tag:Name,Values=webapp-server" "Name=instance-state-name,Values=running" \
      --query "Reservations[0].Instances[0].InstanceId" --output text)
$ ROLE_NAME="WebAppOverPrivRole-$ACCOUNT_ID"
$ echo "ACCOUNT_ID=$ACCOUNT_ID  INSTANCE_ID=$INSTANCE_ID  ROLE_NAME=$ROLE_NAME"

ACCOUNT_ID=304038454789
INSTANCE_ID=i-0a91fac348b8b44e1
ROLE_NAME=WebAppOverPrivRole-304038454789
```

The web application for this exercise would require the following permissions:

- Read configuration file from the `config` object in the web app bucket.
- Read static assets from the `assets` object in the web app bucket.
- Write application logs to the `logs` object in the web app bucket.

That means the role should be limited to:

- `s3:GetObject` on `config` and `assets`.
- `s3:PutObject` on `logs`.
- `s3:ListBucket` solely on the web app bucket.
- No need to access any other bucket in the account.

**Create a Scoped Policy:** Save the policy in a local file so you can attach it to the role.

- Expand to see the full policy
    
    ```bash
    $ cat > ./webapp-scoped-policy.json << EOF
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "ReadConfigAndAssets",
          "Effect": "Allow",
          "Action": ["s3:GetObject"],
          "Resource": [
            "arn:aws:s3:::thm-webapp-data-${ACCOUNT_ID}/config/*",
            "arn:aws:s3:::thm-webapp-data-${ACCOUNT_ID}/assets/*"
          ]
        },
        {
          "Sid": "WriteLogs",
          "Effect": "Allow",
          "Action": ["s3:PutObject"],
          "Resource": ["arn:aws:s3:::thm-webapp-data-${ACCOUNT_ID}/logs/*"]
        },
        {
          "Sid": "ListAppBucket",
          "Effect": "Allow",
          "Action": ["s3:ListBucket"],
          "Resource": ["arn:aws:s3:::thm-webapp-data-${ACCOUNT_ID}"],
          "Condition": {
            "StringLike": {
              "s3:prefix": ["config/*", "assets/*", "logs/*"]
            }
          }
        }
      ]
    }
    EOF
    ```
    

Create the policy.

```bash
$ aws iam create-policy \
    --policy-name WebAppScopedS3Policy \
    --policy-document file://webapp-scoped-policy.json

{
    "Policy": {
        "PolicyName": "WebAppScopedS3Policy",
        "PolicyId": "ANPAUNSQ2UYC73A5NMGRS",
        "Arn": "arn:aws:iam::304038454789:policy/WebAppScopedS3Policy",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 0,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "CreateDate": "2026-03-24T16:43:08+00:00",
        "UpdateDate": "2026-03-24T16:43:08+00:00"
    }
}
```

**Swap the Role Policy:** Detach the over-privileged policy.

```bash
$ OLD_POLICY_ARN=$(aws iam list-attached-role-policies \
    --role-name $ROLE_NAME \
    --query "AttachedPolicies[?contains(PolicyName,'OverPriv')].PolicyArn" \
    --output text)

$ aws iam detach-role-policy \
    --role-name $ROLE_NAME \
    --policy-arn $OLD_POLICY_ARN
```

Attach the new policy.

```bash
$ NEW_POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/WebAppScopedS3Policy"

$ aws iam attach-role-policy \
    --role-name $ROLE_NAME \
    --policy-arn $NEW_POLICY_ARN
```

**Enforce IMDSv2:** Harden the metadata service.

**Note:** This does NOT require stopping or restarting the instance, but any credentials issued via IMDSv1 remain valid for up to 6 hours.

```bash
$ aws ec2 modify-instance-metadata-options \
    --instance-id $INSTANCE_ID \
    --http-tokens required \
    --http-endpoint enabled \
    --http-put-response-hop-limit 1

{
    "InstanceId": "i-0a91fac348b8b44e1",
    "InstanceMetadataOptions": {
        "State": "pending",
        "HttpTokens": "required",
        "HttpPutResponseHopLimit": 1,
        "HttpEndpoint": "enabled",
        "HttpProtocolIpv6": "disabled",
        "InstanceMetadataTags": "disabled"
    }
}
```

**Note:** `--http-put-response-hop-limit 1` is a best practice to limit network hops to 1, preventing containers or reverse proxies from forwarding metadata tokens to external endpoints.

**Verify:** Coming back to the instance SSM session, or starting a new one, you can see that IMDS is not as friendly anymore.

```bash
sh-5.2$ ACCOUNT_ID=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" | xargs -I{} \
    curl -s -H "X-aws-ec2-metadata-token: {}" \
    http://169.254.169.254/latest/dynamic/instance-identity/document | grep -o '"accountId" : "[^"]*"' | cut -d'"' -f4)

sh-5.2$ aws s3 ls s3://thm-finance-reports-$ACCOUNT_ID/

An error occurred (AccessDenied) when calling the ListObjectsV2 operation: [...]
```

But the required permissions are applied.

```bash
sh-5.2$ aws s3 ls s3://thm-webapp-data-$ACCOUNT_ID/config/

2026-03-26 09:06:47         58 app.conf
2026-03-26 09:06:47         44 db.conf
```

Lastly, you can grab the flag for successfully remediating the misconfiguration. Make sure you run this in a separate CloudShell tab, not in the instance session.

```bash
$ aws lambda invoke \
    --function-name AWS203-VerifyRemediation \
    --payload '{}' \
    /tmp/verify-output.json && python3 -m json.tool /tmp/verify-output.json

[...]
{
    "policy_check": "PASS — over-privileged policy removed",
    "scoped_policy_check": "PASS — WebAppScopedS3Policy attached",
    "imds_check": "PASS — IMDSv2 enforced (HttpTokens=required)",
    "status": "PASS",
    "flag": "[REDACTED]"
}
```

You did well and scoped down the over-permissive role as well as hardening the instance metadata while preserving application functionality.

**Answer the questions below**

> What is the flag for this task?
> 

THM{EN_TARO_ADUN}

### Task 5 - Build It Securely

The first step should always be to understand the requirements. Before creating any IAM resource, answer these questions:

1. What AWS service will assume this role? Common examples are: EC2, Lambda, ECS.
2. What API actions does the end service need? The end service can be anything from a web application to automation or IaC.
3. What specific resources does it access? Common examples are: bucket names, table names, or ARNs.
4. Are there conditions that should limit access further? These can include: VPC, source IP, tags, or timeframe.

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

```bash
$ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

$ BOUNDARY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/Room23-DevRoleBoundary"

$ echo "ACCOUNT_ID=$ACCOUNT_ID"

ACCOUNT_ID=304038454789$ echo "BOUNDARY_ARN=$BOUNDARY_ARN"

BOUNDARY_ARN=arn:aws:iam::304038454789:policy/Room23-DevRoleBoundary
```

**Save the Policies:** The trust policy defines who can assume the role. For an EC2, only the EC2 service should be allowed. Key points to note:

- Never use `"Principal":"*"` because this allows any entity to assume the role.
- Never add IAM users or other accounts to the trust policy unless cross-account access is explicitly required.

For EC2, the principal is always `ec2.amazonaws.com`. Save the trust policy so you can attach it later.

```bash
$ cat > ./trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
```

Save the permission policy scoped to the requirements.

- Expand to see the full policy
    
    ```bash
    $ cat > ./secure-webapp-policy.json << EOF
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "ReadConfigAndAssets",
          "Effect": "Allow",
          "Action": ["s3:GetObject"],
          "Resource": [
            "arn:aws:s3:::thm-webapp-data-${ACCOUNT_ID}/config/*",
            "arn:aws:s3:::thm-webapp-data-${ACCOUNT_ID}/assets/*"
          ]
        },
        {
          "Sid": "WriteLogs",
          "Effect": "Allow",
          "Action": ["s3:PutObject"],
          "Resource": ["arn:aws:s3:::thm-webapp-data-${ACCOUNT_ID}/logs/*"]
        },
        {
          "Sid": "ListAppBucketPrefixes",
          "Effect": "Allow",
          "Action": ["s3:ListBucket"],
          "Resource": ["arn:aws:s3:::thm-webapp-data-${ACCOUNT_ID}"],
          "Condition": {
            "StringLike": {
              "s3:prefix": ["config/*", "assets/*", "logs/*"]
            }
          }
        }
      ]
    }
    EOF
    ```
    

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

**Note:** Further hardening can be done by using `aws:SourceVpc` as a condition; this ensures API calls are denied outside the source VPC, limiting the blast radius. At the same time, you will also need a VPC endpoint, but this is outside the scope of the exercise.

**Create the Role:** First, create the role with the permission boundary provided in the lab.

```bash
$ aws iam create-role \
    --role-name SecureWebAppRole \
    --assume-role-policy-document file://trust-policy.json \
    --permissions-boundary $BOUNDARY_ARN \
    --description "Least-privilege role for the web application"

{
    "Role": {
        "Path": "/",
        "RoleName": "SecureWebAppRole",
        "RoleId": "AROAUNSQ2UYC6BIYQX3KT",
        "Arn": "arn:aws:iam::304038454789:role/SecureWebAppRole",
        "CreateDate": "2026-03-24T16:58:31+00:00",
```

Then, create the managed policy from the previously saved file. Make sure you save the ARN

```bash
$ aws iam create-policy \
    --policy-name SecureWebAppS3Policy \
    --policy-document file://secure-webapp-policy.json \
    --description "Scoped S3 access for the web application"

{
    "Policy": {
        "PolicyName": "SecureWebAppS3Policy",
        "PolicyId": "ANPAUNSQ2UYCWTVL7MEJB",
        "Arn": "arn:aws:iam::304038454789:policy/SecureWebAppS3Policy",
        "Path": "/",
```

Attach the policy to the role. You will also attach the SSM policy for managing instance access.

```bash
$ SECURE_POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/SecureWebAppS3Policy"

$ aws iam attach-role-policy \
    --role-name SecureWebAppRole \
    --policy-arn $SECURE_POLICY_ARN

$ aws iam attach-role-policy \
    --role-name SecureWebAppRole \
    --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
```

**Create the Instance Profile:** You can now create an instance profile and add the role to that profile.

```bash
$ aws iam create-instance-profile \
    --instance-profile-name SecureWebAppProfile

{
    "InstanceProfile": {
        "Path": "/",
        "InstanceProfileName": "SecureWebAppProfile",
        "InstanceProfileId": "AIPAWA3VODMXVUWE4KSRD",
        "Arn": "arn:aws:iam::304038454789:instance-profile/SecureWebAppProfile",
        "CreateDate": "2026-03-25T07:18:52+00:00",
        "Roles": []
    }
}$ aws iam add-role-to-instance-profile \
    --instance-profile-name SecureWebAppProfile \
    --role-name SecureWebAppRole
```

**Verify:** You can run the helper Lambda function to see if everything was set up correctly.

```bash
$ aws lambda invoke \
  --function-name AWS203-VerifySecureBuild \
  --payload '{}' \
  /tmp/verify-secure.json && python3 -m json.tool /tmp/verify-secure.json

{
  "role_found": "SecureWebAppRole",
  "boundary_check": "PASS — Room23-DevRoleBoundary applied",
  "trust_check": "PASS — only ec2.amazonaws.com in trust policy",
  "policy_check": "PASS — no overly-broad policies attached",
  "status": "PASS",
  "flag": "[REDACTED]"
}
```

**Answer the questions below**

> What is the flag for this task?
> 

THM{CARRIER_HAS_ARRIVED}

### Task 6 - Conclusion

You identified an EC2 instance with an over-privileged IAM role, remediated the misconfiguration, hardened the deployment, and rebuilt everything from scratch.

Here is a handy checklist you can run through when creating any EC2 instance role:

- Permission Scoping:
    - Actions limited to only the needed API calls.
    - Resources scoped to specific ARNs.
    - Prefix conditions on buckets.
    - VPC conditions for limiting blast radius (VPC endpoints required).
- Trust Policy:
    - Only add the required service principal.
    - No wildcard principals.
    - No unnecessary cross-account trust.
- Metadata Protection:
    - Enforce IMDSv2.
    - Hop limit set to 1.
    - Optionally, disable IMDS entirely if the instance does not need it.
- Monitoring:
    - CloudTrail data events enabled for S3 buckets.
    - Alerts on unexpected API calls from the role.
    - GuardDuty is enabled to detect unusual credential usage.

**Key Takeaways**

- Scope service roles in accordance with the Principle of Least Privilege.
- Enforce IMDSv2 on all instances or disable IMDS entirely if not needed.
- Use conditions to limit credentials usage.
- Instance roles should be part of any security analysis.
- Always verify everything still works after tightening security.
