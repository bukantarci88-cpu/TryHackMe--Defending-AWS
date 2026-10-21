# AWS Security 2.2. The Forgotten Access Key

### Task 1 - Introduction

An engineer creates an AWS access key to run a deployment script. The script works, the project is deployed, and the key is forgotten, still active, never rotated, saved in a config file somewhere. If the key is leaked, an attacker would have persistent, long-lived access to the environment. This is one of the most common credential hygiene misconfigurations in AWS.

### Task 2 - Real-World Incident

Uber is one of the largest ride-sharing platforms in the world, and it uses AWS as its cloud provider to store sensitive data in S3 buckets. Uber's engineering teams use GitHub as their code repository platform and AWS access keys to programmatically access AWS services.

**What Happened**

![The attack chain that led to the breach.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1781259338003.png)

The breach happened through a chain of credential failures:

1. **Credential stuffing into GitHub** - The attackers tested stolen email/password combinations against GitHub accounts. They found a valid login and gained access to Uber's private GitHub repositories. There was no MFA enforcement.
2. **Access key leak** - Inside one of the private repositories, the attackers found AWS access keys hardcoded in the source code.
3. **S3 data exfiltration** - Using the keys, the attackers authenticated to the AWS account and proceeded to access and download 16 unencrypted database backup files from S3.
4. **Ransom and cover-up** - The attackers demanded payment, and Uber's Chief Security Officer paid the ransom and covered the incident as a vulnerability disclosure.

**Core Failures**

- **Long-lived access keys with no rotation** - They provide persistent access with no expiration.
- **Source code hardcoded keys** - Access keys were stored in the application code instead of a secrets management system or replaced with temporary role-based credentials.
- **No MFA** - Access to GitHub or AWS did not require MFA for power users.
- **Over-privileged access** - The keys provided broad access to S3 data stores.
- **No monitoring or alerting** - There was no detection for unusual API activity patterns, such as S3 bulk downloads.

**Answer the questions below**

> What AWS service would you use to remediate the hardcoded keys misconfiguration?
> 

Secrets Manager

### Task 3 - Identification

The IAM credential report is your primary tool for a fast audit. It provides a CSV snapshot of every IAM user's credentials in the account.

![Create and download IAM credential report](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1774000332535.png)

**Note:** For convenience, you can set the account ID and lab bucket name as environment variables. Forgotten Keys

```bash
$ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

$ echo "Account ID: ${ACCOUNT_ID}"

Account ID: 524090942184$ BUCKET_NAME="thm-app-data-${ACCOUNT_ID}"

$ echo "Bucket:${BUCKET_NAME}"

Bucket: thm-app-data-524090942184
```

```bash
$ aws iam generate-credential-report

{
    "State": "STARTED",
    "Description": "No report exists. Starting a new report generation task"
}
```

The report will take ~1 minute to generate, and you can then download and view it.

```bash
$ aws iam get-credential-report \
    --query 'Content' \
    --output text | base64 --decode > credential-report.csv

$ cat credential-report.csv

user,arn,user_creation_time[...]
```

The report includes these key columns for each user:

- **user** - the IAM username.
- **mfa_active** - MFA enabled (true/false).
- **access_key_1_active / access_key_2_active** - access keys are active (true/false).
- **access_key_1_last_used_date / access_key_2_last_used_date** - last time the key was used.
- **access_key_1_last_rotated / access_key_2_last_rotated** - last time the keys were rotated.

You can view the report more conveniently by running this small scriptlet.

```bash
$ python3 -c "
import csv
cols = ['user','mfa_active','access_key_1_active','access_key_1_last_used_date',
        'access_key_2_active','access_key_2_last_used_date']
for row in csv.DictReader(open('credential-report.csv')):
    print('---')
    for c in cols: print(f'  {c}: {row.get(c, \"N/A\")}')
"

[...]
---
  user: dev-keyleaks
  mfa_active: false
  access_key_1_active: true
  access_key_1_last_used_date: 2026-03-19T09:36:00Z
  access_key_2_active: true
  access_key_2_last_used_date: N/A
---
[...]
```

**FINDING:**  You can quickly see the account has no MFA active and two active access keys. You'll be able to look at the other users as well, but your focus should be on the `dev-keyleaks` user.

List all keys for the user.

```bash
$ aws iam list-access-keys \
    --user-name dev-keyleaks

{
    "AccessKeyMetadata": [
        {
            "UserName": "dev-keyleaks",
            "AccessKeyId": "AKIAXUBSBELUDHGUBRY7",
            "Status": "Active",
            "CreateDate": "2026-03-19T09:36:20+00:00"
        },
        {
            "UserName": "dev-keyleaks",
            "AccessKeyId": "AKIAXUBSBELULW2KLZSA",
            "Status": "Active",
            "CreateDate": "2026-03-19T09:36:19+00:00"
        }
    ]
}
```

Now, check each key.

**Note:** Access key IDs will be stored in environment variables for convenience.

```bash
$ KEY1_ID=$(aws iam list-access-keys \
       --user-name dev-keyleaks \
       --query "AccessKeyMetadata[0].AccessKeyId" \
       --output text)

$ KEY2_ID=$(aws iam list-access-keys \
       --user-name dev-keyleaks \
       --query "AccessKeyMetadata[1].AccessKeyId" \
       --output text)
```

```bash
$ aws iam get-access-key-last-used \
    --access-key-id $KEY1_ID

{
    "UserName": "dev-keyleaks",
    "AccessKeyLastUsed": {
        "LastUsedDate": "2026-03-19T09:36:00+00:00",
        "ServiceName": "s3",
        "Region": "us-east-1"
    }
}$ aws iam get-access-key-last-used \
    --access-key-id $KEY2_ID

{
    "UserName": "dev-keyleaks",
    "AccessKeyLastUsed": {
        "ServiceName": "N/A",
        "Region": "N/A"
    }
}
```

**FINDING:** The key with no `LastUsedDate` field is active but was never used.

Check MFA status for the user.

```bash
$ aws iam list-mfa-devices \
    --user-name dev-keyleaks
{
    "MFADevices": []
}
```

**FINDING:** No MFA configured.

Check the permissions of the user.

![Check user permissions in AWS console.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1774000524158.png)

```bash
$ aws iam list-attached-user-policies \
    --user-name dev-keyleaks

{
    "AttachedPolicies": []
}
```

```bash
$ aws iam list-groups-for-user \
    --user-name dev-keyleaks

{
    "Groups": [
        {
            "Path": "/",
            "GroupName": "AppDataReaders",
            "GroupId": "AGPAXUBSBELUOA5J57PJW",
            "Arn": "arn:aws:iam::524090942184:group/AppDataReaders",
            "CreateDate": "2026-03-19T09:36:00+00:00"
        }
    ]
}$ aws iam list-attached-group-policies \
    --group-name AppDataReaders

{
    "AttachedPolicies": [
        {
            "PolicyName": "AppDataReadersPolicy",
            "PolicyArn": "arn:aws:iam::524090942184:policy/AppDataReadersPolicy"
        }
    ]
}
```

Since the user is part of a group, you can check the group policy to see the permissions.

```bash
$ POLICY_VERSION=$(aws iam get-policy \
    --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/AppDataReadersPolicy" \
    --query 'Policy.DefaultVersionId' --output text)

$ aws iam get-policy-version \
    --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/AppDataReadersPolicy" \
    --version-id $POLICY_VERSION \
    --query 'PolicyVersion.Document'

[...]
        {
            "Action": [
                "s3:ListBucket",
                "s3:GetObject"
            ],
            "Resource": [
                "arn:aws:s3:::thm-app-data-524090942184",
                "arn:aws:s3:::thm-app-data-524090942184/*"
            ],
            "Effect": "Allow",
            "Sid": "S3ReadAppBucket"
        },
[...]
```

**FINDING:** The user belongs to a group that has access to a specific S3 bucket. The blast radius is limited, but an attacker could silently read the entire contents of that bucket.

**Findings Summary**

That was a long run, but let us put everything together: The `dev-keyleaks` has no MFA enabled, and one stale access key that was never used, and its permissions allow for reading the content of a specific S3 bucket.

What you should also be on the lookout for when analyzing findings:

- **Age** - Keys that are older than 90 days and have never been rotated.
- **Usage gap** - Keys that are rarely used (30+ days) should be disabled.
- **No monitoring** - CloudTrail alerts or automated checking should be in place for key usage anomalies.

**Answer the questions below**

> What AWS service can you use to monitor key usage?
> 

CloudTrail

> What other S3 actions are allowed in the group policy (listed alphabetically)?
> 

GetBucketLocation,ListAllMyBuckets

### Task 4 - Remediation

- Deactivate the stale key.
- Wait and confirm.
- Delete the stale key.
- Rotate the active key.
- Enable MFA for the user.
- Verify the fix.

**Deactivate The Stale Key**

**Note:** Sometimes listing keys puts them in a different order, so make sure you have the right key in the right variable.

```bash
$ aws iam update-access-key \
    --user-name dev-keyleaks \
    --access-key-id $KEY2_ID \
    --status Inactive
```

**Wait And Confirm:** The recommended approach in this step is to ensure proper communication during the change, allow a 24- to 72-hour window, and be on the lookout for anything that breaks during this time. A good practice is to monitor any API calls targeting this key during the wait window by using CloudTrail.

**Delete The Stale Key:** A good reminder here is that this is an irreversible process; once an access key is deleted, it is permanently removed, and any service or application using it will lose access. 

```bash
$ aws iam delete-access-key \
    --user-name dev-keyleaks \
    --access-key-id $KEY2_ID
```

**Rotate The Active Key:** Create a new access key for the user.

```bash
$ aws iam create-access-key \
    --user-name dev-keyleaks

{
    "AccessKey": {
        "UserName": "dev-keyleaks",
        "AccessKeyId": "AKIAXUBSBELUIIXHFEFJ",
        "Status": "Active",
        "SecretAccessKey": "ZQFR6Sf5N1wnD[...]",
        "CreateDate": "2026-03-20T10:22:02+00:00"
    }
}
```

**Note:** Save the secret access key, as you cannot retrieve it again afterward.

```bash
$ aws configure set aws_access_key_id [REPLACE_WITH_NEW_KEY_ID] --profile dev-keyleaks

$ aws configure set aws_secret_access_key [REPLACE_WITH_NEW_KEY_SECRET] --profile dev-keyleaks

$ aws configure set region us-east-1 --profile dev-keyleaks
```

Before removing the old key, test that the new key works.

```bash
$ aws sts get-caller-identity --profile dev-keyleaks

{
    "UserId": "AIDAXUBSBELUGAGXBR3HY",
    "Account": "524090942184",
    "Arn": "arn:aws:iam::524090942184:user/dev-keyleaks"
}$ aws s3 ls s3://${BUCKET_NAME}/ --profile dev-keyleaks

                           PRE config/
                           PRE logs/
                           PRE reports/
```

Now, run the commands you used for the stale key, but this time for the other key you identified. This ensures that the user has only one key.

```bash
$ aws iam update-access-key \
    --user-name dev-keyleaks \
    --access-key-id $KEY1_ID \
    --status Inactive

$ aws iam delete-access-key \
    --user-name dev-keyleaks \
    --access-key-id $KEY1_ID
```

**Enable MFA For The User:** In a live environment, MFA adds a second authentication factor. This can help protect sensitive operations by also requiring a one-time code when executing.

**Note:** This step is optional for the lab, as it requires setting up user MFA in your personal authenticator app, such as Google Authenticator or Microsoft Authenticator. It can be safely removed after completing the lab.

Assign an MFA device.

![Assign a MFA device to the user.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1774003889799.png)

Provide a name for the device, select `Authenticator App`, and click `Next`.

![Provide a name for the MFA, select authenticator app, and click next.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1774003890181.png)

Scan the QR code and input two consecutive one-time codes.

![Complete the authenticator setup](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1774003890165.png)

You can set this up via the CLI, but it still requires you to download the generated image and scan the QR code in the authenticator app.

**Note:** In `CloudShell`, you can download a file by going to the Actions drop-down in the top-right of the shell window, then selecting `Download file`, and providing the path to the .png file.

```bash
$ aws iam create-virtual-mfa-device \
  --virtual-mfa-device-name dev-keyleaks-mfa \
  --outfile /tmp/mfa-qr.png \
  --bootstrap-method QRCodePNG

$ aws iam enable-mfa-device \
  --user-name dev-keyleaks \
  --serial-number "arn:aws:iam::${ACCOUNT_ID}:mfa/dev-keyleaks-mfa" \
  --authentication-code1 [REPLACE_WITH_CODE_1] \
  --authentication-code2 [REPLACE_WITH_CODE_2]
```

**Verify:** Running the commands below ensures the user now has only one access key and an enrolled MFA device.

```bash
$ aws iam list-access-keys \
    --user-name dev-keyleaks

{
    "AccessKeyMetadata": [
        {
            "UserName": "dev-keyleaks",
            "AccessKeyId": "AKIAXUBSBELUIIXHFEFJ",
            "Status": "Active",
            "CreateDate": "2026-03-20T10:22:02+00:00"
        }
    ]
}$ aws iam list-mfa-devices \
    --user-name dev-keyleaks

{
    "MFADevices": [
        {
            "UserName": "dev-keyleaks",
            "SerialNumber": "arn:aws:iam::524090942184:mfa/dev-keyleaks-mfa",
            "EnableDate": "2026-03-20T10:41:39+00:00"
        }
    ]
}
```

One last step to do is to retrieve your well-earned flag by running a helper Lambda function.

```bash
$ aws lambda invoke \
    --function-name AWS202-VerifyRemediation \
    --payload '{}' \
    /tmp/verify-task4.json && python3 -m json.tool /tmp/verify-task4.json

[...]
{
    "active_key_count": 1,
    "key_check": "PASS",
    "mfa_device_count": 1,
    "mfa_check": "PASS",
    "status": "PASS",
    "flag": "[REDACTED]"
}
```

That was quite a ride, but you managed to successfully remove stale keys, rotate existing keys, and enroll MFA devices.  

**Answer the questions below**

> What should you always do before deleting access keys?
> 

wait

> What is the flag retrieved at the end?
> 

THM{QUICKLY_FIND_MY_PHONE}

```bash
~ $ aws sts get-caller-identity --profile dev-keyleaks
{
"UserId": "AIDA4NFHWSLO2OENK6H2O",
"Account": "852902712029",
"Arn": "arn:aws:iam::852902712029:user/dev-keyleaks"
}
```

 <img width="988" height="301" alt="image" src="https://github.com/user-attachments/assets/bb826b55-c1b9-4ace-854a-631a85bb1f66" />


### Task 5 - Build It Securely

Now, let us take a step back and understand how to approach this securely from day one.

**Temporary Credentials**

- Create an IAM role with the required permissions.
- Allow the user (or service) to assume the role.
- The role issues temporary credentials that expire automatically.

First, create the trust policy. This will allow `dev-keyleaks` user to assume the role.

```bash
$ cat > /tmp/trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${ACCOUNT_ID}:user/dev-keyleaks"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}
EOF
```

Then, create the role. The permission boundary parameter is mandatory.

```bash
$ aws iam create-role \
    --role-name DevS3ReadRole \
    --assume-role-policy-document file:///tmp/trust-policy.json \
    --permissions-boundary "arn:aws:iam::${ACCOUNT_ID}:policy/Room22-DevS3ReadBoundary" \
    --description "Developer role for S3 read access - requires MFA"
{
    "Role": {
        "Path": "/",
        "RoleName": "DevS3ReadRole",
        "RoleId": "AROAXUBSBELUGIWWK3FAZ",
        "Arn": "arn:aws:iam::524090942184:role/DevS3ReadRole",
        "CreateDate": "2026-03-20T11:06:19+00:00",
[...]
```

Lastly, attach an inline policy to set permissions.

```bash
$ aws iam put-role-policy \
  --role-name DevS3ReadRole \
  --policy-name S3ReadAccess \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Sid\": \"S3ReadSpecificBucket\",
      \"Effect\": \"Allow\",
      \"Action\": [\"s3:GetObject\", \"s3:ListBucket\"],
      \"Resource\": [
        \"arn:aws:s3:::${BUCKET_NAME}\",
        \"arn:aws:s3:::${BUCKET_NAME}/*\"
      ]
    }]
  }"
```

**Verify:** To verify this, you will use the `dev-keyleaks` profile created earlier to request temporary credentials.

**Note:** This step requires one valid MFA code, so it will not work if the MFA was not set up in the previous task. You can skip over this set of commands if you did not set a MFA in the previous task.

```bash
$ CREDS=$(aws sts assume-role \
    --profile dev-keyleaks \
    --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/DevS3ReadRole" \
    --role-session-name dev-session \
    --serial-number "arn:aws:iam::${ACCOUNT_ID}:mfa/dev-keyleaks-mfa" \
    --token-code [REPLACE_WITH_VALID_MFA_CODE] \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
    --output text)

$ export AWS_ACCESS_KEY_ID=$(echo $CREDS | awk '{print $1}')

$ export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | awk '{print $2}')

$ export AWS_SESSION_TOKEN=$(echo $CREDS | awk '{print $3}')
```

You can verify the setup by running the following commands.

```bash
$ aws sts get-caller-identity

{
    "UserId": "AROAXUBSBELUGIWWK3FAZ:dev-session",
    "Account": "524090942184",
    "Arn": "arn:aws:sts::524090942184:assumed-role/DevS3ReadRole/dev-session"
}$ aws s3 ls s3://${BUCKET_NAME}/

                           PRE config/
                           PRE logs/
                           PRE reports/$ aws s3 cp s3://${BUCKET_NAME}/reports/quarterly-review.txt -

[REDACTED]

This file contains the quarterly security review.
Access to this file should be tightly controlled.$ unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

You can also run this helper Lambda function to retrieve the flag.

**Note:** Run the `unset` command from the previous step, or the Lambda function will be denied execution.

```bash
$ aws lambda invoke \
    --function-name AWS202-VerifySecureBuild \
    --payload '{}' \
    /tmp/verify-task5.json && python3 -m json.tool /tmp/verify-task5.json

[...]
{
    "permission_boundary": "arn:aws:iam::524090942184:policy/Room22-DevS3ReadBoundary",
    "boundary_check": "PASS",
    "trust_mfa_check": "PASS",
    "s3_policy_check": "PASS",
    "status": "PASS",
    "flag": "[REDACTED]"
}
```

**Why Temporary Credentials**

STS has some advantages over long-lived keys:

- **Expire automatically** - Default is after 1 hour, but can be configured
- **Cannot be reused** - Once expired, the credentials are useless
- **Include session token** - This helps API calls be auditable in CloudTrail

**Remember The Keys**

If you must use long-lived keys, it is best to also implement these guardrails:

- Enforce MFA on sensitive operations.
- Define key rotation schedule:
    - Maximum age: 90 days - keys older than 90 days should be rotated.
    - Unused threshold: 30 days - keys unused for more than 30 days should be deactivated.
    - Maximum keys per user: 1 - Users should have at most 1 active key, with an exception of 2 during the rotation window.
    - Automated audit - use AWS Config managed rules or a scheduled script.

**The Credential Decision Flow**

When deciding how to authenticate a workload in AWS, use the following priority list as a rule of thumb:

- IAM role - Common use cases: EC2 instance profiles, Lambda execution roles, ECS task roles.
- STS assume-role - For human users or cross-account access.
- SSO / Identity Center - For human users using the console or CLI.
- Long-lived access keys - Only when none of the above are possible, and proper credentials hygiene is implemented.

**Answer the questions below**

> What is the default lifetime (in hours) for a set of temporary credentials?
> 

1

> What guardrail should you implement if planning to use long-lived access keys?
> 

Key rotation schedule

> What is the flag found in the reports?
> 

THM{FOUND_YOUR_KEY}

<img width="983" height="123" alt="image 1" src="https://github.com/user-attachments/assets/4bae1ed1-cd6e-493f-84e9-ff489b1449d5" />


```bash
~ $ aws s3 cp s3://thm-app-data-852902712029/reports/quarterly-review.txt - --profile dev-keyleaks
THM{FOUND_YOUR_KEY}
```

> What is the flag retrieved after executing the helper function?
> 

THM{NO_KEYS_NEEDED}

```bash
~ $  aws lambda invoke \ --function-name AWS202-VerifySecureBuild \
--payload '{}' \
/tmp/verify-task5.json && python3 -m json.tool /tmp/verify-task5.json{
"StatusCode": 200,
"ExecutedVersion": "LATEST"
}
{
    "permission_boundary": "arn:aws:iam::852902712029:policy/Room22-DevS3ReadBoundary",
    "boundary_check": "PASS",
    "trust_mfa_check": "PASS",
    "s3_policy_check": "PASS",
    "status": "PASS",
    "flag": "THM{NO_KEYS_NEEDED}"
}
```

### Task 6 - Conclusion

You have successfully found a forgotten access key, remediated it, and now understand how to approach and implement credentials management securely.

**Key Takeaways**

- Credential reports are your first line of audit.
- Old keys are silent vulnerabilities.
- Ensure you first deactivate the keys, wait, and check if used, then delete.
- MFA should be enforced.
- Prefer temporary credentials over long-lived access keys.
- Automate auditing.
