# TryHackMe AWS Security: Forgotten Keys

## Overview

This room focuses on identifying and remediating forgotten AWS IAM access keys, reviewing credential hygiene, and replacing long-lived credentials with temporary, role-based access.

## Task 1 — Introduction

An engineer may create an AWS access key for a deployment script and then forget about it. If the key remains active, unrotated, and stored in a configuration file or source code, a leak can give an attacker persistent access to the AWS environment.

**Core risk:** Forgotten long-lived credentials can remain valid long after their original purpose has ended.

## Task 2 — Real-World Incident: Uber

The notes describe a breach chain involving compromised GitHub access and hardcoded AWS access keys:

1. **Credential stuffing:** Attackers tested stolen email/password combinations against GitHub and accessed private repositories where MFA was not enforced.
2. **Exposed keys:** AWS access keys were hardcoded in source code.
3. **S3 data access:** The keys were used to access and download 16 unencrypted database backup files from S3.
4. **Ransom and cover-up:** The notes describe a ransom demand and an attempted cover-up.

### Key security failures

- Long-lived access keys were not rotated.
- Credentials were hardcoded in source code rather than stored in a secrets-management system or replaced with role-based temporary credentials.
- MFA was not enforced.
- Access was broader than necessary for the required S3 data.
- Monitoring and alerting for unusual API activity, such as bulk S3 downloads, were lacking.

**Remediation service:** AWS Secrets Manager can help manage secrets instead of hardcoding them in source code.

## Task 3 — Identify Forgotten Keys

### Generate an IAM credential report

The IAM credential report provides a CSV snapshot of IAM users' credential status.

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET_NAME="thm-app-data-${ACCOUNT_ID}"

aws iam generate-credential-report

aws iam get-credential-report \
  --query 'Content' \
  --output text | base64 --decode > credential-report.csv
```

The report may take about a minute to become available.

### Important credential-report fields

| Field | Meaning |
|---|---|
| `user` | IAM username |
| `mfa_active` | Whether MFA is enabled |
| `access_key_1_active` / `access_key_2_active` | Whether each access key is active |
| `access_key_1_last_used_date` / `access_key_2_last_used_date` | Last recorded use of each key |
| `access_key_1_last_rotated` / `access_key_2_last_rotated` | Last rotation time for each key |

A quick Python summary of selected fields:

```bash
python3 -c "
import csv
cols = ['user','mfa_active','access_key_1_active','access_key_1_last_used_date',
        'access_key_2_active','access_key_2_last_used_date']
for row in csv.DictReader(open('credential-report.csv')):
    print('---')
    for c in cols:
        print(f'  {c}: {row.get(c, \"N/A\")}')
"
```

### Inspect a user's access keys

```bash
aws iam list-access-keys --user-name dev-keyleaks
aws iam get-access-key-last-used --access-key-id "$KEY_ID"
aws iam list-mfa-devices --user-name dev-keyleaks
```

The example user `dev-keyleaks` had:
- MFA disabled.
- Two active access keys.
- One key with recorded S3 usage in `us-east-1`.
- One active key with no recorded use.

### Review effective permissions

Check directly attached user policies and group membership:

```bash
aws iam list-attached-user-policies --user-name dev-keyleaks
aws iam list-groups-for-user --user-name dev-keyleaks
aws iam list-attached-group-policies --group-name AppDataReaders
```

Retrieve the default version of a managed policy:

```bash
POLICY_VERSION=$(aws iam get-policy \
  --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/AppDataReadersPolicy" \
  --query 'Policy.DefaultVersionId' --output text)

aws iam get-policy-version \
  --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/AppDataReadersPolicy" \
  --version-id "$POLICY_VERSION" \
  --query 'PolicyVersion.Document'
```

The example `AppDataReaders` group policy allowed `s3:ListBucket` and `s3:GetObject` for a specific application-data bucket. The notes also identify `GetBucketLocation` and `ListAllMyBuckets` as additional allowed S3 actions.

**Finding:** Although the permissions were limited to a specific bucket for object reads/listing, a compromised key could still allow an attacker to read that bucket's contents.

### What to watch for

- **Key age:** Keys older than 90 days that have not been rotated.
- **Usage gap:** Keys unused for more than 30 days should be reviewed and potentially deactivated.
- **Monitoring gaps:** Use AWS CloudTrail and automated checks to identify anomalous key usage.

## Task 4 — Remediate the Forgotten Keys

Recommended sequence:

1. Deactivate the stale key.
2. Wait and monitor for impact.
3. Delete the stale key only after confirming it is no longer required.
4. Rotate the active key.
5. Enable MFA.
6. Verify the final configuration.

### Deactivate a stale key

Confirm that the key ID is the correct one before running a change:

```bash
aws iam update-access-key \
  --user-name dev-keyleaks \
  --access-key-id "$STALE_KEY_ID" \
  --status Inactive
```

### Wait and confirm

Allow a **24–72-hour monitoring window**, coordinating with the application or service owner. Use CloudTrail to check whether API calls continue to target the key and watch for application failures.

### Delete the stale key

Deletion is irreversible. A service that still relies on the key will lose access.

```bash
aws iam delete-access-key \
  --user-name dev-keyleaks \
  --access-key-id "$STALE_KEY_ID"
```

### Rotate the active key

Create a replacement key:

```bash
aws iam create-access-key --user-name dev-keyleaks
```

Save the secret access key securely when it is returned; AWS does not show the secret again later. Avoid committing it to source control.

Configure a dedicated AWS CLI profile using the new credentials:

```bash
aws configure set aws_access_key_id '<NEW_KEY_ID>' --profile dev-keyleaks
aws configure set aws_secret_access_key '<NEW_SECRET_KEY>' --profile dev-keyleaks
aws configure set region us-east-1 --profile dev-keyleaks
```

Verify identity and access before removing the previous key:

```bash
aws sts get-caller-identity --profile dev-keyleaks
aws s3 ls "s3://${BUCKET_NAME}/" --profile dev-keyleaks
```

After confirming that the replacement works, deactivate and delete the old key:

```bash
aws iam update-access-key \
  --user-name dev-keyleaks \
  --access-key-id "$OLD_KEY_ID" \
  --status Inactive

aws iam delete-access-key \
  --user-name dev-keyleaks \
  --access-key-id "$OLD_KEY_ID"
```

### Enable MFA

List registered MFA devices:

```bash
aws iam list-mfa-devices --user-name dev-keyleaks
```

The room demonstrates creating a virtual MFA device and enabling it with two consecutive authenticator codes:

```bash
aws iam create-virtual-mfa-device \
  --virtual-mfa-device-name dev-keyleaks-mfa \
  --outfile /tmp/mfa-qr.png \
  --bootstrap-method QRCodePNG

aws iam enable-mfa-device \
  --user-name dev-keyleaks \
  --serial-number "arn:aws:iam::${ACCOUNT_ID}:mfa/dev-keyleaks-mfa" \
  --authentication-code1 '<CODE_1>' \
  --authentication-code2 '<CODE_2>'
```

Use the QR code with an authenticator app and replace the example values with the actual codes from that setup.

### Verify remediation

```bash
aws iam list-access-keys --user-name dev-keyleaks
aws iam list-mfa-devices --user-name dev-keyleaks
```

Expected end state in the room: one active access key and one enrolled MFA device.

## Task 5 — Build It Securely with Temporary Credentials

Where possible, avoid long-lived IAM user access keys. Use an IAM role and AWS Security Token Service (STS) to issue temporary credentials.

### 1. Create a trust policy requiring MFA

Example trust policy for allowing `dev-keyleaks` to assume a role only when MFA is present:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<ACCOUNT_ID>:user/dev-keyleaks"
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
```

### 2. Create a role with a permission boundary

```bash
aws iam create-role \
  --role-name DevS3ReadRole \
  --assume-role-policy-document file:///tmp/trust-policy.json \
  --permissions-boundary "arn:aws:iam::${ACCOUNT_ID}:policy/Room22-DevS3ReadBoundary" \
  --description "Developer role for S3 read access - requires MFA"
```

### 3. Attach least-privilege S3 permissions

```bash
aws iam put-role-policy \
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

### 4. Assume the role and use temporary credentials

This requires a configured profile and a valid MFA code:

```bash
CREDS=$(aws sts assume-role \
  --profile dev-keyleaks \
  --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/DevS3ReadRole" \
  --role-session-name dev-session \
  --serial-number "arn:aws:iam::${ACCOUNT_ID}:mfa/dev-keyleaks-mfa" \
  --token-code '<VALID_MFA_CODE>' \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
  --output text)

export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | awk '{print $1}')
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | awk '{print $2}')
export AWS_SESSION_TOKEN=$(echo "$CREDS" | awk '{print $3}')
```

Verify the assumed role and S3 access:

```bash
aws sts get-caller-identity
aws s3 ls "s3://${BUCKET_NAME}/"
aws s3 cp "s3://${BUCKET_NAME}/reports/quarterly-review.txt" -
```

Clear the temporary credentials from the shell when finished:

```bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

### Why temporary credentials?

- **Automatic expiry:** The room states the default lifetime is one hour; session duration can be configured within AWS limits.
- **Reduced persistence:** Expired credentials cannot be reused.
- **Session token:** Temporary credentials include a session token and can support auditability of API calls in CloudTrail.

### Guardrails when long-lived keys cannot be avoided

- Require MFA for sensitive operations where supported.
- Rotate keys at least every 90 days.
- Review or deactivate keys unused for more than 30 days.
- Keep at most one active key per user, except for a short rotation overlap where two may be needed.
- Automate credential audits with AWS Config rules or scheduled scripts.

### Authentication preference

1. **IAM roles** — for workloads such as EC2 instance profiles, Lambda execution roles, and ECS task roles.
2. **STS AssumeRole** — for human users or cross-account access where appropriate.
3. **AWS IAM Identity Center (SSO)** — for people accessing the AWS console or CLI.
4. **Long-lived access keys** — only when alternatives are not feasible and strong credential hygiene is in place.

## Task 6 — Conclusion and Key Takeaways

- Use IAM credential reports as a first-line credential audit.
- Treat forgotten or unused access keys as potential security risks.
- Deactivate a key, wait, and monitor its use before deleting it.
- Enable MFA.
- Prefer IAM roles and temporary STS credentials over long-lived access keys.
- Apply least privilege to user and role permissions.
- Use CloudTrail to monitor API activity and investigate unusual usage.
- Automate credential hygiene checks.

## Answers and Flags

| Question | Answer |
|---|---|
| What AWS service can help remediate hardcoded keys? | AWS Secrets Manager |
| What AWS service can monitor key usage? | AWS CloudTrail |
| What other S3 actions are allowed in the group policy? | `GetBucketLocation`, `ListAllMyBuckets` |
| What should you do before deleting access keys? | Deactivate, wait, and confirm they are no longer needed |
| Flag retrieved after remediation | `THM{QUICKLY_FIND_MY_PHONE}` |
| Default temporary credential lifetime (hours) | `1` |
| Guardrail for long-lived keys | Key rotation schedule |
| Flag found in the reports | `THM{FOUND_YOUR_KEY}` |
| Flag after secure-build helper function | `THM{NO_KEYS_NEEDED}` |

## Important Notes

- Replace placeholders such as `<ACCOUNT_ID>`, `<NEW_KEY_ID>`, `<NEW_SECRET_KEY>`, and MFA codes with values from your own lab environment.
- Never publish real secret access keys, session tokens, passwords, or MFA codes in a repository.
- The identifiers and account details in the original lab output are environment-specific; use placeholders in reusable notes.
