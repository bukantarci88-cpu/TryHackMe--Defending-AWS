# AWS Security 5.1. The Leaky Bucket

### Task 1 - Introduction

Publicly accessible S3 buckets have been responsible for some of the largest data exposures in cloud security history. Even though AWS today makes it very hard to publicly expose buckets, this misconfiguration is still something you can encounter in the wild and should be a quick check-and-fix in your security toolbelt.

### Task 2 - Real-World Incident

Public S3 buckets have become so common as an attack vector that security teams run automated scanners looking for them. AWS also took notice and is making it even harder to make an S3 bucket public by default.

Below are a few examples of incidents that happened to large companies:

- [**Verizon**](https://www.techtarget.com/searchsecurity/news/450422709/Misconfigured-AWS-S3-bucket-exposes-millions-of-Verizon-customers-data): A third-party vendor left an S3 bucket containing call center data publicly accessible. Approximately 6 million customer records were exposed, including names, addresses, and account PINs. The bucket was used in a routine project and was never locked back down.
- [**Dow Jones**](https://www.forbes.com/sites/lconstantin/2017/07/17/cloud-storage-error-exposes-over-two-million-dow-jones-customer-records/): A public S3 bucket exposed the personal and financial data of 2.2 million subscribers. The bucket had been configured for a content distribution project and left open indefinitely.
- [**Pegasus Airlines**](https://gdprtech.com/en/the-future-of-unstructured-data-lessons-from-the-pegasus-airlines-data-breach/): A misconfigured S3 bucket exposed 6.5 terabytes of data, including flight charts, navigation materials, and crew member personal information. Over 23 million files were publicly accessible. The root cause: an internal data integration project that disabled Block Public Access and never re-enabled it.

**Common Pattern:** In each case, the attackers did nothing sophisticated. They used publicly available tools to scan AWS for open buckets.

![Common pattern in the misconfiguration](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1781512956473.png)

The overall pattern in each case was:

1. A bucket was intentionally opened (for a project, integration, or migration).
2. Block Public Access was either not enabled or was intentionally disabled.
3. No monitoring or alerting was in place to detect the exposed bucket.
4. The exposure lasted months to years before discovery.

**Answer the questions below**

> What AWS S3 security control would have partially prevented the security incidents described in the task?
> 

Block Public Access

### Task 3 - Identification

In this task, you will find the misconfiguration using common AWS CLI commands. You can also navigate the AWS Console, but in practice, it is better to become familiar with the standard AWS commands. They serve both for targeted verification and for automation.

**Quick Recap**

| **Layer** | **What it controls** | **Overridden by** |
| --- | --- | --- |
| **Access Control List** | Who can list/read the bucket and objects | Block Public Access |
| **Bucket Policy** | Fine-grained access rules (per-action, per-principal) | Block Public Access |
| **Block Public Access** | Account-level or bucket-level switch that blocks all public access | None |

**Identify the Bucket:** First, find your bucket.

![Find the leaky bucket](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1773821931011.png)

```bash
$ aws s3api list-buckets --query "Buckets[?contains(Name, 'leaky')].Name" --output text

leaky-bucket-326089725134-us-east-1
```

**Note:** For practicality, you can save the bucket name in an environment variable.

```bash
$ export BUCKET_NAME=$(aws s3api list-buckets --query \
"Buckets[?contains(Name, 'leaky')].Name" --output text)

$ echo $BUCKET_NAME

leaky-bucket-326089725134-us-east-1
```

**Check Bucket Configuration:** In a legacy context, you can check and confirm ACLs are active. Nowadays, `BucketOwnerEnforced` is the default ownership control, and it disables ACLs entirely.

```bash
$ aws s3api get-bucket-ownership-controls --bucket $BUCKET_NAME

{
    "OwnershipControls": {
        "Rules": [
            {
                "ObjectOwnership": "BucketOwnerPreferred"
            }
        ]
    }
}
```

**FINDING:** `BucketOwnerPreferred` means ACLs are active for this bucket. 

Next, check the public access settings.

```bash
$ aws s3api get-public-access-block --bucket $BUCKET_NAME

{
    "PublicAccessBlockConfiguration": {
        "BlockPublicAcls": false,
        "IgnorePublicAcls": false,
        "BlockPublicPolicy": false,
        "RestrictPublicBuckets": false
    }
}
```

**FINDING:** All four settings show as false; this is bad.

An additional check should also be done at the account level, as this can still override the bucket-level configuration.

**Note:** The Account ID is saved in another environment variable for convenience.

```bash
$ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

$ echo $ACCOUNT_ID

326089725134
```

```bash
$ aws s3control get-public-access-block --account-id $ACCOUNT_ID

{
    "PublicAccessBlockConfiguration": {
        "BlockPublicAcls": false,
        "IgnorePublicAcls": false,
        "BlockPublicPolicy": false,
        "RestrictPublicBuckets": false
    }
}
```

**FINDING:** You see the same pattern here, too; this needs fixing.

Now, check the bucket policy.

```bash
$ aws s3api get-bucket-policy --bucket $BUCKET_NAME --query Policy --output text

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PublicGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::leaky-bucket-326089725134-us-east-1/*"
        }
    ]
}
```

**FINDING:** The policy allows `GetObject` for any principal. Combined with the previous findings, it means anyone on the internet can see the information stored in the bucket.

**Verify**

You can actually check this by opening one of the bucket's object links in a private browser window.

You can also check the ACLs. As mentioned, this is a legacy mechanism, but good for understanding each control layer.

```bash
$ aws s3api get-bucket-acl --bucket $BUCKET_NAME

{
    "Owner": {
        "ID": "ee363028c9a71f57dd5d6cf5fdb2efa56609b9aec91fd5e360e017fa61eb7aec"
    },
    "Grants": [
        {
            "Grantee": {
                "ID": "ee363028c9a71f57dd5d6cf5fdb2efa56609b9aec91fd5e360e017fa61eb7aec",
                "Type": "CanonicalUser"
            },
            "Permission": "FULL_CONTROL"
        },
        {
            "Grantee": {
                "Type": "Group",
                "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
            },
            "Permission": "READ"
        }
    ]
}
```

**FINDING:** Any grant on `AllUsers` or `AuthenticatedUsers` indicates a public ACL grant.

What an attacker would do, and you can check, is list bucket objects without any credentials.

```bash
$ aws s3 ls s3://$BUCKET_NAME/ --no-sign-request

                           PRE customer-records/
2026-03-17 07:12:27         25 flag.txt
2026-03-17 07:12:28        164 sample-data.txt
```

**Retrieve the Flag:** Lastly, you (and anyone) on the internet can grab the flag.

```bash
$ aws s3 cp s3://$BUCKET_NAME/flag.txt - --no-sign-request

[REDACTED]
```

**Findings Summary**

You have seen the tell-tales of a "leaky bucket":

- All four settings for blocking public access are set to `false`.
- The attached policy is too broad, allowing anyone access to the bucket.
- Grants on `AllUsers` that indicate a public ACL grant.

**Answer the questions below**

> What is the flag from the publicly exposed S3 object?
> 

THM{CARL_MESSED_UP_AGAIN}

> Besides the flag file, what other file is exposed (extension included) in the customer-records object?
> 

export.csv

Run the query below:

```
 aws s3 ls s3://$BUCKET_NAME/customer-records/ --no-sign-request 2026-11-02 15:32:43        
 139 export.csv
```

### Task 4 - Remediation

Alright, it seems the rumors were true, and Carl did make the bucket public. It is time to undo the change before it is too late.

**Block Public Access:** Start by blocking public access.

![Find the Block public access bucket settings and click edit, and change the settings to block public access.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1782479970977.png)

```bash
$ aws s3api put-public-access-block \
    --bucket $BUCKET_NAME \
    --public-access-block-configuration \
"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

Verify that all four values are now set to `true`.

```bash
$ aws s3api get-public-access-block --bucket $BUCKET_NAME

{
    "PublicAccessBlockConfiguration": {
        "BlockPublicAcls": true,
        "IgnorePublicAcls": true,
        "BlockPublicPolicy": true,
        "RestrictPublicBuckets": true
    }
}
```

**Remove Bucket Policy:** Next, remove the wildcard principal by removing the bucket policy.

```bash
$ aws s3api delete-bucket-policy --bucket $BUCKET_NAME
```

Verify that the policy was removed.

```bash
$ aws s3api get-bucket-policy --bucket $BUCKET_NAME

aws: [ERROR]: An error occurred ([REDACTED]) when calling the GetBucketPolicy operation: The bucket policy does not exist

Additional error details:
BucketName: leaky-bucket-326089725134-us-east-1
```

**Note:** This command should throw an error if the previous step was done correctly.

**Reset ACL:** Now, reset ACL to private.

```bash
$ aws s3api put-bucket-acl --bucket $BUCKET_NAME --acl private
```

Try the unauthenticated access again. You should see `Access Denied` in the response.

```bash
$ curl -s "https://$BUCKET_NAME.s3.amazonaws.com/flag.txt"

<?xml version="1.0" encoding="UTF-8"?>
<Error>
	<Code>
		AccessDenied
[...]
```

You can also check that authenticated access still works.

```bash
$ aws s3 cp s3://$BUCKET_NAME/flag.txt -

[REDACTED]
```

**Verify:** This exercise also has a Lambda function that checks if the remediation was implemented correctly.

Run the Lambda function and, if you remediated the misconfiguration, the function will seed the flag and provide the command to retrieve it.

```bash
$ aws lambda invoke --function-name AWS501-VerifyRemediation \
--cli-binary-format raw-in-base64-out --payload '{}' /tmp/out.json \
&& python3 -m json.tool /tmp/out.json

{
    "status": "COMPLETE",
    "message": "All checks passed. Retrieve your flag with:",
    "command": "[REDACTED]",
    "checks": {
        "block_public_access": "PASS",
        "bucket_policy": "PASS (no policy)",
        "bucket_acl": "PASS"
    }
}
```

**Answer the questions below**

> What is the error shown when verifying the bucket policy was removed?
> 

NoSuchBucketPolicy

When calling the GetBucketPolicy operation it says NoSuchBucketPolicy

> What is the flag found after remediating the misconfiguration?
> 

THM{LOCKED_DOWN_AND_PRIVATE}

Run the query below: 

```
aws s3 cp s3://leaky-bucket-083971419833-us-east-1/flag-task4.txt -
```

### Task 5 - Build It Securely

Most of the time, you will run security audits, monitoring, remediation, and mitigation on already configured infrastructures. As a practical exercise, it can also be useful to understand how to deploy securely from day one.

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

**Note:** You will also create a logging bucket in parallel, which will be used later.

**Create the Bucket:** Start by creating a bucket. The pre-command will ensure the bucket name is unique and saved in a variable. You will need it to validate the build.

```bash
$ export SECURE_BUCKET="secure-bucket-$(aws sts get-caller-identity --query Account --output text)-$(date +%s)"

$ aws s3api create-bucket --bucket $SECURE_BUCKET --region us-east-1

{
    "Location": "/secure-bucket-160369836820-1773828689",
    "BucketArn": "arn:aws:s3:::secure-bucket-160369836820-1773828689"
}

$ export LOGGING_BUCKET="s3-access-logs-$(aws sts get-caller-identity --query Account --output text)"

$ aws s3api create-bucket --bucket $LOGGING_BUCKET --region us-east-1

{
    "Location": "/s3-access-logs-160369836820",
    "BucketArn": "arn:aws:s3:::s3-access-logs-160369836820"
}
```

Next, enable Block Public Access.

```bash
$ aws s3api put-public-access-block \
    --bucket $SECURE_BUCKET \
    --public-access-block-configuration \
"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

$ aws s3api put-public-access-block \
  --bucket $LOGGING_BUCKET \
  --public-access-block-configuration \
"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

**Note:** AWS enables this by default, but this step ensures no stone is left unturned. Then, disable ACLs entirely.

```bash
$ aws s3api put-bucket-ownership-controls \
  --bucket $SECURE_BUCKET \
  --ownership-controls '{"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}'

$ aws s3api put-public-access-block \
  --bucket $LOGGING_BUCKET \
  --public-access-block-configuration \
"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

**Attach Scoped Policy:** Now, attach a bucket policy that grants access only to specific principals.

```bash
$ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

$ cat > /tmp/secure-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyNonTLS",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::$SECURE_BUCKET",
                "arn:aws:s3:::$SECURE_BUCKET/*"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        }
    ]
}
EOF

$ aws s3api put-bucket-policy --bucket $SECURE_BUCKET --policy file:///tmp/secure-policy.json
```

For the logging bucket, attach a specific policy that grants access only to the logging service.

```bash
$ cat > /tmp/log-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "S3ServerAccessLogsPolicy",
            "Effect": "Allow",
            "Principal": {"Service": "logging.s3.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::$LOGGING_BUCKET/*",
            "Condition": {"StringEquals": {"aws:SourceAccount": "$(aws sts get-caller-identity --query Account --output text)"}}
        }
    ]
}
EOF

$ aws s3api put-bucket-policy --bucket $LOGGING_BUCKET --policy file:///tmp/log-policy.json
```

Enable account-level prevention against buckets being made public.

```bash
$ aws s3control put-public-access-block \
    --account-id $ACCOUNT_ID \
    --public-access-block-configuration \
"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

It's very important to create the logging bucket as well.

```bash
$ aws s3api put-bucket-logging \
    --bucket $SECURE_BUCKET \
    --bucket-logging-status "{\"LoggingEnabled\":{\"TargetBucket\":\"$LOGGING_BUCKET\",\"TargetPrefix\":\"$SECURE_BUCKET/\"}}"
```

**Verify:** Run the Lambda verification function to validate the setup and retrieve the flag.

```bash
$ aws lambda invoke \
    --function-name AWS501-VerifySecureBuild \
    --cli-binary-format raw-in-base64-out \
    --payload "{\"bucket\":\"$SECURE_BUCKET\"}" /tmp/out.json \
    && python3 -m json.tool /tmp/out.json

[...]
{
    "status": "COMPLETE",
    "message": "All checks passed.",
    "flag": "[REDACTED]",
    "checks": {
        "block_public_access": "PASS",
        "acls_disabled": "PASS",
        "tls_deny_policy": "PASS",
        "access_logging": "PASS"
    }
}
```

**Answer the questions below**

> What is the flag revealed by the Lambda checker function?
> 

THM{SECURED_FROM_DAY_ONE}

### Task 6 - Conclusion

Identified a leaky bucket, remediated the misconfiguration, and learned how to build it securely.

**Key Takeaways**

- Enable S3 Block Public Access at the account level as a default baseline.
- Granting a wildcard principal should be an edge case, not the rule.
- Disable ACLs by using BucketOwnerEnforced on all new buckets.
- Block Public Access overrides ACLs and bucket policies, but the latter do surface if BPA is disabled.
- Monitor for public buckets regularly.

AWS provides additional help in your efforts to make it harder to publicly expose buckets, as well as through security tools like IAM Access Analyzer and AWS Config.
