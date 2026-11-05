# AWS Security 5.3. The Blind Bucket

### Task 1 - Introduction

S3 access logging is one of the most frequently missed security controls in AWS deployments. It is not enabled by default on new buckets, and CloudTrail does not log S3 data events by default. This leaves a blind spot for any S3 activity, but by the end of this room, you will be able to shed some light on it.

### Task 2 - Real-World Incident

In April 2018, a former Chegg contractor used shared AWS root credentials to download the personal data of 40 million users from S3. The breach went completely undetected for five months - until a threat intelligence vendor found 25 million of those passwords on an underground forum.

Chegg is a US-based education technology company offering textbook rentals, tutoring services, and scholarship search tools. They stored sensitive customer data in AWS S3 buckets.

**What Happened**

![Attack chain for unmonitored S3 activity.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1781513127615.png)

1. **Credential Access**: A former Chegg contractor retained access to shared AWS root credentials after their engagement ended.
2. **S3 Enumeration**: Using the root credentials, the former contractor explored Chegg's S3 environment. Because S3 data events were not enabled, no record of this enumeration existed in Chegg's CloudTrail logs.
3. **Mass Exfiltration**: The attacker downloaded approximately 40 million user records, including names, email addresses, hashed passwords, and sensitive scholarship application data.
4. **Five-month Blind Spot**: The exfiltration occurred in April 2018. Chegg's security team detected nothing. No internal alert fired. The breach remained completely unknown for five months.
5. **External Discovery**: In September 2018, a threat intelligence vendor notified Chegg that approximately 25 million plaintext passwords originating from Chegg's database were circulating on an underground forum.
6. **FTC Enforcement**: The FTC filed a complaint against Chegg, citing it for failing to monitor its networks for unauthorized attempts to exfiltrate personal information.

**Core Failures**

- **No S3 data event logging**: CloudTrail management events do not capture GetObject, PutObject, or DeleteObject. Without data events enabled, the bulk download left no trace. CloudTrail S3 data events would have recorded each GetObject call - including the access key ID, source IP, user agent, and timestamp.
- **Shared root credentials**: AWS root credentials carry unrestricted permissions and cannot be scoped by IAM policy. Issuing them to contractors and failing to revoke them after engagement created a persistent high-privilege access path.
- **No detection for five months**: The combination of root credential misuse and absent data-event logging created a complete blind spot. Even a basic alert on root account API activity outside normal operational hours would have flagged the April 2018 access.

### Task 3 - Identification

You are preparing to perform a security audit on a customer's data store. The customer holds their data mainly in S3 buckets. The buckets are not public, ACLs are disabled.

**Set the Environment Variables:** First, set up the required environment variables.

```bash
$ export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

$ export BUCKET_NAME="thm-blind-bucket-${ACCOUNT_ID}"

$ export TRAIL_NAME=$(aws cloudtrail describe-trails \
    --query "trailList[?Name=='room53-management-trail'].Name" \
    --output text)

$ export LOG_GROUP=$(aws logs describe-log-groups \
    --query "logGroups[?contains(logGroupName, '/aws/cloudtrail/room53/')].logGroupName" \
    --output text)

$ echo "Account ID: $ACCOUNT_ID Bucket: $BUCKET_NAME Trail: $TRAIL_NAME Log group: $LOG_GROUP"

Account ID: 154989417305 Bucket: thm-blind-bucket-154989417305 Trail: room53-management-trail Log group: /aws/cloudtrail/room53/154989417305
```

**Find the Bucket:** Next, list the buckets and identify the lab bucket.

![Lab buckets.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1775121771996.png)

```bash
$ aws s3api list-buckets \
    --query "Buckets[?contains(Name,'thm-blind-bucket')].Name" \
    --output table

----------------------------------------
|              ListBuckets             |
+--------------------------------------+
|  thm-blind-bucket-154989417305       |
|  thm-blind-bucket-logs-154989417305  |
+--------------------------------------+
```

You can grab the flag from the S3 bucket; let's see if anyone notices.

```bash
$ aws s3 ls s3://$BUCKET_NAME/

                           PRE activity-log/
                           PRE backups/
                           PRE financial-reports/
2026-04-01 16:17:07         23 flag.txt$ aws s3 cp s3://$BUCKET_NAME/flag.txt -

[REDACTED]
```

**Check S3 Server Access Log:** Now, check whether S3 server access logging is configured.

```bash
$ aws s3api get-bucket-logging --bucket $BUCKET_NAME
```

**FINDING:** No output indicates the server access logging is not configured on this bucket. No HTTP request to objects is tracked.

**Check CloudTrail:** There is a CloudTrail trail configured, so let's see if anything is logged there.

First, identify the lab trail.

```bash
$ aws cloudtrail describe-trails \
    --query "trailList[*].{Name:Name,HomeRegion:HomeRegion,S3Bucket:S3BucketName}" \
    --output table
-----------------------------------------------------------------------------------
|                                  DescribeTrails                                 |
+------------+---------------------------+----------------------------------------+
| HomeRegion |           Name            |                S3Bucket                |
+------------+---------------------------+----------------------------------------+
|  us-east-1 |  room53-management-trail  |  thm-trail-room53-154989417305         |
[...]
```

Check the configured resources for the trail.

```bash
$ aws cloudtrail get-event-selectors --trail-name $TRAIL_NAME

{
    "TrailARN": "arn:aws:cloudtrail:us-east-1:154989417305:trail/room53-management-trail",
    "EventSelectors": [
        {
            "ReadWriteType": "[REDACTED]",
            "IncludeManagementEvents": true,
            "DataResources": [],
            "ExcludeManagementEventSources": []
        }
    ]
}
```

**FINDING:** `DataResources: []` means no S3 data events are being captured.

You can also check the recent events history in CloudTrail.

```bash
$ aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventSource,AttributeValue=s3.amazonaws.com \
    --max-results 20 \
    --query "Events[*].{Time:EventTime,Name:EventName,User:Username}" \
    --output table

----------------------------------------------------------------------------------
|                                 LookupEvents                                   |
+----------------------------------+-----------------------------+---------------+
|               Name               |            Time             |     User      |
+----------------------------------+-----------------------------+---------------+
|  GetBucketOwnershipControls      |  2026-04-02T09:11:29+00:00  |  154989417305 |
|  GetBucketVersioning             |  2026-04-02T09:11:28+00:00  |  154989417305 |
|  GetBucketObjectLockConfiguration|  2026-04-02T09:11:28+00:00  |  154989417305 |
[...]
```

**FINDING:** You will see only management-related events here, so no S3 activity.

Try querying the CloudWatch Logs group directly.

```bash
$ START_TIME=$(( $(date +%s) - 900 ))

$ END_TIME=$(date +%s)

$ QUERY_STRING='fields @timestamp, eventName, userIdentity.arn, requestParameters.key
    | filter eventSource = "s3.amazonaws.com"
    and requestParameters.bucketName = "'"$BUCKET_NAME"'"
    and eventName in ["GetObject", "PutObject", "DeleteObject"]
    | sort @timestamp desc
    | limit 20'

$ QUERY_ID=$(aws logs start-query \
    --log-group-name "$LOG_GROUP" \
    --start-time $START_TIME \
    --end-time $END_TIME \
    --query-string "$QUERY_STRING" \
    --query queryId \
    --output text)
```

Give it a couple of seconds, and check the query result.

```bash
$ aws logs get-query-results --query-id "$QUERY_ID"

{
    "queryLanguage": "[REDACTED]",
    "results": [],
    "statistics": {
        "recordsMatched": 0.0,
        "recordsScanned": 0.0,
        "estimatedRecordsSkipped": 30.0,
        "bytesScanned": 0.0,
        "estimatedBytesSkipped": 46341.0,
        "logGroupsScanned": 1.0
    },
    "status": "Complete"
}
```

**FINDING:** No results here either.

**Key Notes**

| **Feature** | **S3 Server Access Logs** | **CloudTrail S3 Data Events** |
| --- | --- | --- |
| **What it records** | Every HTTP request to the bucket | API-level data operations (e.g. GetObject, PutObject) |
| **Delivery latency** | Minutes to hours | ~15 minutes |
| **Format** | Space-separated log lines | JSON |
| **IAM identity** | Not included (just IP/user-agent) | Yes (full ARN of the caller) |
| **Integration** | S3 prefix search | CloudWatch Logs, Insights, Athena, GuardDuty |

It is a good practice to enable both; the server access logs provide detailed per-request records, while CloudTrail data events provide IAM context and integration for security monitoring.

Here is what you have so far:

- S3 Server Access Logs are not configured.
- CloudTrail S3 Data events are not captured.
- Overall S3 activity is not monitored.

There is a blind spot for this bucket.

**Answer the questions below**

> In the CloudTrail event selector output, what type of read/write activities are tracked?
> 

All

<img width="738" height="210" alt="image" src="https://github.com/user-attachments/assets/77d14e58-38b7-4319-8d66-75a2ab95a6a1" />


> What is the flag stored in the S3 text file?
> 

THM{LET_THE_HUNT_BEGIN}

### Task 4 - Remediation

You have identified the blind spot; now it is time to enable logging. 

**Enable CloudTrail S3 Data Events:** You will start with the CloudTrail data events. Run this command to enable trail logging for them.

```bash
$ aws cloudtrail put-event-selectors \
      --trail-name $TRAIL_NAME \
      --event-selectors "[
      {
        \"ReadWriteType\": \"All\",
        \"IncludeManagementEvents\": true,
        \"DataResources\": [
          {
            \"Type\": \"AWS::S3::Object\",
            \"Values\": [\"arn:aws:s3:::${BUCKET_NAME}/\"]
          }
        ]
      }
    ]"

{
    "TrailARN": "arn:aws:cloudtrail:us-east-1:154989417305:trail/room53-management-trail",
    "EventSelectors": [
        {
            "ReadWriteType": "All",
            "IncludeManagementEvents": true,
            "DataResources": [
                {
                    "Type": "AWS::S3::Object",
                    "Values": [
                        "arn:aws:s3:::thm-blind-bucket-154989417305/"
                    ]
                }
            ],
            "ExcludeManagementEventSources": []
        }
    ]
}
```

Now check that the event selector is configured.

```bash
$ aws cloudtrail get-event-selectors --trail-name $TRAIL_NAME

{
    "TrailARN": "arn:aws:cloudtrail:us-east-1:154989417305:trail/room53-management-trail",
    "EventSelectors": [
        {
            "ReadWriteType": "All",
            "IncludeManagementEvents": true,
            "DataResources": [
                {
                    "Type": "AWS::S3::Object",
                    "Values": [
                        "arn:aws:s3:::thm-blind-bucket-154989417305/"
                    ]
                }
            ],
            "ExcludeManagementEventSources": []
        }
    ]
}
```

Try to grab the flag again.

```bash
$ aws s3 cp s3://$BUCKET_NAME/flag.txt -

[REDACTED]
```

Alternatively, you can skip to the next section and, once you finish the next section, run the commands here.

```bash
$ START_TIME=$(( $(date +%s) - 900 ))

$ END_TIME=$(date +%s)

$ QUERY_STRING='fields @timestamp, eventName, userIdentity.arn, requestParameters.key
| filter eventSource = "s3.amazonaws.com"
    and requestParameters.bucketName = "'"$BUCKET_NAME"'"
    and eventName in ["GetObject", "PutObject", "DeleteObject"]
| sort @timestamp desc
| limit 20'

$ QUERY_ID=$(aws logs start-query \
  --log-group-name "$LOG_GROUP" \
  --start-time $START_TIME \
  --end-time $END_TIME \
  --query-string "$QUERY_STRING" \
  --query queryId \
  --output text)
```

Then check the query output.

```bash
$ aws logs get-query-results --query-id "$QUERY_ID"

{
    "queryLanguage": "[REDACTED]",
    "results": [
        [
            {
                "field": "@timestamp",
                "value": "2026-04-02 09:34:47.728"
            },
            {
                "field": "eventName",
                "value": "GetObject"
            },
            {
                "field": "userIdentity.arn",
                "value": "arn:aws:iam::154989417305:user/154989417305"
            },
            {
                "field": "requestParameters.key",
                "value": "flag.txt"
            },
            {
                "field": "@ptr",
                "value": "[...]"
            }
        ]
    ],
    "statistics": {
        "recordsMatched": 2.0,
        "recordsScanned": 4.0,
        "estimatedRecordsSkipped": 21.0,
        "bytesScanned": 7988.0,
        "estimatedBytesSkipped": 33797.0,
        "logGroupsScanned": 1.0
    },
    "status": "Complete"
}
```

**Enable S3 Server Access Logging:** The trail is live, but you can do better. You can start by storing the lab logging bucket so the next commands are easier to follow.

```bash
$ export LOGGING_BUCKET="thm-blind-bucket-logs-${ACCOUNT_ID}"
```

Enable the logging on the data bucket.

```bash
$ aws s3api put-bucket-logging \
    --bucket $BUCKET_NAME \
    --bucket-logging-status "{
      \"LoggingEnabled\": {
        \"TargetBucket\": \"$LOGGING_BUCKET\",
        \"TargetPrefix\": \"${BUCKET_NAME}/\"
      }
    }"
```

Then, verify the configuration.

```bash
$ aws s3api get-bucket-logging --bucket $BUCKET_NAME

{
    "LoggingEnabled": {
        "TargetBucket": "thm-blind-bucket-logs-154989417305",
        "TargetPrefix": "thm-blind-bucket-154989417305/"
    }
}
```

**Verify:** Now, run the helper Lambda function to retrive the flag.

```bash
$ aws lambda invoke \
    --function-name AWS503-VerifyRemediation \
    --cli-binary-format raw-in-base64-out \
    --payload '{}' /tmp/out.json \
    && python3 -m json.tool /tmp/out.json

[...]
{
    "cloudtrail_data_events": "PASS - CloudTrail data events enabled for thm-blind-bucket-154989417305",
    "server_access_logging": "PASS - server access logging enabled (target: thm-blind-bucket-logs-154989417305)",
    "status": "PASS",
    "flag": "[REDACTED]"
}
```

Now you have visibility.

**Answer the questions below**

> What is the short name for the query language used?
> 

CWLI

<img width="412" height="255" alt="image 1" src="https://github.com/user-attachments/assets/d284e25e-11cf-4f4d-9cab-574851dfe7bd" />


> What is the flag found after remediating the misconfiguration?
> 

THM{NOW_EVERYTHING_IS_VISIBLE}

### Task 5 - Build It Securely

You’ll now build a fully monitored S3 deployment from scratch to understand how you would securely approach this from day one. For simplicity, you will reuse the lab CloudTrail trail, but in a production deployment, you would add the trail configuration step before the ones presented below.

**Create the Buckets:** First, create your logging and data buckets. They will be saved as environment variables for later use.

```bash
$ LOG_BUCKET="s3-data-logs-${ACCOUNT_ID}-$(date +%s)"

$ DATA_BUCKET="s3-monitored-data-${ACCOUNT_ID}-$(date +%s)"

$ aws s3api create-bucket --bucket $LOG_BUCKET --region us-east-1

{
    "Location": "/s3-data-logs-154989417305-1775124082",
    "BucketArn": "arn:aws:s3:::s3-data-logs-154989417305-1775124082"
}$ aws s3api create-bucket --bucket $DATA_BUCKET --region us-east-1

{
    "Location": "/s3-monitored-data-154989417305-1775124083",
    "BucketArn": "arn:aws:s3:::s3-monitored-data-154989417305-1775124083"
}
```

**Secure the Buckets:** Next, block public access to the buckets.

```bash
$ aws s3api put-public-access-block \
  --bucket $LOG_BUCKET \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

$ aws s3api put-public-access-block \
  --bucket $DATA_BUCKET \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

Then, ensure ownership control is enforced.

```bash
$ aws s3api put-bucket-ownership-controls \
  --bucket $LOG_BUCKET \
  --ownership-controls '{"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}'

$ aws s3api put-bucket-ownership-controls \
  --bucket $DATA_BUCKET \
  --ownership-controls '{"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}'
```

Ensure encryption is enabled.

```bash
$ aws s3api put-bucket-encryption \
  --bucket $LOG_BUCKET \
  --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

$ aws s3api put-bucket-encryption \
  --bucket $DATA_BUCKET \
  --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
```

**Enable Logging:** Add a logging policy to the logging bucket.

```bash
$ cat > ./log-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "S3ServerAccessLogsPolicy",
            "Effect": "Allow",
            "Principal": {"Service": "logging.s3.amazonaws.com"},
            "Action": ["s3:PutObject"],
            "Resource": "arn:aws:s3:::$LOG_BUCKET/*",
            "Condition": {
                "StringEquals": {"aws:SourceAccount": "$ACCOUNT_ID"}
            }
        }
    ]
}
EOF

$ aws s3api put-bucket-policy --bucket $LOG_BUCKET --policy file://log-policy.json
```

Now, enable logging on the data bucket.

```bash
$ export TRAIL_NAME=$(aws cloudtrail describe-trails \
    --query "trailList[?Name=='room53-management-trail'].Name" \
    --output text)

$ aws s3api put-bucket-logging \
  --bucket $DATA_BUCKET \
  --bucket-logging-status "{
    \"LoggingEnabled\": {
      \"TargetBucket\": \"$LOG_BUCKET\",
      \"TargetPrefix\": \"${DATA_BUCKET}/\"
    }
  }"

$ aws cloudtrail put-event-selectors \
  --trail-name $TRAIL_NAME \
  --event-selectors "[
    {
      \"ReadWriteType\": \"All\",
      \"IncludeManagementEvents\": true,
      \"DataResources\": [
        {
          \"Type\": \"AWS::S3::Object\",
          \"Values\": [\"arn:aws:s3:::${DATA_BUCKET}/\"]
        }
      ]
    }
  ]"

{
    "TrailARN": "arn:aws:cloudtrail:us-east-1:154989417305:trail/room53-management-trail",
    "EventSelectors": [
        {
            "ReadWriteType": "All",
[...]
```

**Verify:** Lastly, you can run the helper Lambda function to validate the setup and retrieve the flag.

```bash
$ aws lambda invoke \
    --function-name AWS503-VerifySecureBuild \
    --cli-binary-format raw-in-base64-out \
    --payload '{}' /tmp/out.json \
    && python3 -m json.tool /tmp/out.json

[...]
{
    "bucket_found": "s3-monitored-data-154989417305-1775124083",
    "cloudtrail_data_events": "PASS - CloudTrail data events enabled for s3-monitored-data-154989417305-1775124083",
    "server_access_logging": "PASS - server access logging enabled (target: s3-data-logs-154989417305-1775124082)",
    "status": "PASS",
    "flag": "[REDACTED]"
}
```

**Useful Queries**

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

**Note:** As of June 15, 2026, AWS officially rolled out Log Analytics as a unified console experience. If the AWS account defaults to Log Analytics, use the `Preferences` button on the top-right of the service and disable `Opt in to Log Analytics`. Once done, you can navigate to Logs Insights.

![CloudWatch and where to run the queries.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1775125907988.png)

Open Logs Insights and run any of the following queries.

![Select the log trail, input the query, run the query, and analyze the results.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1775125907353.png)

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

**Note:** Not all queries will return results, even with a wider timeframe.

Top principals by read volume:

```bash
fields @timestamp, userIdentity.arn, requestParameters.bucketName
	| filter eventSource = "s3.amazonaws.com" and eventName = "GetObject"
	| stats count() as reads by userIdentity.arn
	| sort reads desc
	| limit 20
```

High-volume reads by a single principal:

```bash
fields @timestamp, userIdentity.arn
	| filter eventSource = "s3.amazonaws.com" and eventName = "GetObject"
	| stats count() as reads by userIdentity.arn, bin(5m)
	| filter reads > 100
	| sort @timestamp desc
```

Access to specific sensitive path prefixes:

```bash
fields @timestamp, userIdentity.arn, requestParameters.key
	| filter eventSource = "s3.amazonaws.com"
		and eventName in ["GetObject","DeleteObject"]
		and requestParameters.bucketName = "$DATA_BUCKET"
		and requestParameters.key like /[REPLACE WITH SENSITIVE PREFIX]\\//
	| sort @timestamp desc
```

First-time access to a bucket:

```bash
fields @timestamp, userIdentity.arn, requestParameters.bucketName
	| filter eventSource = "s3.amazonaws.com" and eventName = "GetObject"
	| sort @timestamp asc
	| dedup userIdentity.arn, requestParameters.bucketName
```

**Answer the questions below**

> What is the flag revealed by the helper Lambda function?
> 

THM{YOU_ARE_NOW_PREPARED}

### Task 6 - Conclusion

In this room, you have gone from a completely blind bucket to a fully monitored one. Here is what to carry forward.

**Key Takeaways**

- CloudTrail does not log S3 data events by default. You must explicitly add data event selectors for each bucket (or all buckets). Without this, GetObject and PutObject operations are completely invisible in CloudTrail.
- Enable CloudTrail S3 data events for every bucket containing sensitive or important data. Treat the absence of data event logging as a misconfiguration, not an optional configuration.
- S3 server access logging complements CloudTrail data events. Server logs give you per-request HTTP details. CloudTrail provides IAM identity context and integration with security tools. You want both for sensitive data.
- Logs are useless if nobody queries them. Enable logging, then build detection queries for bulk reads, anomalous principals, and sensitive-path access. Run them regularly or automate with CloudWatch Alarms.
- GuardDuty uses CloudTrail S3 data events. If you enable GuardDuty S3 Protection, CloudTrail data events must be enabled. Without them, GuardDuty cannot detect exfiltration patterns for S3 data.
- This is a current operational risk, not a legacy edge case. A bucket can have strong access controls and still be dangerously blind if object-level visibility is missing.
