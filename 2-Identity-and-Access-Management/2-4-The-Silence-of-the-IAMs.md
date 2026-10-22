# AWS Security 2.4. The Silence of the IAMs

### Task 1 - Introduction

An attacker gains a foothold in your AWS account. Maybe through leaked access keys, maybe through an application vulnerability. One of the steps an attacker would take next is to ensure persistence.

In AWS, persistence often looks like an IAM change: a new access key created, an over-permissive policy attached to a low-privilege identity, or a new IAM user created. This room focuses on that blind spot and ensures you have the right knowledge to tackle this from day one.

### Task 2 - Real-World Incident

There are many real-world examples of how a lack of monitoring led to major security incidents. Let us have a look at what happened to Ubiquiti in late 2020.

Ubiquiti Networks is a US-based tech company producing wireless networking and IoT devices, including UniFi. Like many companies, Ubiquiti runs its development platforms, source repos, and operational secrets on AWS and GitHub. Employees had broad AWS permissions to the management infrastructure, and although CloudTrail was enabled, no automated alerting or active monitoring was in place.

![Attack chain for the Ubiquiti incident.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1781259445933.png)

1. **Credential Abuse** - A senior software engineer used his own employee credentials to access an administrative key stored in the AWS infrastructure. Minutes later, those credentials were used from a Surfshark VPN IP.
2. **Data Theft** - During the next two weeks, the engineer cloned over 1,000 GitHub repositories, extracted dozens of secret files from AWS Secrets Manager, and downloaded more than 1400 AWS configuration files.
3. **Log Tampering** - To hide his activity, he reduced AWS CloudWatch log retention policies to one day, ensuring records would auto-delete before anyone could review them.
4. **Extortion Attempt** - A few weeks later, posting as an anonymous external hacker, the engineer sent Ubiquiti a ransom demand in exchange for the stolen data.
5. **Discovery** - The engineer was caught by an accidental VPN disconnect during a cloning session. During that brief window, his real home IP appeared in the repository access log. The engineer was arrested and sentenced to six years in a federal prison.

**Core Failures**

- **No alerts on high-risk IAM calls** - Without deterministic alerts on privilege-escalating calls, the engineer's activity was indistinguishable from normal operations.
- **Undetected log tampering** - Modifying CloudWatch log retention is a sensitive operation that requires at least alerting and change tracking.
- **Secrets Manager access** - Data-plane monitoring and anomaly alerts on bulk secrets access should have flagged the activity as a high-severity incident early in the attack.

**Answer the questions below**

> What did the attacker do to remove evidence of his activity?
> 

Log Tampering (The unauthorized modification or deletion of AWS audit logs and retention settings to hide malicious activity.)

### Task 3 - Identification

First things first, open `CloudShell` or use the AWS CLI with the provided credentials, and save the account ID.

```bash
$ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

$ echo $ACCOUNT_ID

569945792897
```

**Check CloudTrail:** Before you investigate, identify the CloudTrail trail in the account.

```bash
$ aws cloudtrail describe-trails \
    --query "trailList[*].{Name:Name,IsMultiRegion:IsMultiRegionTrail,HomeRegion:HomeRegion,GlobalEvents:IncludeGlobalServiceEvents}" \
    --output table

--------------------------------------------------------------------
|                          DescribeTrails                          |
+--------------+-------------+-----------------+-------------------+
| GlobalEvents | HomeRegion  |  IsMultiRegion  |       Name        |
+--------------+-------------+-----------------+-------------------+
|  True        |  us-east-1  |  False          |  lab-audit-trail  |
|  True        |  us-east-1  |  True           |  thm-org-trail    |
+--------------+-------------+-----------------+-------------------+
```

Confirm the trail is actively logging. Make sure you match the `lab-audit-trail` in the command. If the trails are shown in a different order, make sure you change the `0` in the command below to the appropriate trail index.

```bash
$ TRAIL_NAME=$(aws cloudtrail describe-trails \
    --query "trailList[0].Name" --output text)

$ aws cloudtrail get-trail-status --name $TRAIL_NAME

{
    "IsLogging": true,
    "LatestDeliveryTime": "2026-03-30T08:40:33.806000+00:00",
    "StartLoggingTime": "2026-03-24T09:41:38.402000+00:00",
    "LatestCloudWatchLogsDeliveryTime": "2026-03-30T09:28:07.702000+00:00",
    "LatestDigestDeliveryTime": "2026-03-30T08:51:05.164000+00:00",
    "LatestDeliveryAttemptTime": "2026-03-30T08:40:33Z",
    "LatestNotificationAttemptTime": "",
    "LatestNotificationAttemptSucceeded": "",
    "LatestDeliveryAttemptSucceeded": "2026-03-30T08:40:33Z",
    "TimeLoggingStarted": "2026-03-24T09:41:38Z",
    "TimeLoggingStopped": ""
}
```

**FINDING:** CloudTrail logging is confirmed by `IsLogging: true`

**Understand High-Risk IAM Events:** Some IAM events are routine read operations, while others are high-risk write operations that can lead to privilege escalation. Here is a handful of risky operations to watch out for.

| **Event Name** | **Risk** | **Why** |
| --- | --- | --- |
| **AttachUserPolicy** | Critical | Attaching a managed policy (like AdministratorAccess) grants immediate privilege escalation. |
| **AttachRolePolicy** | Critical | Similarly, privilege escalation is granted through roles. |
| **PutUserPolicy** | Critical | Creating an inline policy for a user makes it harder to discover. |
| **CreateUser** | High | A new IAM user can be a sign of a persistence attempt. |
| **CreateAccessKey** | High | New programmatic credentials for API access without console logins. |
| **CreateLoginProfile** | High | Adding console access to a user that previously had only programmatic access. |
| **UpdateAssumeRolePolicy** | High | This can enable cross-account persistence. |
| **DeleteTrail** / **StopLogging** | Critical | This is a defense evasion for disabling audit trails. |
| **DeactivateMFADevice** | High | Removing MFA makes it easier to gain access to an account. |

**Search for IAM Changes**

![An event in the CloudTrail lgos.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1774864372702.png)

Use lookup-events to search for recent IAM write events.

```bash
$ aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy \
    --max-results 10 \
    --query "Events[*].{Time:EventTime,User:Username,Event:EventName,Resources:Resources[0].ResourceName}" \
    --output table

---------------------------------------------------------------------------------------------
|                                            LookupEvents                                   |
+------------------+---------------+-----------------------------+--------------------------+
|       Event      |   Resources   |            Time             |               User       |
+------------------+---------------+-----------------------------+--------------------------+
|  AttachUserPolicy|  app-deployer |  2026-03-24T09:42:18+00:00  |  Room24-AdminAttach-[...]|
+------------------+---------------+-----------------------------+--------------------------+
```

**FINDING:** It looks like a policy was attached to one of the users.

When investigating, it is a good practice to note the `Username` (who made the change) and the `Resources` (what was changed). Search for `CreateAccessKey` events.

```bash
$ aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
    --max-results 10 \
    --query "Events[*].{Time:EventTime,User:Username,Event:EventName,Resources:Resources[0].ResourceName}" \
    --output table

----------------------------------------------------------------------------------------------------
|                                                 LookupEvents                                      |
+-----------------+-----------------------+-----------------------------+---------------------------+
|      Event      |       Resources       |            Time             |           User            |
+-----------------+-----------------------+-----------------------------+---------------------------+
[...]
|  CreateAccessKey|  AKIAYJM3KUGA2K5PZAX2 |  2026-03-24T09:42:23+00:00  |  [REDACTED]-569945792897  |
[...]
+-----------------+-----------------------+-----------------------------+---------------------------+
```

**FINDING:** A key was created for a user. You can extend the search for IAM write events.

```bash
$ aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventSource,AttributeValue=iam.amazonaws.com \
    --max-results 50 \
    --query "Events[?contains(EventName,'Attach') || contains(EventName,'Create') || contains(EventName,'Put') || contains(EventName,'Update') || contains(EventName,'Delete')].{Time:EventTime,User:Username,Event:EventName}" \
    --output table

--------------------------------------------------------------------------------------------------
|                                            LookupEvents                                        |
+----------------------------+-----------------------------+-------------------------------------+
|            Event           |            Time             |                  User               |
+----------------------------+-----------------------------+-------------------------------------+
[...]
|  CreateAccessKey           |  2026-03-24T09:42:23+00:00  |  [REDACTED]-569945792897            |
|  AttachUserPolicy          |  2026-03-24T09:42:18+00:00  |  Room24-AdminAttach-569945792897    |
[...]
+----------------------------+-----------------------------+-------------------------------------+
```

**FINDING:** Several suspicious changes should be further investigated.

**Inspect Suspicious Changes**

In the logs, you should be able to see at least two suspicious events:

- **AttachUserPolicy** event - The `AdministratorAccess` managed policy was attached directly to a low-privilege user.
- **CreateAccessKey** event - A new key was created for the low-privilege user.

![The console details for the AttachUserPolicy event.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1774864372509.png)

To get more details for the AttachUserPolicy, you can run the following command.

```bash
$ aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy \
    --max-results 5 \
    --query "Events[0].CloudTrailEvent" \
    --output text | python3 -m json.tool

{
    "eventVersion": "1.11",
    "userIdentity": {
        "type": "AssumedRole",
        "principalId": "AROAYJM3KUGAZGIVXHFWL:Room24-AdminAttach-569945792897",
[...]
```

Look for:

- **userIdentity** - who performed the action.
- **requestParameters** - which policy ARN was attached to which user.
- **sourceIPAddress** - where the request originated from.
- **eventTime** - when it happened.

**Confirm the Current State:** List the attached policies.

```bash
$ aws iam list-attached-user-policies --user-name app-deployer \
    --query "AttachedPolicies[*].{Policy:PolicyName,ARN:PolicyArn}" --output table

------------------------------------------------------------------------
|                       ListAttachedUserPolicies                       |
+----------------------------------------------+-----------------------+
|                      ARN                     |        Policy         |
+----------------------------------------------+-----------------------+
|  arn:aws:iam::aws:policy/AdministratorAccess |  AdministratorAccess  |
+----------------------------------------------+-----------------------+
```

**FINDING:** low-privilege user has AdministratorAccess attached directly.

List the access keys.

```bash
$ aws iam list-access-keys --user-name app-deployer \
    --query "AccessKeyMetadata[*].{KeyId:AccessKeyId,Status:Status,Created:CreateDate}" --output table

-----------------------------------------------------------------
|                        ListAccessKeys                         |
+----------------------------+------------------------+---------+
|           Created          |         KeyId          | Status  |
+----------------------------+------------------------+---------+
|  2026-03-24T09:42:23+00:00 |  AKIAYJM3KUGA2K5PZAX2  |  Active |
+----------------------------+------------------------+---------+
```

**FINDING:** The low-privilege user has at least one active key.

**Findings Summary**

Here is what you found so far:

- An administrator policy was attached to a low-privileged user.
- For the same user, an access key was created.
- Even if CloudTrail recorded the events, there is no detection rule or alerting.

Unauthorized changes, which could indicate privilege escalation and persistence, were silent.

**Answer the questions below**

> What is the user that created an access key (without the account ID suffix)?
> 

 Room24-RogueKeyCreator

```bash
$ aws cloudtrail lookup-events \
--lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy \
--max-results 5 \
--query "Events[0].CloudTrailEvent" \
--output text | python3 -m json.tool
```

> If you look at the AttachUserPolicy event, what is the source of the event?
> 

[iam.amazonaws.com](http://iam.amazonaws.com/)

```bash
aws cloudtrail lookup-events \ 
--lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy \
--max-results 5 \
--query "Events[0].CloudTrailEvent" \
--output text | python3 -m json.tool
```

### Task 4 - Remediation

You have identified the unauthorized changes. Now it is time to revert them and set up proper detection. Make sure you have the required IDs before you proceed.

```bash
$ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

$ ROGUE_KEY_ID=$(aws iam list-access-keys --user-name app-deployer \
    --query "sort_by(AccessKeyMetadata, &CreateDate)[-1].AccessKeyId" \
    --output text)

$ echo "ACCOUNT_ID=$ACCOUNT_ID  ROGUE_KEY_ID=$ROGUE_KEY_ID"

ACCOUNT_ID=569945792897  ROGUE_KEY_ID=AKIAYJM3KUGA2K5PZAX2
```

**Revert the Changes:** Detach the admin policy from the user.

```bash
$ aws iam detach-user-policy \
    --user-name app-deployer \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

Verify the policy was removed.

```bash
$ aws iam list-attached-user-policies --user-name app-deployer --output table

--------------------------
|ListAttachedUserPolicies|
+------------------------+
```

Deactivate and delete the rogue access key.

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

**Note:** In a real environment, you must verify that the change was not legitimate before rolling it back.

```bash
$ aws iam update-access-key \
    --user-name app-deployer \
    --access-key-id $ROGUE_KEY_ID \
    --status Inactive

$ aws iam delete-access-key \
    --user-name app-deployer \
    --access-key-id $ROGUE_KEY_ID
```

Verify the user has no access keys.

```bash
$ aws iam list-access-keys --user-name app-deployer --output table

----------------
|ListAccessKeys|
+--------------+
```

**Set up SNS:** Amazon SNS (Simple Notification Service) is a fully managed messaging service that enables push notifications via SMS, email, or HTTP to multiple subscribers.

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

**Note:** Subscribing to or confirming an email is optional. Even in a sandbox environment, do not use your personal email address.

Create an SNS topic.

```bash
$ SNS_ARN=$(aws sns create-topic --name iam-change-alerts \
    --query TopicArn --output text)

$ echo $SNS_ARN

arn:aws:sns:us-east-1:569945792897:iam-change-alerts
```

Subscribe to the SNS topic with an email. In a real environment, this would be a monitored email.

```bash
$ aws sns subscribe \
    --topic-arn $SNS_ARN \
    --protocol email \
    --notification-endpoint [REPLACE WITH EMAIL]

{
    "SubscriptionArn": "pending confirmation"
}
```

Check the inbox and confirm the subscription. The AWS confirmation will look like the screenshot below.

![Confirmation for subscribing to the SNS topic.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1774866023407.png)

**Set up EventBridge:** Amazon EventBridge is a serverless, event-driven service that enables different services to communicate asynchronously via an event bus. Create the event pattern for IAM changes.

```bash
$ cat > ./iam-event-pattern.json << 'EOF'
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": [
      "AttachUserPolicy",
      "AttachRolePolicy",
      "AttachGroupPolicy",
      "PutUserPolicy",
      "PutRolePolicy",
      "PutGroupPolicy",
      "CreateUser",
      "CreateAccessKey",
      "CreateLoginProfile",
      "UpdateAssumeRolePolicy",
      "DeactivateMFADevice",
      "DeleteUser",
      "DeleteAccessKey"
    ]
  }
}
EOF
```

Create the EventBridge rule using the pattern defined.

```bash
$ aws events put-rule \
    --name iam-high-risk-changes \
    --event-pattern file://iam-event-pattern.json \
    --state ENABLED \
    --description "Alerts on high-risk IAM API calls"

{
    "RuleArn": "arn:aws:events:us-east-1:569945792897:rule/iam-high-risk-changes"
}
```

Add the SNS topic as a target.

```bash
$ aws events put-targets \
    --rule iam-high-risk-changes \
    --targets "Id=sns-iam-alerts,Arn=$SNS_ARN"

{
    "FailedEntryCount": 0,
    "FailedEntries": []
}
```

Next, apply the topic policy. If you perform the previous step in the AWS Console, this policy is automatically added.

```bash
$ cat > /tmp/iam-topic-policy.json<< EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DefaultOwnerAccess",
      "Effect": "Allow",
      "Principal": {"AWS": "*"},
      "Action": [
        "SNS:GetTopicAttributes","SNS:SetTopicAttributes","SNS:AddPermission",
        "SNS:RemovePermission","SNS:DeleteTopic","SNS:Subscribe",
        "SNS:ListSubscriptionsByTopic","SNS:Publish"
      ],
      "Resource": "${SNS_ARN}",
      "Condition": {"StringEquals": {"AWS:SourceOwner": "${ACCOUNT_ID}"}}
    },
    {
      "Sid": "AllowEventBridgePublish",
      "Effect": "Allow",
      "Principal": {"Service": "events.amazonaws.com"},
      "Action": "SNS:Publish",
      "Resource": "${SNS_ARN}"
    }
  ]
}
EOF$ aws sns set-topic-attributes \
  --topic-arn $SNS_ARN \
  --attribute-name Policy \
  --attribute-value file:///tmp/iam-topic-policy.json
```

**Verify:** Let's see your setup in action. You can make a controlled IAM change to verify alerting fires.

```bash
$ TEST_KEY=$(aws iam create-access-key --user-name app-deployer \
    --query 'AccessKey.AccessKeyId' --output text)
```

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

**Note:** The email might take ~1-3 minutes to land in the inbox. You should clean up the test key.

```bash
$ aws iam delete-access-key \
    --user-name app-deployer \
    --access-key-id $TEST_KEY
```

Once everything is set up, you can run the helper Lambda function to fetch your well-earned flag.

```bash
$ aws lambda invoke \
    --function-name AWS204-VerifyRemediation \
    --payload '{}' \
    /tmp/verify-output.json && python3 -m json.tool /tmp/verify-output.json

[...]
{
    "admin_policy_check": "PASS — AdministratorAccess removed",
    "key_check": "PASS — no active keys (all rogue keys removed)", "status": "PASS",
    "flag": "[REDACTED]"
}
```

The IAMs are no longer silent.

**Answer the questions below**

> What is the flag retrieved at the end of the exercise?
> 

THM{SILENT_CHANGES_DETECTED}

### Task 5 - Build It Securely

You have addressed the immediate threat in the previous task and set up a basic detection rule. Now, here is how you can improve that and build an IAM monitoring baseline from scratch. Buckle up, as this is going to be quite a ride.

First, as always, make sure you have the appropriate details saved in environment variables.

```bash
$ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

$ SNS_ARN="arn:aws:sns:us-east-1:${ACCOUNT_ID}:iam-change-alerts"

$ echo "ACCOUNT_ID=$ACCOUNT_ID  SNS_ARN=$SNS_ARN"

ACCOUNT_ID=569945792897  SNS_ARN=arn:aws:sns:us-east-1:569945792897:iam-change-alerts
```

**Define Events List**

It is a good practice to organize the events you want to monitor by severity:

- **Critical** - immediate investigation required:
    - AttachUserPolicy, AttachRolePolicy, AttachGroupPolicy
    - PutUserPolicy, PutRolePolicy, PutGroupPolicy
    - CreateUser
    - UpdateAssumeRolePolicy
    - DeleteTrail, StopLogging
    - PutRetentionPolicy
- **High** - review within 1-2 hours:
    - CreateAccessKey, CreateLoginProfile, DeactivateMFADevice
    - DeleteUserPolicy, DetachUserPolicy
- **Medium** - review within 24 hours:
    - CreateRole, CreateGroup, AddUserToGroup
    - Create EventBridge Rules

Create separate rules for better routing:

- Critical -> direct message/all channels.
- High -> Slack.
- Medium -> email.

In this exercise, you will create the patterns for the critical events and attach them to an SNS topic.

```bash
$ cat > ./iam-critical-pattern.json << 'EOF'
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": [
      "AttachUserPolicy",
      "AttachRolePolicy",
      "AttachGroupPolicy",
      "PutUserPolicy",
      "PutRolePolicy",
      "PutGroupPolicy",
      "CreateUser",
      "UpdateAssumeRolePolicy"
    ]
  }
}
EOF
```

Create the new rule for the IAM events.

```bash
$ aws events put-rule \
    --name iam-critical-changes \
    --event-pattern file://iam-critical-pattern.json \
    --state ENABLED \
    --description "Critical IAM changes requiring immediate investigation"

{
    "RuleArn": "arn:aws:events:us-east-1:569945792897:rule/iam-critical-changes"
}
```

Attach it to the SNS topic.

```bash
$ aws events put-targets \
    --rule iam-critical-changes \
    --targets "Id=sns-critical,Arn=$SNS_ARN"

{
    "FailedEntryCount": 0,
    "FailedEntries": []
}
```

Add another rule for log tampering and add it to the SNS topic as well.

```bash
$ cat > ./audit-tampering-pattern.json << 'EOF'
{
  "source": ["aws.cloudtrail"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["cloudtrail.amazonaws.com"],
    "eventName": [
      "DeleteTrail",
      "StopLogging",
      "UpdateTrail",
      "PutEventSelectors"
    ]
  }
}
EOF
```

Create the log rule.

```bash
$ aws events put-rule \
    --name audit-trail-tampering \
    --event-pattern file://audit-tampering-pattern.json \
    --state ENABLED \
    --description "Alerts on CloudTrail tampering - defense evasion indicator"

{
    "RuleArn": "arn:aws:events:us-east-1:569945792897:rule/audit-trail-tampering"
}
```

Add the SNS target.

```bash
$ aws events put-targets \
    --rule audit-trail-tampering \
    --targets "Id=sns-audit,Arn=$SNS_ARN"

{
    "FailedEntryCount": 0,
    "FailedEntries": []
}
```

**Set up CloudWatch:** Amazon CloudWatch is a monitoring and observability service that collects, monitors, and analyzes logs, metrics, and events. First, define a metric filter on the CloudTrail log group.

```bash
$ aws logs put-metric-filter \
  --log-group-name aws-cloudtrail-logs \
  --filter-name IAMWriteEventCount \
  --filter-pattern '{ ($.eventSource = "iam.amazonaws.com") && (($.eventName = "AttachUserPolicy") || ($.eventName = "CreateUser") || ($.eventName = "CreateAccessKey") || ($.eventName = "PutUserPolicy") || ($.eventName = "AttachRolePolicy") || ($.eventName = "UpdateAssumeRolePolicy")) }' \
  --metric-transformations \
    metricName=IAMHighRiskEventCount,metricNamespace=SecurityMetrics,metricValue=1,defaultValue=0
```

Create an alarm when more than 3 IAM write events happen within 5 minutes.

```bash
$ aws cloudwatch put-metric-alarm \
  --alarm-name iam-change-burst \
  --metric-name IAMHighRiskEventCount \
  --namespace SecurityMetrics \
  --statistic Sum \
  --period 300 \
  --threshold 3 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --alarm-actions $SNS_ARN \
  --alarm-description "Alerts when more than 3 high-risk IAM events occur within 5 minutes"
```

**Verify:** Verify EventBridge rules are active.

```bash
$ aws events list-rules \
    --query "Rules[*].{Name:Name,State:State}" --output table

---------------------------------------------------------------------------------
|                                   ListRules                                   |
+--------------------------------------------------------------------+----------+
|                                Name                                |  State   |
+--------------------------------------------------------------------+----------+
[...]
|  audit-trail-tampering                                             |  ENABLED |
|  iam-critical-changes                                              |  ENABLED |
|  iam-high-risk-changes                                             |  ENABLED |
+--------------------------------------------------------------------+----------+
```

Verify SNS subscription.

```bash
$ aws sns list-subscriptions-by-topic \
    --topic-arn $SNS_ARN \
    --query "Subscriptions[*].{Endpoint:Endpoint,Protocol:Protocol}" --output table

------------------------------------------
|        ListSubscriptionsByTopic        |
+---------------------------+------------+
|         Endpoint          | Protocol   |
+---------------------------+------------+
|  hadley.geno@minafter.com |  email     |
+---------------------------+------------+
```

Verify CloudWatch alarms.

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

**Note:** CloudWatch alarms can take 2-10 minutes to transition out of the INSUFFICIENT_DATA state, but this time depends on the alarm's evaluation period and metric type.

```bash
$ aws cloudwatch describe-alarms \
    --alarm-names iam-change-burst \
    --query "MetricAlarms[*].{Name:AlarmName,State:StateValue,Metric:MetricName}" --output table

--------------------------------------------------------
|                    DescribeAlarms                    |
+------------------------+--------------------+--------+
|         Metric         |       Name         | State  |
+------------------------+--------------------+--------+
|  IAMHighRiskEventCount |  iam-change-burst  |  OK    |
+------------------------+--------------------+--------+
```

Verify metric filter.

```bash
$ aws logs describe-metric-filters \
  --log-group-name aws-cloudtrail-logs \
  --query "metricFilters[*].{Name:filterName,Pattern:filterPattern}" --output table

-------------------------------------------------------------
|                  DescribeMetricFilters                    |
+---------+-------------------------------------------------+
|  Name   |               IAMWriteEventCount                |
|  Pattern|  [{ ($.eventSource = "iam.amazonaws.com") [...] |
+---------+-------------------------------------------------+
```

Finally, you can run the helper Lambda function to retrieve the flag.

```bash
$ aws lambda invoke \
    --function-name AWS204-VerifySecureBuild \
    --payload '{}' \
    /tmp/verify-secure.json && python3 -m json.tool /tmp/verify-secure.json

[...]
{
    "iam-high-risk-changes_check": "PASS — enabled with target",
    "audit-trail-tampering_check": "PASS — enabled with target",
    "status": "PASS",
    "flag": "[REDACTED]"
}
```

Excellent work. You should now be able to implement an IAM baseline for monitoring and alerting.

**Answer the questions below**

> What is the flag at the end of the exercise?
> 

THM{WATCHING_THE_WATCHERS}

### Task 6 - Conclusion

That was quite a journey, and here is a handy checklist you can use at any time:

- CloudTrail trail is active and logging management events.
- CloudTrail logs are stored in a protected S3 bucket with versioning.
- EventBridge rule for critical IAM changes.
- EventBridge rule for audit trail tampering.
- SNS topic with confirmed subscribers.
- CloudWatch metric filter counting high-risk IAM events.
- CloudWatch alarm for burst detection.

**Key Takeaways**

- CloudTrail is your IAM audit log.
- IAM persistence is usually the first attacker move.
- Log tampering is a critical signal to monitor and alert on.
- For a layered defense strategy, you can complement EventBridge's deterministic alerting with GuardDuty's behavioral detection.
