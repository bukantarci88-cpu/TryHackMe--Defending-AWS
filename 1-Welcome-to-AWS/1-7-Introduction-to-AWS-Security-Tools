# AWS 1.7. Introduction to AWS Security Tools

### Task 1 - Introduction

In this room, you will walk through the four pillars of AWS security observability:

- **CloudTrail** - API activity logging
- **GuardDuty** - continuous threat detection
- **Inspector** - vulnerability and configuration assessment
- **Detective** - investigation and visual analytics

### Task 2 - CloudTrail

Amazon CloudTrail records API activity across your AWS account. It logs every request made to the AWS API, whether programmatic or from the Web Console, and stores the data in an S3 bucket or CloudWatch Logs. These logs are the foundation for security monitoring, incident investigation, and compliance auditing.

**Service Key Points**

- A trail is created in a single region but can capture API calls from all regions if configured as a multi-region trail.
- CloudTrail retains event history for 90 days by default. For longer retention, deliver logs to S3 and/or CloudWatch Logs.
- Logs are signed and can be validated for integrity using log-file validation.
- The S3 bucket must have a bucket policy that grants the CloudTrail service write access.

**Security Best Practices**

- Enable a multi-region trail to capture activity in every region.
- Enable log-file integrity validation to detect tampering.
- Use server-side encryption ( SSE-S3 AES256 or SSE-KMS) on the S3 bucket.
- Stream logs to CloudWatch Logs for real-time alerting.
- Add a lifecycle rule to expire or archive old logs, for example, 30 days for lab environments.

**Practical Exercise**

1. Navigate to the `CloudTrail` service `Dashboard`.

![Navigate to CloudTrail Dashboard](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772018423718.png)

1. Click Create Trail and fill in the trail name, select the `Use existing S3 bucket`, click `Browse`, select the lab bucket (starts with `security-lab-cloudtrail-`), and scroll down. **Note:** Ensure encryption is checked.

![Complete the trail form with name and bucket.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772018423418.png)

1. Provide a name for the KMS key, ensure `Log file validation` is checked, and click `Next`.

![Provide KMS key name, ensure log validation is checked and click next.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772018423514.png)

1. Ensure that only the following checkboxes are checked before you click Next:
- Event type: `Management events`
- API activity: `Read, Write`

![Ensure only management activities and read/write API activity are checked.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772018423427.png)

1. Validate and create the trail.
2. Once the trail is successfully created, you can see it automatically starts logging.

![Trail successfully created and logging](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772104698972.png)

1. You can navigate to the S3 bucket and see that the folder structure is created and activity is tracked.

![S3 bucket where CloudTrail logs activities](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772104697847.png)

1. Alternatively, you can run the CLI commands in `CloudShell` or AWS CLI.

**Note:** If you created the trail in the AWS Console, the create command will fail because the trail already exists. You can delete the trail and re-create it using the CLI commands or reset the lab environment and follow the CLI path. Make sure you replace the bucket name with the one deployed in your lab.

```bash
           # Identify the S3 bucket
$ aws s3 ls

2026-02-26 07:11:02 security-lab-cloudtrail-058264110959-us-east-1# Create the trail - make sure you replace the S3 bucket name
$ aws cloudtrail create-trail \
    --name SecurityLabTrail \
    --s3-bucket-name "security-lab-cloudtrail-058264110959-us-east-1" \
    --is-multi-region-trail \
    --enable-log-file-validation

{
    "Name": "SecurityLabTrail",
    "S3BucketName": "security-lab-cloudtrail-058264110959-us-east-1",
    "IncludeGlobalServiceEvents": true,
    "IsMultiRegionTrail": true,
    "TrailARN": "arn:aws:cloudtrail:us-east-1:058264110959:trail/SecurityLabTrail",
    "LogFileValidationEnabled": true,
    "IsOrganizationTrail": false
}# Start logging
$ aws cloudtrail start-logging --name SecurityLabTrail

# Get trail status
$ aws cloudtrail get-trail-status --name SecurityLabTrail

{
    "IsLogging": true,
    "LatestDeliveryTime": "2026-02-26T11:34:23.628000+00:00",
    "StartLoggingTime": "2026-02-26T11:34:20.057000+00:00",
    "LatestDeliveryAttemptTime": "2026-02-26T11:34:23Z",
    "LatestNotificationAttemptTime": "",
    "LatestNotificationAttemptSucceeded": "",
    "LatestDeliveryAttemptSucceeded": "2026-02-26T11:34:23Z",
    "TimeLoggingStarted": "2026-02-26T11:34:20Z",
    "TimeLoggingStopped": ""
}
```

**Answer the questions below**

> What is CloudTrail recording?
> 

API activity

> What is the name of the other trail visible in the CloudTrail Dashboard?
> 

thm-org-trail

### Task 3 - GuardDuty

Amazon GuardDuty provides continuous threat detection by analyzing CloudTrail logs, VPC Flow Logs, and DNS logs. It uses machine learning and threat intelligence feeds to identify anomalous or malicious activity such as unusual API calls, unauthorized access attempts, or communication with known malicious IPs.

**Service Key Points**

- A GuardDuty detector is per-region. Your account has one enabled in `us-east-1`.
- GuardDuty automatically ingests CloudTrail management events, VPC Flow Logs, and DNS query logs.
- Findings include severity ratings (Low, Medium, High), affected resources, and the actor (IP, IAM identity).
- The detector can be managed by a delegated administrator (the security account).

**Security Best Practices**

- Enable GuardDuty in all regions.
- Keep the default threat intelligence feeds active.
- Review findings regularly and integrate with notification systems (SNS, EventBridge).
- Use GuardDuty findings as input for Detective investigations.

**Practical Exercise**

**Note:** GuardDuty is centrally managed at the Organization level, so it cannot be enabled during the lab. You can use the following command to enable the service in an account: `aws guardduty create-detector --enable --region` .

1. Navigate to the `GuardDuty` service.

![Navigate to the GuardDuty service.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772020155251.png)

1. Navigate to `Settings` and check that a detector is already configured.

![Check the configured detector](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772020155535.png)

1. Before we proceed to the next step, let us generate some sample findings. Run the following commands in `CloudShell` or AWS CLI.

AWS Security Tools

```bash
           # This will save the Detector ID in a variable
$ DETECTOR_ID=$(aws guardduty list-detectors --region us-east-1 --query 'DetectorIds[0]' --output text)

$ echo "Detector ID: $DETECTOR_ID"

Detector ID: 62c6c5918941026da6018b64e1fa72e7# Create the sample findings

$ aws guardduty create-sample-findings \
    --detector-id "$DETECTOR_ID" \
    --region us-east-1 \
    --finding-types \
      "Recon:EC2/PortProbeUnprotectedPort" \
      "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B"
```

1. Navigate to `Findings` and investigate the samples.

**Note:** If the sample findings do not appear, try refreshing the page or rerun the command. However, the task completion does not depend on these findings.

![Navigate to Findings and look at the samples.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772106995459.png)

1. By clicking on a sample, you can see more details around the event.

![Explore the report for the finding.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772107336630.png)

**Answer the questions below**

> What is one of the event sources for GuardDuty?
> 

CloudTrail

> GuardDuty rates every finding using which three severity levels?
> 

Low, Medium, High

### Task 4 - Inspector

Amazon Inspector performs automated security assessments on your EC2 instances. It checks for known vulnerabilities (CVEs), insecure configurations, and deviations from best practices. Inspector integrates with GuardDuty and CloudTrail to provide a complete picture of your security posture.

**Service Key Points**

- Automatically detects new resources and re-evaluates them whenever changes occur.
- Scans Amazon EC2 instances, Amazon ECR container images, AWS Lambda functions, and developer code (CI/CD pipelines) for dependency and secret problems.
- Calculates a highly prioritized risk score for every finding by combining CVE data with real-time environmental factors like network accessibility and exploitability.
- Findings include CVE identifiers, severity ratings, and remediation guidance.

**Security Best Practices**

- Use the Common Vulnerabilities and Network Reachability rules packages for broad coverage.
- Run assessments periodically (weekly or on instance launch) for continuous compliance.
- Export findings to S3 or send them to Security Hub for centralized tracking.
- Prioritize remediation by severity: Critical and High first.

**Practical Exercise**

1. Navigate to the `Inspector` service.

![Navigate to Inspector service.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772020922915.png)

1. Click `Get Started` and enable Inspector for this account.

![Activate Inspector for the account.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772175763250.png)

1. Once activated, it will take ~3-5 minutes for the service to discover the existing instance and populate the findings.
2. You can activate the scans for your account by going to `Account Coverage` and selecting the resource scanning from the `Activate` drop-down menu.

**Note:** Once the Amazon EC2 scanning is activated, you can proceed to the next step.

![Scanning can be activated by going to Account coverage and then to the Activate drop-down menu.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1779975889034.png)

1. Explore the findings on the EC2 instance by navigating to `Findings`, selecting `By instance`, and selecting the lab EC2.

![Explore the findings on the EC2 instance by going to findings and then the instance ID.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1779975888969.png)

**Answer the questions below**

> Which are the two ports that are found to be vulnerable (listed in ascending order)?
> 

22,80

> What type of vulnerability do the two ports have in common?
> 

Network Reachability

### Task 5 - Detective

Amazon Detective builds an investigation graph from GuardDuty findings, CloudTrail events, and VPC Flow Logs. It automatically creates timelines, actor paths, and resource connections that help you investigate security incidents. Detective shows actors, IP addresses, and resources in a visual timeline, making it easier to understand the scope of an incident.

**Service Key Points**

- A Detective behavior graph is created per region and automatically starts ingesting data from GuardDuty and CloudTrail.
- The graph takes 24-48 hours to build a meaningful baseline of normal behavior.
- Once populated, you can investigate findings by exploring entity profiles (IP addresses, IAM users, EC2 instances).
- Detective is most useful when GuardDuty has findings to investigate.

**Security Best Practices**

- Create the behavior graph in the same region as GuardDuty.
- Delete the graph after investigation to avoid unnecessary data retention and costs.
- Use a ReadOnly IAM policy for analysts who should investigate but not modify.
- Use a VPC Endpoint for Detective to keep API traffic off the public internet.

**Practical Exercise**

1. Navigate to the `Detective` service.

![Navigate to the Detective service.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772021241988.png)

1. You should see the `Get Started` page. Click on `Get Started` and enable Detective.

![Enable Detective](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772021242118.png)

1. On the left side, you can navigate to the different Detective dashboards. Go to `Search`, select EC2 instance as type, enter the wildcard  in the search field, and click `Search`.

**Note:** Findings take 24-48 hours to populate profiles, so the instance might not appear, or there may be limited information. Give the service at least ~5 minutes after activation to discover the resources. You can play the mini-game in the next task if it takes too long.

![Search for all EC2 instances.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772786917318.png)

1. Click on the instance ID, and it will show the findings for that instance.

![The summary screen for an EC2 instance.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772094782991.png)

1. Also, you can run an investigation for Roles or Users. For this part, you will need your User ARN. For simplicity, we will use `CloudShell`.

```bash
           $ aws sts get-caller-identity

{
    "UserId": "AIDAQBCPBAOP4SYPL7VUV",
    "Account": "002313225119",
    "Arn": "arn:aws:iam::002313225119:user/002313225119"
}
```

1. Now navigate to `Investigations` and click `Run Investigation`.

![Start an investigation by navigating to Investigations and click Run Investigation.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772177559119.png)

1. In the Investigation form, select `Specify an AWS role or user with an ARN`, select `AWS user` from the IAM resource dropdown, and fill in the ARN found earlier. Then click `Run Investigation`.

**NOTE:** If you see an `ARN not found` error, Detective needs a few more minutes to discover the resources.

![Fill out the form with the necessary information and start the investigation.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772177558990.png)

1. Once completed, you can have a look at the findings.

**Note:** The investigation most likely will not reveal much in the lab environment, but it is a good exercise to see how to run a manual investigation.

![Investigation results summary](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772177559092.png)

This is great, you have configured Detective and run your first investigation. Congratulations.

**Answer the questions below**

> What other IAM resource type can you select from the Investigation drop-down?
> 

AWS Role

> What is the minimum time Detective needs to build a meaningful behavior-graph baseline?
> 

24

### Task 6 - Conclusion

Excellent. You have explored the four most widely used AWS security observability services.

**Key Takeaways**

- CloudTrail allows you to have good security visibility, event history, and is the first step towards many compliance standards like PCI-DSS or SOC2.
- GuardDuty is your friendly neighborhood watchdog. It provides continuous security monitoring, intelligent detection, covers a wide spectrum of AWS resources, and is easy to activate and use.
- Inspector continuously assesses your workloads (EC2, ECR, Lambda) for software vulnerabilities and unintended network exposure. Use it to identify CVEs and configuration drift.
- Detective collects, correlates, and analyzes security data across your AWS environment. It builds visual investigation timelines from GuardDuty findings and CloudTrail events, helping you understand the full scope of security incidents.

**Practical Exercise**

You went through theory and hands-on exercises. Now it is time to test your newfound knowledge with a minigame. Open the `View Site` and answer the questions based on what you have learned in this room.

**Answer the questions below**

> What is the flag received when completing the mini-game?
> 

THM{DEFENCE_IN_DEPTH}
