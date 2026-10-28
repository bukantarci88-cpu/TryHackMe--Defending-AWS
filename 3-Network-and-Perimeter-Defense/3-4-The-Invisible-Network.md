# AWS Security 3.4. The Invisible Network

### Task 1 - Introduction

Your SOC has flagged an alert: an EC2 instance appears to be communicating with an unknown external IP. You need to answer basic questions:

- Where is the traffic going?
- How much data was transferred?
- When did it start, and what ports are being used?

You open FlowLogs and search for logs. There are none. No network telemetry exists for this VPC. Every connection that has ever been made, legitimate or malicious, left zero trace at the network layer.

This is not an edge case. Many teams deploy workloads into VPCs without enabling FlowLogs, either because they forget, assume another tool covers it, or want to avoid the cost. The result is a critical visibility gap that makes investigation impossible and detection a guessing game. This is how the Marriott breach persisted for four years.

**Learning Objectives**

- Understand what VPC FlowLogs capture and their limitations
- Identify when FlowLogs are missing from a VPC
- Enable FlowLogs with an appropriate IAM role and log destination
- Query Flow Log data using CloudWatch Logs Insights
- Build reusable security queries for monitoring and investigation
- Design a network visibility baseline for new VPC deployments

### Task 2 - Real-World Incident

Let us examine how missing network telemetry contributed to one of the longest undetected breaches in history.

Marriott International is one of the world's largest hotel chains. In 2016, Marriott completed its $13 billion acquisition of Starwood Hotels and Resorts, inheriting Starwood's IT infrastructure, including the Starwood Preferred Guest (SPG) central reservation database. The SPG database held personal information for hundreds of millions of loyalty program members: names, addresses, passport numbers, payment card details, and detailed travel history.

As part of the acquisition, this database continued operating in the Starwood environment while Marriott planned IT integration. The inherited network lacked VPC Flow Logs or equivalent network traffic monitoring - an oversight that allowed attackers to operate invisibly for years.

![Attack chain from initial foothold, to acquisition, exfiltration, and discovery.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1781260693183.png)

1. **Initial compromise (2014):** Attackers gained access to the Starwood network in 2014, two years before Marriott announced the acquisition. Using remote access tools, they established persistent footholds and began lateral movement and data reconnaissance inside the Starwood environment.
2. **Persistence through acquisition (2016):** When Marriott completed its acquisition in September 2016, it inherited not only Starwood's hotels and loyalty program, but also its already-compromised network. No network traffic analysis or deep technical security review was performed as part of integration planning. The attackers' persistent access tools remained operational and undetected.
3. **Years of undetected exfiltration (2014–2018):** Throughout this period, the attackers maintained access to the SPG database and exfiltrated data over sustained outbound connections. This traffic generated unusual network patterns that would have been visible in network flow logs, but no such logs were being collected or analyzed. There was no baseline of normal network behavior, no alerts on anomalous outbound connections, and no network-layer audit trail of any kind.
4. **Discovery (September 2018):** A security tool flagged an alert on 7 September 2018 for an unusual database query on the SPG database. An internal investigation confirmed the breach. Marriott publicly disclosed the incident on 30 November 2018, approximately 4 years after the initial compromise.

**Core Failures**

- **No network traffic monitoring:** The attackers' lateral movement and exfiltration traffic generated network activity that flow logs would have captured. Unusual outbound connections from database servers to external IPs, sustained data transfer flows, and east-west lateral movement all went unrecorded for years.
- **No network security review during M&A due diligence:** Marriott acquired Starwood's network alongside its hotels and loyalty program. A network traffic analysis during due diligence could have identified unusual connections. This was not performed.
- **No traffic baseline for anomaly detection:** Without a history of normal network traffic, there was no way to identify when unusual activity began. Network logging from day one establishes the baseline that enables anomaly detection.
- **Four-year attacker dwell time:** The attackers operated inside the network for approximately four years before discovery. Modern network monitoring tools, fed by flow log data, can reduce attacker dwell time from years to hours or days.

**Answer the questions below**

> For how many years did the attackers have undetected access to Starwood's network?
> 

4

> If a network traffic baseline had been in place, what detection mechanism could have been enabled?
> 

Anomaly detection

### Task 3 - Identification

In this task, you will take on the role of a security analyst asked to assess the network visibility posture of a VPC.

Place the VPC ID in an environment variable so you can use it later.

```bash
$ VPC_ID=$(aws ec2 describe-vpcs \
        --filters "Name=tag:Name,Values=net-lab-vpc" \
        --query "Vpcs[0].VpcId" --output text)

$ echo "VPC: $VPC_ID"

VPC: vpc-054ed738c39ee646e
```

**What Are VPC FlowLogs?**

VPC FlowLogs capture metadata about IP traffic going to and from network interfaces in your VPC. Each record describes a network connection and contains the following fields:

| **Field** | **Description** |
| --- | --- |
| **srcaddr** | Source IP address |
| **dstaddr** | Destination IP address |
| **srcport** | Source port |
| **dstport** | Destination port |
| **protocol** | IANA protocol number (6 = TCP, 17 = UDP, 1 = ICMP) |
| **packets** | Number of packets transferred |
| **bytes** | Number of bytes transferred |
| **start** | Start time of the flow (Unix timestamp) |
| **end** | End time of the flow (Unix timestamp) |
| **action** | ACCEPT or REJECT based on security group and NACL rules |
| **log-status** | Logging status: OK, NODATA, or SKIPDATA |

FlowLogs can be enabled at three levels:

- **VPC level** - captures all traffic for every network interface in the VPC.
- **Subnet level** - captures traffic for all interfaces in a specific subnet.
- **ENI (Elastic Network Interface) level** - captures traffic for a single interface.

FlowLogs can be delivered to three destinations:

- **CloudWatch Logs** - good for real-time queries and alerting via Logs Insights.
- **Amazon S3** - good for long-term storage, large-scale analysis, and cost efficiency.
- **Amazon Kinesis Data Firehose** - good for streaming to third-party tools.

**What FlowLogs Do Not Capture**

FlowLogs record metadata about connections, not the contents of packets. They also exclude:

- DNS queries to the Amazon-provided DNS server.
- Traffic to the instance metadata service (`169.254.169.254`).
- DHCP traffic.
- Traffic to the VPC router and reserved addresses in each subnet.

**Check for Existing FlowLogs:** Run the following command to check if any FlowLogs exist for the lab VPC:

```bash
$ aws ec2 describe-flow-logs \
      --filter "Name=resource-id,Values=$VPC_ID" \
      --output table

------------------
|DescribeFlowLogs|
+----------------+
```

**FINDING:** The output table is empty, indicating that no logging is configured for the VPC.

To confirm there are no FlowLogs anywhere in the account, you can run the following command.

```bash
$ aws ec2 describe-flow-logs \
      --query "FlowLogs[*].{ID:FlowLogId,Resource:ResourceId,Status:FlowLogStatus,Destination:LogDestinationType}" \
      --output table
```

**FINDING:** No output here either.

The lab setup includes two instances that are generating network traffic that is not logged.

```bash
$ aws ec2 describe-instances \
      --filters "Name=vpc-id,Values=$VPC_ID" "Name=instance-state-name,Values=running" \
      --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name'].Value|[0],ID:InstanceId,PrivateIP:PrivateIpAddress,PublicIP:PublicIpAddress}" \
      --output table

---------------------------------------------------------------------------------
|                               DescribeInstances                               |
+----------------------+------------------------+-------------+-----------------+
|          ID          |         Name           |  PrivateIP  |    PublicIP     |
+----------------------+------------------------+-------------+-----------------+
|  i-0ca352ad11139dc4f |  net-lab-web-server    |  10.0.1.177 |  44.220.168.187 |
|  i-0e0009efd5ab1f4f2 |  net-lab-internal-app  |  10.0.2.39  |  None           |
+----------------------+------------------------+-------------+-----------------+
```

**FINDING:** Two running instances, one with a public IP, are unmonitored. Without monitoring, the command below would leave no trace.

**Note:** To retrieve the task flag, you have to remove the `| head -5` in the `curl` command.

```bash
$ WEB_IP=$(aws ec2 describe-instances \
      --filters "Name=tag:Name,Values=net-lab-web-server" "Name=instance-state-name,Values=running" \
      --query "Reservations[0].Instances[0].PublicIpAddress" --output text)

$ echo "Web server IP: $WEB_IP"

Web server IP: 44.220.168.187$ curl -s http://$WEB_IP | head -5
<html>
<head><title>Network Lab - Web Server</title></head>
<body>
<h1>Network Visibility Lab</h1>
<p><strong>Instance:</strong> i-0ca352ad11139dc4f</p>
```

**Understand the Risk**

Without FlowLogs, you cannot answer any of the following questions:

- Is any instance communicating with unexpected external IPs?
- Are there rejected connection attempts indicating scanning activity?
- Is there unusual outbound traffic volume that could indicate data exfiltration?
- Are security group rules working as intended?
- Has any instance in the private subnet somehow gained internet connectivity?

This is the exact visibility gap that allowed the Marriott/Starwood breach to persist undetected for four years - attackers moved laterally and exfiltrated data through network connections that no one was recording.

**Findings Summary**

Wrapping the findings up, you now see that:

- The lab VPC has no VPC FlowLogs enabled at any level.
- Two EC2 instances are actively running and generating network traffic with zero network-layer visibility.
- Any connection made by these instances leaves no traceable record.
- Scanning activity, lateral movement, and data exfiltration could occur right now, and there would be no way to detect or investigate them at the network layer.

**Answer the questions below**

> At what three levels can VPC Flow Logs be enabled (listed alphabetically)?
> 

ENI, Subnet, VPC

> What information about the IP traffic do VPC FlowLogs capture?
> 

Metadata

> What is the flag found on the web server page?
> 

THM{DARK_TEMPLAR_DETECTED} 

<img width="577" height="289" alt="image" src="https://github.com/user-attachments/assets/3de25f48-3fcf-4299-ba05-8ae8e3685672" />

### Task 4 - Remediation

Now that you have confirmed the VPC has no FlowLogs, it is time to fix this. Here is what you will do:

- Create a CloudWatch Logs log group as the Flow Log destination.
- Create an IAM role that grants the Flow Logs service write access to CloudWatch Logs.
- Enable VPC Flow Logs at the VPC level, capturing all traffic.
- Generate test traffic to produce Flow Log records.
- Query the logs with CloudWatch Logs Insights to verify network visibility.
- Invoke the verification Lambda to confirm the remediation is complete.

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

**Create the CloudWatch Log Group:** Flow Logs need a destination. You will use CloudWatch Logs for this lab because it supports real-time queries with Logs Insights. First, create the log group and set a retention period. In a production environment, you would typically use 90 days or more.

```bash
$ aws logs create-log-group --log-group-name /vpc/net-lab-flow-logs

$ aws logs put-retention-policy \
      --log-group-name /vpc/net-lab-flow-logs \
      --retention-in-days 5
```

**Create the IAM Role for Flow Logs:** VPC FlowLogs require an IAM role that grants the FlowLogs service write access to CloudWatch Logs.

First, create the trust policy document. This command saves a scoped policy document to a JSON file.

```bash
$ cat << 'EOF' > /tmp/flow-logs-trust-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
```

Create the role that will receive the saved trust policy.

```bash
$ aws iam create-role \
      --role-name net-lab-flow-logs-role \
      --assume-role-policy-document file:///tmp/flow-logs-trust-policy.json \
      --description "Allows VPC Flow Logs to publish to CloudWatch Logs" \
      --permissions-boundary arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/Room34-LearnerBoundary

{
    "Role": {
        "Path": "/",
        "RoleName": "net-lab-flow-logs-role",
        "RoleId": "AROAWX67EUCHUM5XZR65P",
        "Arn": "arn:aws:iam::463787565199:role/net-lab-flow-logs-role",
[...]
```

Create and attach the permissions needed by CloudWatch Logs.

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

**Note:** For simplicity, the policy is scoped to cover all resources. In real life, you would scope the policy to the relevant resources.

```bash
$ cat << 'EOF' > /tmp/flow-logs-permissions-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Resource": "*"
    }
  ]
}
EOF

$ aws iam put-role-policy \
      --role-name net-lab-flow-logs-role \
      --policy-name FlowLogsToCloudWatch \
      --policy-document file:///tmp/flow-logs-permissions-policy.json
```

**Enable VPC FlowLogs:** With the logs group and role in place, you can now enable the FlowLogs for the VPC.

```bash
$ ROLE_ARN=$(aws iam get-role --role-name net-lab-flow-logs-role --query "Role.Arn" --output text)

$ aws ec2 create-flow-logs \
      --resource-type VPC \
      --resource-ids $VPC_ID \
      --traffic-type ALL \
      --log-destination-type cloud-watch-logs \
      --log-group-name /vpc/net-lab-flow-logs \
      --deliver-logs-permission-arn $ROLE_ARN

{
    "ClientToken": "FECSFzv2/+wXeKRnlX4ftC+UiNvr24JjIt84a9jpW9w=",
    "FlowLogIds": [
        "fl-0c58acd5a4594e219"
    ],
    "Unsuccessful": []
}
```

Verify that the FlowLogs are active.

```bash
$ aws ec2 describe-flow-logs \
      --filter "Name=resource-id,Values=$VPC_ID" \
      --query "FlowLogs[*].{ID:FlowLogId,Status:FlowLogStatus,TrafficType:TrafficType,Destination:LogDestinationType,LogGroup:LogGroupName}" \
      --output table

-------------------------------------------------------------------------------------------------
|                                       DescribeFlowLogs                                        |
+------------------+------------------------+--------------------------+---------+--------------+
|    Destination   |          ID            |        LogGroup          | Status  | TrafficType  |
+------------------+------------------------+--------------------------+---------+--------------+
|  cloud-watch-logs|  fl-0c58acd5a4594e219  |  /vpc/net-lab-flow-logs  |  ACTIVE |  ALL         |
+------------------+------------------------+--------------------------+---------+--------------+
```

You should see the FlowLogs status as `ACTIVE` and all traffic routed to cloud-watch-logs.

**Generate Traffic and Query the Logs:** FlowLogs have a 1 to 5 minute delay before records appear. Try to generate some traffic on the web page. The first curl command is normal traffic, while the second and third `curl` commands probe blocked ports.

```bash
$ WEB_IP=$(aws ec2 describe-instances \
      --filters "Name=tag:Name,Values=net-lab-web-server" "Name=instance-state-name,Values=running" \
      --query "Reservations[0].Instances[0].PublicIpAddress" --output text)

$ echo "Web server IP: $WEB_IP"

Web server IP: 44.220.168.187$ curl -s http://$WEB_IP | head -5

<html>
<head><title>Network Lab - Web Server</title></head>
<body>
<h1>Network Visibility Lab</h1>
<p><strong>Instance:</strong> i-0ca352ad11139dc4f</p>$ curl -s --connect-timeout 3 http://$WEB_IP:8443

$ curl -s --connect-timeout 3 http://$WEB_IP:3306
```

Wait 2-3 minutes, then navigate to CloudWatch and then Logs Insights in the Console. Set the time range for the last 15 minutes and select the log group you just created. You can then run queries for investigation.

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

![Select 15 minutes on the timescale, select the log groups, add a query and run.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1777972797883.png)

Try running the following queries.

1. See all recent FlowLogs records.

```bash
fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, protocol, packets, bytes, action
| sort @timestamp desc
| limit 20
```

2. Find all rejected entries.

```bash
fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, protocol, packets, bytes
| filter action = "REJECT"
| sort @timestamp desc
| limit 20
```

3. Summarize rejected traffic by source IP and destination port.

```bash
fields srcAddr, dstPort, protocol
| filter action = "REJECT"
| stats count(*) as rejectedFlows by srcAddr, dstPort
| sort rejectedFlows desc
| limit 10
```

**Verify:** By running the previous queries, you can quickly verify that the FlowLogs are in place and capture VPC traffic.

![CloudWatch Logs Insights showing the output of the REJECT query.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1777987877328.png)

Run the helper function to check the setup.

```bash
$ aws lambda invoke \
        --function-name AWS304-VerifyRemediation \
        --payload '{}' \
        --cli-binary-format raw-in-base64-out \
        /tmp/verify-remediation.json && python3 -m json.tool /tmp/verify-remediation.json

[...]
{
    "status": "PASS",
    "flow_log_check": "PASS - net-lab-vpc has 1 active Flow Log(s) sending to CloudWatch Logs",
    "flag": "[REDACTED]"
}
```

**Answer the questions below**

> What traffic filter should you use when enabling FlowLogs for security monitoring?
> 

ALL

> What flag is returned after successfully running the helper function?
> 

THM{OBSERVER_DEPLOYED}

### Task 5 - Build It Securely

So how would you build this securely from the start? 

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

**FlowLogs Are a Non-Negotiable Baseline**

VPC FlowLogs should be enabled for every VPC from the moment it is created. Without them, you cannot investigate network-related incidents, detect anomalous traffic patterns, verify that security groups and NACLs are effective, or meet compliance requirements for network logging.

**Choose the Right Destination:** The choice between CloudWatch Logs and S3 depends on your use case:

| **Factor** | **CloudWatch Logs** | **Amazon S3** |
| --- | --- | --- |
| **Real-time queries** | Yes (Logs Insights) | No (requires Athena or external tools) |
| **Alerting** | Yes (Metric Filters + Alarms) | No (requires a separate pipeline) |
| **Cost (high volume)** | Higher | Lower |
| **Long-term retention** | Possible but expensive at scale | Designed for this |
| **SIEM integration** | Via subscription filters | Via S3 event notifications |

Use CloudWatch Logs for short-term operational visibility and alerting (14–30 days), and S3 for long-term archival and compliance (90+ days). You can enable both destinations on the same VPC.

**Create the Secure Log Group:** Apply security measures when creating the CloudWatch log group.

```bash
$ aws logs create-log-group --log-group-name /vpc/production-flow-logs

$ aws logs put-retention-policy \
      --log-group-name /vpc/production-flow-logs \
      --retention-in-days 90
```

For production environments, encrypt the log group with a KMS key.

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

**Note:** You do not need to run this command to complete the lab.

```bash
$ aws logs associate-kms-key \
    --log-group-name /vpc/production-flow-logs \
    --kms-key-id arn:aws:kms:us-east-1:${ACCOUNT_ID}:key/YOUR-KEY-ID
```

**Create a Least-Privilege IAM Role**

The IAM role for FlowLogs should have only the permissions it needs, nothing more. Before writing any IAM resource, answer these four questions:

1. What AWS service will assume this role? - `vpc-flow-logs.amazonaws.com`.
2. What API actions does it need? - write streams and log events to CloudWatch Logs.
3. What specific resources does it access? - the specific production log group, not all log groups.
4. Are there conditions that should limit access further? - yes; scope the trust policy to your AWS account.

Example of a resource-scoped to a specific log group permissions policy.

```bash
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowFlowLogsToCloudWatch",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Resource": "arn:aws:logs:us-east-1:ACCOUNT_ID:log-group:/vpc/production-flow-logs:*"
    }
  ]
}
```

Trust policy with `aws:SourceAccount` condition.

```bash
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "aws:SourceAccount": "ACCOUNT_ID"
        }
      }
    }
  ]
}
```

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

**Note:** The `aws:SourceAccount` condition in the trust policy prevents the confused deputy problem; it ensures only your account can use this role for FlowLogs, even if the FlowLogs service principal could otherwise be used by another account to assume it.

**Enable FlowLogs with Best Practice Settings**

```bash
$ VPC_ID=$(aws ec2 describe-vpcs \
        --filters "Name=tag:Name,Values=net-lab-vpc" \
        --query "Vpcs[0].VpcId" --output text)

$ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

$ aws ec2 create-flow-logs \
      --resource-type VPC \
      --resource-ids $VPC_ID \
      --traffic-type ALL \
      --log-destination-type cloud-watch-logs \
      --log-group-name /vpc/production-flow-logs \
      --deliver-logs-permission-arn arn:aws:iam::${ACCOUNT_ID}:role/production-flow-logs-role \
      --max-aggregation-interval 60 \
      --tag-specifications 'ResourceType=vpc-flow-log,Tags=[{Key=Environment,Value=production},{Key=ManagedBy,Value=security-team}]'

{
    "ClientToken": "rE0vkVbLLAgNOwUIjhNbuiU9KdV00W2/z4LizNg3DZk=",
    "FlowLogIds": [
        "fl-0cf7f49ad93a37eb9"
    ],
    "Unsuccessful": []
}
```

Key settings:

- `traffic-type ALL` - Capture both ACCEPT and REJECT. You need both for a complete security picture.
- `max-aggregation-interval 60` - 1-minute aggregation gives near-real-time visibility. The default is 10 minutes, which is too slow for incident response.
- `tags` - Tag your FlowLogs for cost tracking and governance.

**Build Reusable Security Queries:** With FlowLogs in place, build a library of queries for ongoing security monitoring. Log Insights lets you save queries so you can run them later.

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

![Save a query by inputting a name, selecting the query language, logs, and query text.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1778046528874.png)

Here are a few useful examples.

**Scanning detection** - top rejected connections by source.

```bash
fields srcAddr, dstPort
| filter action = "REJECT"
| stats count(*) as rejections by srcAddr, dstPort
| sort rejections desc
| limit 20
```

**Exfiltration detection** - top talkers by bytes transferred.

```bash
fields srcAddr, dstAddr, bytes
| filter action = "ACCEPT"
| stats sum(bytes) as totalBytes by srcAddr, dstAddr
| sort totalBytes desc
| limit 20
```

**C2 detection** - outbound connections on non-standard ports.

```bash
fields @timestamp, srcAddr, dstAddr, dstPort, bytes
| filter action = "ACCEPT"
  and srcAddr like /^10\./
  and dstAddr not like /^10\./
  and dstPort != 80
  and dstPort != 443
  and dstPort != 53
| sort bytes desc
| limit 20
```

**Network Visibility Checklist**

- VPC FlowLogs enabled at the VPC level with `ALL` traffic filter.
- Log group created with appropriate retention policy (90+ days for production).
- IAM role created with least-privilege permissions scoped to the specific log group.
- Trust policy includes `aws:SourceAccount` condition to prevent the confused deputy problem.
- Log group encrypted with KMS (production environments).
- Standard security queries documented and ready to run.
- Cost monitoring in place for Flow Log expenses.
- Flow Log status verified as `ACTIVE` after creation.

Run the helper function to retrieve the flag for this task.

```bash
$ aws lambda invoke \
      --function-name AWS304-VerifySecureBuild \
      --payload '{}' \
      --cli-binary-format raw-in-base64-out \
      /tmp/verify-secure-build.json && python3 -m json.tool /tmp/verify-secure-build.json

[...]
{
    "status": "PASS",
    "log_group_check": "PASS - /vpc/production-flow-logs exists with 90-day retention",
    "flow_log_check": "PASS - 1 active Flow Log(s) with ALL traffic targeting /vpc/production-flow-logs",
    "flag": "[REDACTED]"
}
```

**Answer the questions below**

> When choosing between CloudWatch Logs and S3 for FlowLogs, which destination supports near real-time queries and alerting?
> 

CloudWatch Logs

> What condition key should you add to the FlowLogs IAM role trust policy to prevent the confused deputy problem?
> 

aws:SourceAccount

> What flag is returned by the helper function?
> 

THM{VOID_ILLUMINATED}

### Task 6 - Conclusion

You have taken a completely blind VPC with zero network visibility and built a fully instrumented environment with VPC FlowLogs, real-time query capability, and a library of security-focused detection queries.

**Key Takeaways**

- **Enable FlowLogs on every VPC from day one** - they are your network-layer audit trail, equivalent to CloudTrail for API calls. There is no retrospective. If logs were not running when an incident occurred, that evidence is gone forever.
- **Capture ALL traffic, not just REJECT** - REJECT-only logs miss accepted connections to unexpected destinations. ACCEPT-only logs miss scanning attempts. You need both to detect scanning and exfiltration and verify that your security controls are working.
- **Scope IAM roles and use the `aws:SourceAccount` condition** - the FlowLogs IAM role should be resource-scoped to its specific log group and include the confused deputy protection condition in its trust policy.
- **Build and run detection queries proactively** - do not wait for an incident to look at your logs. Build a library of queries for scanning, exfiltration, and C2 detection, and run them regularly to catch anomalies before they become incidents.
- **Use CloudWatch Logs for operations, S3 for archival** - pair short-term real-time monitoring with long-term cost-efficient storage to meet both operational and compliance requirements.
- **FlowLogs capture metadata, not content** - they tell you who connected to whom, on which port, and whether it was accepted or rejected. For packet-level inspection, pair FlowLogs with VPC Traffic Mirroring.
