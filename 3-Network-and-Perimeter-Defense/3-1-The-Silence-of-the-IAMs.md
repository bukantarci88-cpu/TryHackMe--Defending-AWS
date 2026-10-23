# AWS Security 3.1. The Silence of the IAMs

### Task 1 - Introduction

A developer builds a web application on EC2 and needs a web server, SSH access for management, and a MySQL database. As it happens, most of the time, the eager cloud admin creates a single security group, opening the needed ports to the entire internet. The web app works, so nobody revisited the setup.

**Learning Objectives**

- Identify overly permissive rules in SG
- Remove and replace SG rules with scoped, least-privilege alternatives
- Use SG2SG references for inter-tier communication
- Understand a multi-tier SG strategy to separate public/private access

### Task 2 - Real-World Incident

 The MongoDB Apocalypse, primarily occurred in early 2017.

During January 2017, security researchers Victor Gevers and Niall Merrigan tracked a wave of attacks targeting publicly exposed MongoDB databases. Within days, the incident escalated from hundreds to thousands of compromised databases.

The affected databases were hosted on major cloud platforms, such as AWS, DigitalOcean, and OVH, running on virtual machines that allowed public access to 27017, the default MongoDB port. Needless to say, the databases had little to no authentication.

**What Happened**

![Attack path showing discovery of unprotected DBs, exfiltration, ransom and deletion.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1782373236111.png)

1. **Scanning**: Attackers used automated scripts to scan the entire internet for hosts with port 27017 open. Tools like Shodan had already indexed thousands of publicly exposed MongoDB instances as early as 2015.
2. **Connection:** With the list at hand, the attackers used MongoDB clients to connect to the databases. Most lacked authentication or used default credentials.
3. **Data Theft**: Once connected, the attackers enumerated the databases, exfiltrated sensitive data, and deleted all collections on the victim instance.
4. **Ransom Note:** In place of the original data, the victims found a single collection containing a ransom demand and instructions on how to pay.
5. **Escalation**: Multiple hacking groups joined the campaign. By mid-January 2017, over 27k databases were wiped out. Later that year, by September, that number grew to 45k+, and the attack spread to other databases, including Elasticsearch, Hadoop, CouchDB, Cassandra, and MySQL.

**Core Failures**

- **Open Security Group (SG) / Firewall (FW) Rules**: The virtual machines running the DB instances had security groups or firewalls that had the default database port open to the internet.
- **No Authentication**: MongoDB's default configuration at the time did not require a username and password.
- **No Backups**: Most of the affected entities had no database backups and were forced to pay the ransom. Even so, they never received their data, as the attackers had not actually copied it.

**Answer the questions below**

> In relation to AWS, what is the primary network-layer service that was misconfigured?
> 

 Security Groups

### Task 3 - Identification

List all running EC2 instances.

```bash
$ aws ec2 describe-instances \
    --filters "Name=instance-state-name,Values=running" \
    --query "Reservations[].Instances[].{InstanceId:InstanceId,Name:Tags[?Key=='Name']|[0].\
Value,SecurityGroups:SecurityGroups[0].GroupName,SubnetId:SubnetId,PrivateIp:PrivateIpAddress,\
PublicIp:PublicIpAddress}" \
    --output table

------------------------------------------------------------------------------------------------------------------------
|                                                   DescribeInstances                                                  |
+---------------------+----------------+-------------+-----------------+------------------+----------------------------+
|     InstanceId      |     Name       |  PrivateIp  |    PublicIp     | SecurityGroups   |         SubnetId           |
+---------------------+----------------+-------------+-----------------+------------------+----------------------------+
|  i-03791d6136f84c91c|  thm-db-server |  10.0.2.10  |  None           |  thm-db-sg       |  subnet-079bb5f9d81b382f5  |
|  i-020fef623f73d51fc|  thm-web-app   |  10.0.1.131 |  34.239.251.118 |  thm-web-app-sg  |  subnet-07a9a196c569bfe60  |
+---------------------+----------------+-------------+-----------------+------------------+----------------------------+
```

**FINDING**: There are two instances running, prefixed with `thm-`. The web app instance is accessible from the internet, while the database instance is in a private subnet (denoted by the lack of a public IP address). 

The web application server has a security group attached. Inspect the rules with the following command.

```bash
$ aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=thm-web-app-sg" \
    --query "SecurityGroups[].{GroupId:GroupId,GroupName:GroupName,InboundRules:IpPermissions}" \
    --output json

[
    {
        "GroupId": "sg-0e902238e17241286",
        "GroupName": "thm-web-app-sg",
        "InboundRules": [
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
[...]
```

To see the details in a simpler format, run the following command for the Inbound SG rules.

**Note:** The output will also show the `Allow all` outbound rule. This can be safely ignored for now.

```bash
$ WEB_SG_ID=$(aws ec2 describe-security-groups --filters \
'Name=group-name,Values=thm-web-app-sg' --query 'SecurityGroups[0].GroupId' --output text)

$ aws ec2 describe-security-group-rules \
    --filters "Name=group-id,Values=$WEB_SG_ID" \
    --query "SecurityGroupRules[].{Protocol:IpProtocol,FromPort:FromPort,\
    ToPort:ToPort,Source:CidrIpv4,Description:Description}" \
    --output table

-----------------------------------------------------------------------
|                     DescribeSecurityGroupRules                      |
+---------------------+-----------+-----------+------------+----------+
|     Description     | FromPort  | Protocol  |  Source    | ToPort   |
+---------------------+-----------+-----------+------------+----------+
|  SSH access         |  22       |  tcp      |  0.0.0.0/0 |  22      |
|  Allow all outbound |  -1       |  -1       |  0.0.0.0/0 |  -1      |
|  MySQL access       |  3306     |  tcp      |  0.0.0.0/0 |  3306    |
|  HTTP access        |  80       |  tcp      |  0.0.0.0/0 |  80      |
+---------------------+-----------+-----------+------------+----------+
```

**FINDING**: The web app exposes ports 22, 80, and 3306 to the entire internet, as shown by the  `0.0.0.0/0` source CIDR on each inbound rule.

Verify the database security group as well.

```bash
$ DB_SG_ID=$(aws ec2 describe-security-groups --filters \
  'Name=group-name,Values=thm-db-sg' --query 'SecurityGroups[0].GroupId' --output text)

$ aws ec2 describe-security-group-rules \
    --filters "Name=group-id,Values=$DB_SG_ID" \
    --query "SecurityGroupRules[].{Protocol:IpProtocol,FromPort:FromPort,\
    ToPort:ToPort,Source:CidrIpv4,Description:Description}" \
    --output table

------------------------------------------------------------------------
|                      DescribeSecurityGroupRules                      |
+----------------------+-----------+-----------+------------+----------+
|      Description     | FromPort  | Protocol  |  Source    | ToPort   |
+----------------------+-----------+-----------+------------+----------+
|  Allow all outbound  |  -1       |  -1       |  0.0.0.0/0 |  -1      |
|  MySQL from anywhere |  3306     |  tcp      |  0.0.0.0/0 |  3306    |
+----------------------+-----------+-----------+------------+----------+
```

**FINDING**: The database security group also allows port 3306 to be accessible from anywhere.

**Findings Summary**

- **Port 22 (SSH) from 0.0.0.0/0 on the web app** - SSH is a management protocol, and exposing it to the entire internet increases the attack surface of the infrastructure. This is an unsafe setup.
- **Port 80 (HTTP) from 0.0.0.0/0 on the web app** - Since this is a public-facing web application, this configuration is ok. The recommendation here would be to transition to a secure HTTP connection (HTTPS/443).
- **Port 3306 (MySQL) from 0.0.0.0/0 on both the web app and the DB** - This is the database port widely open to the entire internet and the core misconfiguration of the MongoDB Apocalypse.

Before moving on to the next step, make sure you understand these core concepts about Security Groups:

- **Stateful**: If an inbound rule allows traffic in, the return traffic is automatically allowed out. By contrast, NACLs are stateless, meaning traffic rules need to be specified for both inbound and outbound connections.
- **Allow-only**: SGs have an implicit deny, meaning that if the package does not match any defined rules, it is dropped.
- **Instance-level**: SGs are attached to instance elastic network interfaces (ENIs). Each ENI can have up to five SGs by default, and all rules are combined when matching the traffic.

**Answer the questions below**

> How many inbound rules does the thm-web-app-sg security group have?
> 

3 

MySQL access (Port 3306 from 0.0.0.0/0)

HTTP access (Port 80 from 0.0.0.0/0)

SSH access (Port 22 from 0.0.0.0/0)

> Which port on the web app is expected to be opened and what is the safer port to use? Answer in the format port/port
> 

80/443 ports **80** and **443** are used for web applications

> By default, an Amazon EC2 instance network interface can have how many security groups associated with it?
> 

5 

By default, an Amazon EC2 instance network interface (ENI) can have up to **5** security groups associated with it.

### Task 4 - Remediation

You have identified two critical findings: port 22 (SSH) and port 3306 (MySQL) are publicly open.

Before you jump into it, here is the strategy:

1. Remove the 0.0.0.0/0 rule on port 22 from the web app SG - you can use SSM Session Manager for administrative access.
2. Remove the 0.0.0.0/0 rule on port 3306 from the web app SG - there is no need for this rule on the web app instance.
3. Replace the 0.0.0.0/0 rule on port 3306 on the database SG - you will allow only the web app SG to connect (SG2SG reference).
4. Verify everything still works.

It's hammer time. First, if not done so in the previous task, save the SG IDs as you will need them later.

```bash
$ export WEB_SG_ID=$(aws ec2 describe-security-groups \
      --filters "Name=group-name,Values=thm-web-app-sg" \
      --query "SecurityGroups[0].GroupId" --output text)

$ export DB_SG_ID=$(aws ec2 describe-security-groups \
      --filters "Name=group-name,Values=thm-db-sg" \
      --query "SecurityGroups[0].GroupId" --output text)

$ echo "Web App SG ID: $WEB_SG_ID | Database SG ID: $DB_SG_ID"

Web App SG ID: sg-0e902238e17241286 | Database SG ID: sg-079a52004890795d8
```

Remove the SSH rule from the web app SG.

```bash
$ aws ec2 revoke-security-group-ingress \
    --group-id $WEB_SG_ID \
    --protocol tcp \
    --port 22 \
    --cidr 0.0.0.0/0

{
    "Return": true,
    "RevokedSecurityGroupRules": [
        {
            "SecurityGroupRuleId": "sgr-0445863a5dc7f620c",
            "GroupId": "sg-0e902238e17241286",
            "IsEgress": false,
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "CidrIpv4": "0.0.0.0/0",
            "Description": "SSH access"
        }
    ]
}
```

Remove the MySQL rule from the web app SG.

```bash
$ aws ec2 revoke-security-group-ingress \
    --group-id $WEB_SG_ID \
    --protocol tcp \
    --port 3306 \
    --cidr 0.0.0.0/0

{
    "Return": true,
    "RevokedSecurityGroupRules": [
        {
            "SecurityGroupRuleId": "sgr-047ff3dae92d2df02",
            "GroupId": "sg-0e902238e17241286",
            "IsEgress": false,
            "IpProtocol": "tcp",
            "FromPort": 3306,
            "ToPort": 3306,
            "CidrIpv4": "0.0.0.0/0",
            "Description": "MySQL access"
        }
    ]
}
```

Replace the MySQL rule on the database SG with a scoped one.

```bash
$ aws ec2 revoke-security-group-ingress \
    --group-id $DB_SG_ID \
    --protocol tcp \
    --port 3306 \
    --cidr 0.0.0.0/0

{
    "Return": true,
    "RevokedSecurityGroupRules": [
        {
            "SecurityGroupRuleId": "sgr-0fc2557eafce5a7a1",
            "GroupId": "sg-079a52004890795d8",
            "IsEgress": false,
            "IpProtocol": "tcp",
            "FromPort": 3306,
            "ToPort": 3306,
            "CidrIpv4": "0.0.0.0/0",
            "Description": "MySQL from anywhere"
        }
    ]
}$ aws ec2 authorize-security-group-ingress \
    --group-id $DB_SG_ID \
    --protocol tcp \
    --port 3306 \
    --source-group $WEB_SG_ID

{
    "Return": true,
    "SecurityGroupRules": [
        {
            "SecurityGroupRuleId": "sgr-0ff88efb01e16b7ae",
            "GroupId": "sg-079a52004890795d8",
            "GroupOwnerId": "769786922981",
[...]
```

Verify the web app SG now shows only port 80.

```bash
$ aws ec2 describe-security-group-rules \
      --filters "Name=group-id,Values=$WEB_SG_ID" \
      --query "SecurityGroupRules[].{Protocol:IpProtocol,FromPort:FromPort,\
      ToPort:ToPort,Source:CidrIpv4,Description:Description}" \
      --output table

-----------------------------------------------------------------------
|                     DescribeSecurityGroupRules                      |
+---------------------+-----------+-----------+------------+----------+
|     Description     | FromPort  | Protocol  |  Source    | ToPort   |
+---------------------+-----------+-----------+------------+----------+
|  Allow all outbound |  -1       |  -1       |  0.0.0.0/0 |  -1      |
|  HTTP access        |  80       |  tcp      |  0.0.0.0/0 |  80      |
+---------------------+-----------+-----------+------------+----------+
```

Check the web app still works. You can use the CLI commands or open the public web app IP directly in the browser.

```bash
$ WEB_IP=$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=thm-web-app" "Name=instance-state-name,Values=running" \
    --query "Reservations[0].Instances[0].PublicIpAddress" --output text)
$ echo "Web app Public IP: $WEB_IP"

Web app Public IP: 34.239.251.118$ curl -s http://$WEB_IP
<!DOCTYPE html>
<html>
<head>
  <title>THM Web Application</title>
  <style>
[...]
```

Check the web app to see if the database connection still works. First, connect to the instance with SSM.

**Note:** Make sure you have the Web Instance ID. Deployment order might swap the listed EC2s. If this happens, you can use the command from Task 3 and either export the ID directly or replace `0` with `1` in the command below.

```bash
$ export WEB_INSTANCE_ID=$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=thm-web-app" "Name=instance-state-name,Values=running" \
    --query "Reservations[0].Instances[0].InstanceId" --output text)
$ aws ssm start-session --target $WEB_INSTANCE_ID

Starting session with SessionId: 769786922981-oa4xx8jgq35vka7yri983ctxry
sh-5.2$
```

Then test the connection from the instance using the `nc` tool.

```bash
Starting session with SessionId: 769786922981-oa4xx8jgq35vka7yri983ctxry

sh-5.2$ nc -v 10.0.2.10 3306 -w 3 < /dev/null

Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 10.0.2.10:3306.
5.7.44-thm-lab
[REDACTED]
Ncat: 0 bytes sent, 42 bytes received in 0.01 seconds.
```

You should see a successful connection (and a flag). This means the SG2SG works as expected.

Lastly, you can run the Lambda helper function to verify the remediation. Make sure you run the command outside the EC2 SSM session or in a separate CloudShell tab.

```bash
$ aws lambda invoke \
    --function-name AWS301-VerifyRemediation \
    --payload '{}' \
    /tmp/out.json && python3 -m json.tool /tmp/out.json

[...]
{
    "ssh_check": "PASS - SSH (22) no longer open to 0.0.0.0/0 on web SG",
    "mysql_web_check": "PASS - MySQL (3306) no longer open to 0.0.0.0/0 on web SG",
    "mysql_db_check": "PASS - MySQL (3306) no longer open to 0.0.0.0/0 on database SG",
    "sg_ref_check": "PASS - database SG uses SG reference for MySQL access",
    "status": "PASS",
    "flag": "[REDACTED]"
}
```

**Answer the questions below**

> What is the flag in the web app webpage?
> 

THM{NEVER_GET_OUT_OF_THE_BOAT}

> What is the flag served by the database service?
> 

THM{NAPALM_IN_THE_MORNING}

> What is the flag when running the verification function?
> 

THM{LISTEN_TO_THE_COLONEL}

### Task 5 - Build It Securely

You successfully remediated the misconfiguration, but how would you build it securely from day one?

In this task, you will implement a pattern for deploying a secure multi-tier application in AWS.

To help you in the long run, make sure you internalize these principles:

- **Default deny** - SGs are created with no inbound rules, start from that baseline and add only what is needed.
- **One SG per role** - Instead of assigning SGs to instances, think in terms of roles, such as "web tier", "database tier", or "management".
- **Use SG references** - Instead of hardcoding IPs or CIDRs, it's always better for internal communication to reference other SGs.
- **Controlled management ports** - SSH, RDP or other management ports should be restricted to known trusted sources or replaced entirely with management access, for example, SSM Session Manager.
- **Egress rules** - By default, outbound rules allow all traffic to all destinations. For sensitive workloads, restrict outbound traffic to only specific destinations, such as applications, S3 endpoints, and API endpoints.

Let's get to work. Grab the VPC ID and create a web tier SG.

```bash
$ export VPC_ID=$(aws ec2 describe-vpcs \
      --filters "Name=tag:Name,Values=thm-vpc" \
      --query "Vpcs[0].VpcId" --output text)

$ echo "VPC: $VPC_ID"

VPC: vpc-05a12a6545e616b9b$ WEB_SG_NEW=$(aws ec2 create-security-group \
    --group-name thm-secure-web-sg \
    --description "Secure web tier - HTTP/HTTPS from internet only" \
    --vpc-id $VPC_ID \
    --tag-specifications 'ResourceType=security-group,Tags=[{Key=Name,Value=thm-secure-web-sg}]' \
    --query "GroupId" --output text)

$ echo "Web tier SG: $WEB_SG_NEW"

Web tier SG: sg-0e5c1d80795bbb80c
```

Add inbound for the web app.

```bash
$ aws ec2 authorize-security-group-ingress \
    --group-id $WEB_SG_NEW \
    --ip-permissions \
      "IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges=[{CidrIp=0.0.0.0/0,Description='HTTP from internet'}]" \
      "IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=0.0.0.0/0,Description='HTTPS from internet'}]"

{
    "Return": true,
    "SecurityGroupRules": [
        {
            "SecurityGroupRuleId": "sgr-0508aeda73b3b1e58",
            "GroupId": "sg-090488485d539241a",
            "GroupOwnerId": "131651247396",
            "IsEgress": false,
            "IpProtocol": "tcp",
[...]
```

Create a database tier SG.

```bash
$ DB_SG_NEW=$(aws ec2 create-security-group \
    --group-name thm-secure-db-sg \
    --description "Secure data tier - MySQL from web tier SG only" \
    --vpc-id $VPC_ID \
    --tag-specifications 'ResourceType=security-group,Tags=[{Key=Name,Value=thm-secure-db-sg}]' \
    --query "GroupId" --output text)

$ echo "Database tier SG: $DB_SG_NEW"

Database tier SG: sg-08c6154c22fba6f9f
```

Add scoped inbound.

```bash
$ aws ec2 authorize-security-group-ingress \
    --group-id $DB_SG_NEW \
    --protocol tcp \
    --port 3306 \
    --source-group $WEB_SG_NEW

{
    "Return": true,
    "SecurityGroupRules": [
        {
            "SecurityGroupRuleId": "sgr-0b918a915b15908f9",
            "GroupId": "sg-0789f7634264f2c04",
            "GroupOwnerId": "131651247396",
            "IsEgress": false,
            "IpProtocol": "tcp",
            "FromPort": 3306,
            "ToPort": 3306,
            "ReferencedGroupInfo": {
                "GroupId": "sg-090488485d539241a",
                "UserId": "131651247396"
            },
            "SecurityGroupRuleArn": "arn:aws:ec2:us-east-1:131651247396:security-group-rule/sgr-0b918a915b15908f9"
        }
    ]
}
```

Restrict egress traffic on the database tier. Services like SSM, CloudWatch, or S3 communicate over HTTPS via VPC endpoints.

```bash
$ aws ec2 revoke-security-group-egress \
    --group-id $DB_SG_NEW \
    --ip-permissions "IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]"

{
    "Return": true,
    "RevokedSecurityGroupRules": [
        {
            "SecurityGroupRuleId": "sgr-09ee1f2013ed872f8",
            "GroupId": "sg-0789f7634264f2c04",
            "IsEgress": true,
            "IpProtocol": "-1",
            "FromPort": -1,
            "ToPort": -1,
            "CidrIpv4": "0.0.0.0/0"
        }
    ]
}$ aws ec2 authorize-security-group-egress \
    --group-id $DB_SG_NEW \
    --ip-permissions \
      "IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=10.0.0.0/16,Description='HTTPS to VPC endpoints'}]"

{
    "Return": true,
    "SecurityGroupRules": [
        {
            "SecurityGroupRuleId": "sgr-0ca49a029c7d35541",
            "GroupId": "sg-0789f7634264f2c04",
            "GroupOwnerId": "131651247396",
            "IsEgress": true,
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "CidrIpv4": "10.0.0.0/16",
            "Description": "HTTPS to VPC endpoints",
            "SecurityGroupRuleArn": "arn:aws:ec2:us-east-1:131651247396:security-group-rule/sgr-0ca49a029c7d35541"
        }
    ]
}
```

You have created SGs with a secure approach and a well-defined scope. In a real environment, the next step would be to attach them to the scoped instances.

Run the helper Lambda function to see that everything is set up correctly.

```bash
$ aws lambda invoke \
    --function-name AWS301-VerifySecureBuild \
    --payload '{}' \
    /tmp/out.json && python3 -m json.tool /tmp/out.json

[...]
{
    "secure_web_sg_check": "PASS - thm-secure-web-sg has HTTP and HTTPS only",
    "secure_db_sg_check": "PASS - thm-secure-db-sg allows MySQL from web SG reference only",
    "status": "PASS",
    "flag": "[REDACTED]"
}
```

**Common Secure Patterns**

Before we wrap up, here are some other security patterns you can use:

- **Three-tier architecture** - This adds a middle layer between the web tier and data tier. This ensures the database never talks directly to the web tier. The flow is Web Tier -> Application Tier -> Database Tier.
- **Bastion / Jump host** This is a traditional approach, but if you must use SSH, create a dedicated bastion SG with tight restrictions around inbound/outbound and source/destination rules. Whenever possible, use SSM instead.
- **Microservices** - Each service gets its own SG. This creates an explicit, auditable communication map.

**Answer the questions below**

> What AWS service is preferred instead of opening SSH access?
> 

 SSM

> What is the flag revealed when you successfully run the checker function?
> 

THM{APOCALYPSE_AVERTED}

### Task 6 - Conclusion

Very well done. You have secured a web app deployment while still keeping functionality. This is no small feat, so you should take pride in it.

**Key Takeaways**

- **Never expose management or critical services ports**: SSH (22), RDP (3389), MySQL (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379), Elasticsearch (9200), or the likes should never be reachable from the internet.
- **Use SG2SG for inter-tier communication**: Instead of hardcoded IP/CIDR, reference security groups. This will also help with scaling and make auditing easier.
- **Stateful and allow-only**: Security groups cannot override a permissive rule; you must remove the rule and design your flow accordingly.
- **Avoid inbound from anywhere**: Inbound rules that allow access from 0.0.0.0/0 should be treated carefully and scoped where possible.
- **Egress rules**: sensitive tiers should have egress rules to limit the blast radius in the event of a compromise.
- **Regular audit**: avoid the "I'll scope it later" mindset and regularly audit your security groups for "temp" rules added in a hurry.
