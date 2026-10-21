# AWS 1.5. Introduction to Cloud Computing

### Task 1 - Introduction

Computing is the engine of the cloud. No matter if you run web applications, process data, or deploy security tools, there is always some form of compute service behind it. In this room, you will understand how AWS provides compute services with a focus on EC2.

**Learning Objectives**

- Understand main AWS compute services and when to use them
- Learn EC2 core concepts
- Connect to EC2 and inspect configurations
- Understand the "pets vs cattle" concept

### Task 2 - AWS Compute Services

AWS offers different levels of compute services, each suited for different use cases.

- **Elastic Compute Cloud (EC2)** - your basic virtual machine in the cloud. Full flexibility in choosing the operating system, installed software, network configuration, and patch management.
- **Elastic Container Service (ECS/EKS)** - you package your applications into container images, and AWS runs them for you.
- **Serverless (Lambda)** - you provide the code for the function, and AWS handles everything else, like provisioning, scaling, and patching.

**Responsibility Spectrum:** Below is a bite-sized overview of the responsibilities.

| **Service** | **You Manage** | **AWS Manages** |
| --- | --- | --- |
| **EC2** | OS, patches, applications, data, and security configuration | Hardware, hypervisor, physical security |
| **Containers** | Application code, dependencies, task configuration | Host OS (Fargate), orchestrator |
| **Lambda** | Code, IAM role, triggers | Provisioning, scaling, patching |

**Security Best Practices**

- Data and access always fall under your responsibility, so make sure you secure those first.
- Understanding compute requirements is necessary to properly assess which compute service to use and how much you need to secure it.
- Use EC2s when you need full OS control, a custom software stack, or long-running processes.
- Use containers when you want consistent deployments across environments and a faster startup than VMs.
- Use Lambdas when you have event-driven, decoupled, and short-lived tasks.

**Practical Exercise**

1. Log in to the AWS Console with the provided credentials. **Note:** Make sure you are in the right region (`us-east-1`).
2. Navigate to the EC2 dashboard.

![Navigate to EC2 service](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1771581241430.png)

1. You can see the details of an EC2 by navigating to the EC2 link and then selecting the instance:
- **Details** - Provides additional information about the EC2 instance (Hostname, VPC, Subnet, Public DNS).
- **Status and alarms** - Provides instance health information and alerts status.
- **Monitoring** - Graphs dashboard providing multiple metrics tracking at a glance (CPU, Network).
- **Security** - Provides details about the Security Groups and opened ports.
- **Networking** - Network configuration overview (IP Addresses, Hostname and DNS, Network Interfaces, Elastic IP addresses).
- **Storage** - Storage details and metrics.
- **Tags** - Instance-associated tags and descriptions.

![Find the EC2 instance details](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1771603062694.png)

1. Alternatively, you can run the following command from CloudShell or AWS CLI.

```bash
           $ aws ec2 describe-instances \
            --filters "Name=instance-state-name,Values=running" \
            --query "Reservations[*].Instances[*].{ID:InstanceId,Type:InstanceType,Name:Tags[?Key=='Name']|[0].Value,AZ:Placement.AvailabilityZone,PublicIP:PublicIpAddress}" \
            --output table

----------------------------------------------------------------------------------
|                                DescribeInstances                               |
+------------+-----------------------+-------------+-----------------+-----------+
|     AZ     |          ID           |    Name     |    PublicIP     |   Type    |
+------------+-----------------------+-------------+-----------------+-----------+
|  us-east-1a|  i-0bb9912130618cb20  |  [REDACTED] |  100.53.120.191 |  t2.nano  |
+------------+-----------------------+-------------+-----------------+-----------+
```

**Answer the questions below**

> Which compute option gives you the most control and also the most responsibility?
> 

EC2

> Which service would you use to run code without provisioning the required infrastructure?
> 

Lambda

> What is the name of the lab instance?
> 

room15-web

### Task 3 - EC2 Core Concepts

Now, the Elastic Compute Cloud (EC2) is the run-of-the-mill virtual machine you know and love. It can scale horizontally (by increasing the number of instances) and vertically (by increasing instance resources), change IPs, support multiple disks, communicate with different services, and much more. Now, let us understand some basic concepts around EC2s.

**Amazon Machine Images**

An Amazon Machine Image (AMI) is a template containing the OS, software, and configuration. When launching an instance, you can select from AWS official AMIs or your own custom AMI. Creating custom AMIs is easy: you bake a hardened, patched, and application-ready instance and save a snapshot as an AMI.

Amazon and the Community also provide a variety of ready-to-use AMIs. They can be selected during EC2 instance creation either from the Quick Start or by browsing the Marketplace.

![How to select standard AMIs](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772700224950.png)

**Instance Types**

These are the AWS-provided hardware profiles of your virtual machine: CPU, memory, storage, and network capacity.

**Note:** Be wary of the costs. While some instances are cheap, others can instantly increase your bill when you power them on. The [AWS Price Calculator](https://calculator.aws/) can help you understand costs before deployment.

They follow a naming convention:

```bash
           t3.micro
││  │
││  └── Size (micro, small, medium, large, xlarge, ...)
│└───── Generation (3)
└────── Family (t = burstable, general purpose)

Common Examples of Families:
t3/t3a - burstable general purpose (good for labs and small workloads)
m5/m6i - balanced general purpose (production workloads)
c5/c6i - compute-optimized (CPU-heavy tasks)
r5/r6i - memory-optimized (databases, caching)
```

**User Data**

User Data is a script that runs automatically when an instance is launched for the first time. Commonly used to install software, configure services, or pull application code. It will not run on subsequent User Data updates or EC2 power cycles.

Example of a simple User Data script that installs the web server.

```bash
           #!/bin/bash
yum update -y
yum install -y httpd
echo "My Web Server" > /var/www/html/index.html
systemctl start httpd
systemctl enable httpd
```

**Key Pairs**

AWS uses Key Pairs for SSH access to Linux Instances. The public key is placed on the instance, while the private key is with you. This is done during instance deployment, but you can also create key pairs for later use.

![Key pair selection on EC2 deployment](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772700623828.png)

A good security consideration is to use the Session Manager service, which provides web-based instance CLI access in a more secure manner.

**Security Best Practices**

- User Data scripts run as root and are stored in the instance metadata, so make sure you do not put credentials or sensitive information there.
- Use AMIs to have hardened, patched, ready-to-use OS or application templates.
- Make sure you tighten access to AMIs since any misconfiguration there will propagate to any new deployment.
- Use Secrets Manager or SSM Parameter Store for sensitive information needed in the User Data script.
- Use Session Manager in favor of SSH access.

**Practical Exercise**

1. In the instance details, identify the AMI used to launch the EC2.

![Identify the AMI used to launch the EC2](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1771582734214.png)

1. Alternatively, you can also use `CloudShell` (or configure AWS CLI on the Attack Box).

```bash
           # This will save the EC2 instance ID for later use
$ INSTANCE_ID=$(aws ec2 describe-instances \
            --filters "Name=tag:Name,Values=room15-web" "Name=instance-state-name,Values=running" \
            --query "Reservations[0].Instances[0].InstanceId" --output text)

$ echo $INSTANCE_ID

i-0bb9912130618cb20$ aws ec2 describe-instances \
            --instance-ids $INSTANCE_ID \
            --query "Reservations[0].Instances[0].{AMI:ImageId,Type:InstanceType,KeyName:KeyName,LaunchTime:LaunchTime}" \
            --output table

------------------------------------------------------------------------------
|                              DescribeInstances                             |
+------------------------+----------+-----------------------------+----------+
|           AMI          | KeyName  |         LaunchTime          |   Type   |
+------------------------+----------+-----------------------------+----------+
|  ami-0f3caa1cf4417e51b |  None    |  2026-02-20T08:56:17+00:00  |  t2.nano |
+------------------------+----------+-----------------------------+----------+
```

1. Let us create a key pair. Locate the `Network & Security` group on the left, then navigate to the `Key Pair` dashboard and click the `Create Key Pair` button on the right.

![Key Pair navigation link](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1771582734368.png)

1. Provide a key name, select `RSA` as type, and `.pem` as format, and then create your key.

![Fill in the key pair creation form](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1771588327495.png)

**Note:** The key `.pem` file will be downloaded, but you will not use it in this room.

1. Now, let us have a closer look at our instance. Navigate back to the EC2 dashboard, select the lab instance, and check the `User Data`.

![Navigate to see the EC2 instance User Data.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1771582734398.png)

1. Can you spot the flag in the User Data? You can also look at this in `CloudShell` (or by configuring AWS CLI on the Attack Box).

**Note:** You should already have the instance ID saved in the variable. If not, rerun the command from step 2.

```bash
           $ aws ec2 describe-instance-attribute \
            --instance-id $INSTANCE_ID \
            --attribute userData \
            --query "UserData.Value" --output text | base64 --decode

#!/bin/bash
yum update -y
yum install -y httpd
systemctl start httpd
systemctl enable httpd# Place flag served by web server
echo "[REDACTED]" > /var/www/html/index.html
```

Excellent. Seems like `User Data` is not a safe place to store secrets.

**Answer the questions below**

> What is the flag found in the instance User Data?
> 

THM{NO_PASSWORDS_HERE}

> Under which user do User Data scripts run as?
> 

root

### Task 4 - Connecting to Instances

Once an instance is running, you need a way to access it. You will need to consider the security advantages and disadvantages when selecting the access method.

**SSH**

This is the traditional approach: you use a private key file and use an SSH connection to connect to the instance's public IP and port (default 22).

EC2 SSH

```bash
           $ ssh -i my-private-key.pem ec2-user@<ec2_public_ip>
```

This requires:

- Port 22 is open in the Security Group associated with the instance.
- A public IP on the instance.
- A key pair configured at launch.

**Session Manager**

This is the recommended approach and provides a browser-based or CLI-based shell session. **Note:** The AWS CLI will require the Session Manager plugin installed.

EC2 SSM

```bash
           $ aws ssm start-session --target <instance_id>
```

This requires:

- SSM Agent (AWS standard AMIs pre-bundle them).
- AWS CLI Session Manager plugin.
- IAM policy granting access.

The SSM Agent on the instance communicates outbound to the AWS SSM service, access is controlled through IAM policies, and every session is logged.

The SSM Session Manager status should be Connected if everything is set up correctly.

**Security Best Practices**

- Prefer SSM over SSH whenever possible.
- If SSH is required, restrict the Security Group to specific IPs and rotate keys regularly.
- Avoid using the default instance users, for example, ec2-user or ubuntu, for production workloads.
- Log all session activity through Session Manager's built-in logging.

**Practical Exercise**

1. Navigate to the lab instance and choose Connect.

![Select and connect to the EC2 instance.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1771583375773.png)

1. Choose SSM Session Manager and Connect.

![Choose SSM Session Manager and connect.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1771583377096.png)

1. A new tab will open, and you should see the instance CLI. Run the `whoami` command.

![SSM instance CLI](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1771585059169.png)

1. From within the instance, you can also retrieve the instance type or other metadata information.

```bash
           # This will store the session token in a variable
$ TOKEN=$(curl -s -X PUT "<http://169.254.169.254/latest/api/token>" \
          -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

$ curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
          <http://169.254.169.254/latest/meta-data/instance-type>
t2.nano
```

You can play with the command and see what other interesting information lies in the instance metadata.

**Answer the questions below**

> What user is showing when you run the `whoami` command?
> 

ssm-user

> What is the IP address you query for instance metadata?
> 

169.254.169.254

### Task 5 - Pets Versus Cattle

When migrating to the cloud, you need to consider a paradigm shift in how you manage the infrastructure. When talking about on-prem versus cloud, you need to move from the 'Pets' model to the 'Cattle' model.

**The Pets Model**

In the usual on-prem environment, servers are like pets. You take care of them, patch them individually, and give them friendly names (e.g., mail server named 'Pidgey'). If a server goes down, rebuilding it from scratch sometimes takes hours or days.

**The Cattle Model**

In the cloud, instances should be treated as cattle. They are identical, replaceable, and easy to spin up or down. Leveraging pre-baked images (AMIs and container images) ensures consistent, scalable deployments.

Here are a couple of advantages of shifting to this model:

- **Immutable infrastructure** - patching, hardening, and configuration updates are built in a new template, which replaces all instances.
- **Reduced attack persistence** - if an attacker compromises an instance, replacing it removes the compromise. Combined with detection, this makes persistence much harder.
- **Reproducibility** - the environment can be deployed as code (Infrastructure as Code), which makes disaster recovery much faster and the infrastructure more reliable.
- **No configuration drift** - servers are configured uniformly and do not accumulate custom changes during their lifecycle.

Below is an example of how this might look in practice.

![Cattle deployment pattern](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1781259084444.png)

**Note:** AutoScaling Group is a logical unit that manages a collection of EC2 instances.

**Security Best Practices**

- Treat instances as "disposables" - design your application or infrastructure so no single instance is irreplaceable.
- Store application state externally (e.g., databases, S3, EFS) and not on the instance itself.
- Automate instance creation through Infrastructure as Code (CloudFormation, Terraform).
- Log everything to dedicated locations and services (CloudWatch, S3).

**Answer the questions below**

> How do you call an infrastructure where you build new AMIs instead of patching individual instances?
> 

Immutable

### Task 6 - Conclusion

- EC2s give you full control over the virtual machine, but also full responsibility for its security.
- Never put secrets in User Data; use AWS dedicated services for storing sensitive information.
- The "cattle not pets" mindset is a good security strategy that reduces drift, limits persistence, and shortens recovery time.
