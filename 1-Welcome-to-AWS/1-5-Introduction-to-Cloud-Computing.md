# TryHackMe - AWS Compute

> **Platform:** TryHackMe\
> **Topic:** AWS Compute\
> **Category:** AWS \| EC2 \| IAM \| Systems Manager \| Cloud Security\
> **Focus:** Compute services, EC2 configuration, secure instance
> access, and immutable infrastructure

------------------------------------------------------------------------

## Overview

AWS compute services provide the processing power needed to run
applications, process data, and deploy security tools. This room focuses
on Amazon Elastic Compute Cloud (EC2), the core concepts behind EC2
instances, methods for connecting to instances, and the **pets versus
cattle** infrastructure model.

## Learning Objectives

-   Understand the main AWS compute services and their use cases.
-   Learn core EC2 concepts.
-   Connect to EC2 instances and inspect their configurations.
-   Understand the pets-versus-cattle approach to infrastructure.

------------------------------------------------------------------------

## 1. AWS Compute Services

AWS offers different compute options depending on how much
infrastructure control is needed.

  -----------------------------------------------------------------------
  Service                 Description             Typical use case
  ----------------------- ----------------------- -----------------------
  **Amazon EC2**          Virtual machines with   Custom software stacks,
                          control over the        full OS control, and
                          operating system,       long-running workloads.
                          software, networking,   
                          and patching.           

  **Amazon ECS / EKS**    Services for running    Consistent deployments
                          containerized           packaged as container
                          applications.           images.

  **AWS Lambda**          Runs code without       Event-driven,
                          requiring you to        decoupled, short-lived
                          provision or manage     tasks.
                          servers. AWS handles    
                          provisioning and        
                          scaling.                
  -----------------------------------------------------------------------

### Shared Responsibility by Compute Type

  -----------------------------------------------------------------------
  Service                 Customer                AWS responsibilities
                          responsibilities        
  ----------------------- ----------------------- -----------------------
  **EC2**                 OS, patches,            Physical hardware,
                          applications, data, and hypervisor, and
                          security configuration. physical security.

  **Containers**          Application code,       For Fargate, the host
                          dependencies, and task  OS; managed
                          configuration.          orchestration
                                                  responsibilities depend
                                                  on the service
                                                  selected.

  **Lambda**              Function code, IAM      Infrastructure
                          role, and triggers.     provisioning, scaling,
                                                  and patching of the
                                                  underlying environment.
  -----------------------------------------------------------------------

### Security Notes

-   Data and access control remain important customer responsibilities.
-   Choose the compute service based on workload requirements and the
    level of management you want.
-   Use EC2 when you need full operating-system control or a custom
    software stack.
-   Use containers for consistent application packaging and deployment.
-   Use Lambda for suitable event-driven workloads where server
    management is unnecessary.

### Inspect Running EC2 Instances with AWS CLI

Run this in AWS CloudShell or a configured AWS CLI environment. Confirm
that the CLI is using the intended region; the lab uses `us-east-1`.

``` bash
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query "Reservations[*].Instances[*].{ID:InstanceId,Type:InstanceType,Name:Tags[?Key=='Name']|[0].Value,AZ:Placement.AvailabilityZone,PublicIP:PublicIpAddress}" \
  --output table
```

In the EC2 console, instance details are organized into areas such as:

-   **Details:** instance identifiers, VPC, subnet, and public DNS.
-   **Status and alarms:** instance health and status checks.
-   **Monitoring:** metrics such as CPU and network activity.
-   **Security:** associated security groups and permitted traffic.
-   **Networking:** IP addresses, DNS, network interfaces, and Elastic
    IPs.
-   **Storage:** attached storage configuration and metrics.
-   **Tags:** labels and descriptions associated with the instance.

**Key takeaway:** EC2 offers the most direct control over the virtual
machine, but it also carries more operating-system and configuration
responsibility than serverless compute.

------------------------------------------------------------------------

## 2. EC2 Core Concepts

### Amazon Machine Image (AMI)

An **Amazon Machine Image (AMI)** is a template used to launch an EC2
instance. It includes the operating system and may include software and
configuration.

-   AWS-provided and community AMIs can be selected when launching an
    instance.
-   Custom AMIs can provide a hardened, patched, application-ready
    baseline.
-   AMI access should be restricted appropriately because insecure
    settings can be inherited by instances launched from it.

### Instance Types

An EC2 instance type defines the virtual machine's hardware profile,
including CPU, memory, storage, and networking capacity.

Example: `t3.micro`

-   `t`: instance family (burstable general purpose).
-   `3`: generation.
-   `micro`: size.

Common families described in the room:

  -----------------------------------------------------------------------
  Family examples                     General purpose
  ----------------------------------- -----------------------------------
  `t3`, `t3a`                         Burstable general-purpose
                                      workloads, including small
                                      workloads and labs.

  `m5`, `m6i`                         Balanced general-purpose workloads.

  `c5`, `c6i`                         Compute-optimized workloads, such
                                      as CPU-intensive tasks.

  `r5`, `r6i`                         Memory-optimized workloads, such as
                                      databases and caching.
  -----------------------------------------------------------------------

**Cost consideration:** Instance prices vary. Check expected costs with
the AWS Pricing Calculator before deployment.

### User Data

**EC2 User Data** allows scripts to run during the initial launch of an
instance. It is commonly used to install software, configure services,
or retrieve application code.

Example from the room:

``` bash
#!/bin/bash
yum update -y
yum install -y httpd
echo "My Web Server" > /var/www/html/index.html
systemctl start httpd
systemctl enable httpd
```

The script updates packages, installs Apache HTTP Server, creates a
basic web page, and starts and enables the service.

#### User Data Security

-   User Data scripts typically run with root privileges on Linux
    instances.
-   User Data may be accessible through instance metadata or AWS APIs,
    depending on permissions and configuration.
-   **Do not store passwords, API tokens, or other secrets in User
    Data.**
-   Use AWS Secrets Manager or Systems Manager Parameter Store for
    sensitive values, with access controlled through IAM.
-   Treat User Data and instance metadata access as part of the instance
    security boundary.

### Key Pairs

EC2 key pairs are commonly used for SSH access to Linux instances.

-   The **public key** is placed on the instance.
-   The **private key** is retained by the user and used to
    authenticate.
-   Protect private key files and restrict access to them.

For production access, consider AWS Systems Manager Session Manager
where appropriate.

### Find an Instance's AMI and Configuration

First, save the instance ID for the lab instance:

``` bash
INSTANCE_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=room15-web" \
            "Name=instance-state-name,Values=running" \
  --query "Reservations[0].Instances[0].InstanceId" \
  --output text)

echo "$INSTANCE_ID"
```

Then inspect selected instance properties:

``` bash
aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --query "Reservations[0].Instances[0].{AMI:ImageId,Type:InstanceType,KeyName:KeyName,LaunchTime:LaunchTime}" \
  --output table
```

### Inspect User Data

``` bash
aws ec2 describe-instance-attribute \
  --instance-id "$INSTANCE_ID" \
  --attribute userData \
  --query "UserData.Value" \
  --output text | base64 --decode
```

This command retrieves the User Data attribute and decodes its Base64
representation. Run it only in an AWS environment where you are
authorized to inspect the instance.

**Lab observation:** The room's User Data contained a flag,
demonstrating why secrets should not be embedded in startup scripts.

------------------------------------------------------------------------

## 3. Connecting to EC2 Instances

Two access approaches covered in the room are SSH and AWS Systems
Manager Session Manager.

### SSH

SSH connects to a Linux instance using a private key and the instance's
public IP address.

``` bash
ssh -i my-private-key.pem ec2-user@<ec2_public_ip>
```

Typical requirements:

-   The instance has a reachable public IP or another network path.
-   The associated security group allows TCP port `22` from the
    connecting source.
-   A suitable key pair is configured.
-   The correct username and private key are used.

**Security recommendations:**

-   Restrict SSH ingress to specific trusted IP addresses instead of
    opening it broadly.
-   Protect private keys and rotate or replace them when needed.
-   Avoid exposing SSH publicly when an alternative access method is
    available.

### AWS Systems Manager Session Manager

Session Manager provides browser-based or CLI-based shell access without
requiring inbound SSH access to the instance.

``` bash
aws ssm start-session --target <instance_id>
```

Typical requirements include:

-   The SSM Agent is installed and running on the instance.
-   The instance can communicate outbound with the Systems Manager
    service.
-   The instance has an appropriate IAM role or permissions.
-   The operator's IAM identity is authorized to start a session.
-   For CLI use, the Session Manager plugin is installed.

Session Manager activity can be logged when the relevant logging
configuration is enabled.

**Security recommendation:** Prefer Session Manager over SSH when it
meets operational requirements. Apply least-privilege IAM permissions
and enable suitable session logging.

### Retrieve EC2 Instance Metadata

The room demonstrates retrieving an IMDSv2 token before requesting
metadata:

``` bash
TOKEN=$(curl -s -X PUT \
  "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

curl -s \
  -H "X-aws-ec2-metadata-token: $TOKEN" \
  "http://169.254.169.254/latest/meta-data/instance-type"
```

The metadata service address is `169.254.169.254`. The example returns
the instance type, such as `t2.nano`, for the lab instance.

Metadata can expose useful instance information and may provide access
to role credentials when an instance role is configured. Restrict access
to metadata and avoid allowing untrusted workloads to query it.

------------------------------------------------------------------------

## 4. Pets Versus Cattle

The pets-versus-cattle model describes two approaches to managing
infrastructure.

### Pets Model

Servers are treated as unique systems that are maintained individually
and may have memorable names. If a server fails, restoring it can
require significant manual work.

### Cattle Model

Instances are designed to be replaceable and consistent. Instead of
manually repairing each instance, teams create new instances from
approved templates and automate deployment.

Benefits include:

-   **Immutable infrastructure:** changes are made to a new image or
    template, which replaces existing instances rather than relying on
    ad hoc changes.
-   **Reduced persistence opportunities:** replacing a compromised
    instance can remove changes made to that instance, although
    detection, credential rotation, and investigation may still be
    required.
-   **Reproducibility:** Infrastructure as Code can help recreate
    environments consistently.
-   **Reduced configuration drift:** instances are built from consistent
    baselines.
-   **Faster recovery:** automated deployment can reduce recovery time.

An **Auto Scaling Group** manages a collection of EC2 instances and can
help maintain the desired capacity.

### Security Best Practices

-   Design instances to be replaceable rather than irreplaceable.
-   Keep persistent application data outside individual instances where
    appropriate, such as in databases, Amazon S3, or Amazon EFS.
-   Automate provisioning through Infrastructure as Code tools such as
    AWS CloudFormation or Terraform.
-   Send logs to dedicated services or storage, such as Amazon
    CloudWatch and Amazon S3.
-   Build patching and hardening into approved images and deployment
    pipelines.
-   Remember that replacing an instance is not a substitute for
    investigating a compromise or securing affected credentials and
    other resources.

------------------------------------------------------------------------

## 5. Lab Questions and Answers

  -----------------------------------------------------------------------
  Question                            Answer
  ----------------------------------- -----------------------------------
  Which compute option gives the most EC2
  control and responsibility?         

  Which service runs code without you AWS Lambda
  provisioning the infrastructure?    

  What is the name of the lab         room15-web
  instance?                           

  What flag was found in the instance THM{NO_PASSWORDS_HERE}
  User Data?                          

  Under which user do User Data       root
  scripts run?                        

  What user appeared when running     ssm-user
  `whoami` in the Session Manager     
  shell?                              

  What IP address is used for EC2     169.254.169.254
  instance metadata?                  

                           
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## Key Takeaways

-   EC2 provides extensive control but requires responsibility for OS
    security, patching, and configuration.
-   Choose EC2, containers, or Lambda according to the workload and
    management requirements.
-   AMIs can provide consistent, hardened instance baselines.
-   Never store secrets in User Data; use a dedicated secrets service
    and restrictive IAM permissions.
-   Prefer Session Manager over publicly exposed SSH where practical.
-   Use IMDSv2 and restrict access to instance metadata.
-   Treat cloud instances as replaceable, automate deployment, and keep
    persistent data and logs outside individual instances where
    appropriate.

------------------------------------------------------------------------

## Skills Practiced

-   AWS compute service selection
-   EC2 instance inspection using the AWS Console and CLI
-   AMI, instance type, User Data, and key pair concepts
-   Secure instance access with SSH and Session Manager
-   EC2 instance metadata queries using IMDSv2
-   Cloud security and immutable infrastructure principles
