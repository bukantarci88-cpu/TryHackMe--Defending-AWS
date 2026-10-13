# TryHackMe - Defending AWS Writeup

> **Platform:** TryHackMe\
> **Challenge:** Defending AWS\
> **Category:** Cloud Security \| AWS \| Shared Responsibility Model \|
> IAM \| S3 \| Threat Detection

------------------------------------------------------------------------

# Overview

This room explores the AWS Shared Responsibility Model and common cloud
security failures. It highlights how customer-side misconfigurations,
excessive permissions, exposed credentials, and insufficient monitoring
can lead to serious data breaches.

The objective is to understand the security responsibilities associated
with different cloud service models and identify practical controls that
help protect AWS resources.

------------------------------------------------------------------------

# AWS Shared Responsibility Model

AWS is responsible for securing the underlying cloud infrastructure,
while customers are responsible for securing the resources and
configurations they control. The exact division of responsibility
depends on the service being used.

## Cloud Service Models

### Infrastructure as a Service (IaaS)

IaaS provides virtualized computing resources, such as virtual machines,
over the internet. Customers have greater control over the operating
system, applications, and network configuration.

**Example:** Amazon EC2.

Customer security responsibilities commonly include: - Patching and
hardening the operating system. - Securing applications and services. -
Configuring security groups and network access. - Managing IAM roles and
permissions.

### Platform as a Service (PaaS)

PaaS provides a managed platform for developing and deploying
applications, reducing the need to manage the underlying infrastructure.

**Examples:** Heroku, Vercel, and Google App Engine.

Customers still need to secure application code, identities, data, and
the configuration options exposed by the service.

### Software as a Service (SaaS)

SaaS provides ready-to-use applications hosted by a service provider.

**Examples:** Slack, Zoom, Gmail, Google Docs, and Dropbox.

Customers remain responsible for appropriate account security, access
management, data handling, and service configuration.

### Function as a Service (FaaS)

FaaS, commonly associated with serverless computing, lets developers run
individual functions in response to events without managing the
underlying servers.

**Example:** AWS Lambda.

AWS manages the underlying infrastructure and runtime, while customers
must secure their code, permissions, secrets, data, and logging.

## Responsibility by AWS Service

  -----------------------------------------------------------------------
  Service                 AWS responsibility      Customer responsibility
  ----------------------- ----------------------- -----------------------
  **EC2**                 Physical infrastructure OS patching, service
                          and virtualization      hardening, security
                                                  groups, IAM roles, and
                                                  application security

  **RDS**                 Underlying              Database access,
                          infrastructure and many encryption settings,
                          managed maintenance     parameter
                          tasks                   configuration, and
                                                  public exposure

  **Lambda**              Infrastructure and      Function code,
                          managed runtime         permissions, secrets,
                                                  and logging

  **S3**                  Underlying storage      Bucket policies, access
                          infrastructure          controls, encryption
                                                  settings, public
                                                  access, and data
                                                  lifecycle
  -----------------------------------------------------------------------

**Key takeaway:** Moving workloads to the cloud does not remove the
customer's responsibility for security. Identity, data, application, and
service configuration still require careful management.

**Room question:** Name one area that is the customer's responsibility
to secure for a Lambda function.

**Answer:** Application code.

------------------------------------------------------------------------

# Real-World Example: Capital One

## Incident Summary

The Capital One breach demonstrated how a vulnerability in an
internet-facing component, combined with access to temporary cloud
credentials and permissions to access storage, can expose sensitive
data.

## Attack Pattern

1.  An attacker exploited a server-side request forgery (SSRF)
    vulnerability in a publicly accessible application component.
2.  The vulnerability was used to make requests to the EC2 instance
    metadata service.
3.  Temporary IAM role credentials were obtained.
4.  The credentials were used to make AWS API requests and access S3
    data permitted by the role.

This incident illustrates how application vulnerabilities and overly
broad permissions can combine to create a path from an internet-facing
service to sensitive cloud data.

## Defensive Measures

-   Apply **least privilege** to IAM roles and policies.
-   Reduce exposure of instance metadata and credentials.
-   Enable and centralize AWS CloudTrail logging.
-   Alert on unusual STS activity and unexpected S3 access.
-   Use preventive guardrails such as service control policies,
    permission boundaries, and configuration rules where appropriate.

**Room question:** What IAM best practice should always be applied?

**Answer:** Least privilege.

------------------------------------------------------------------------

# Real-World Example: Uber --- Exposed Credentials

## Incident Summary

The 2016 Uber breach is an example of how compromised developer
credentials and exposed cloud keys can lead to unauthorized access to
stored data.

## Attack Pattern

1.  An attacker gained access to an engineer's GitHub account.
2.  AWS access keys stored in code were discovered.
3.  The keys were used to access AWS resources and download files from
    an S3 datastore.

Exposed credentials can effectively become an entry point to cloud
resources when the associated permissions are not sufficiently
restricted or monitored.

## Defensive Measures

-   Never store secrets or access keys in source code.
-   Use **AWS Secrets Manager** or **AWS Systems Manager Parameter
    Store** for appropriate secret-management needs.
-   Prefer IAM roles and short-lived credentials where possible.
-   Rotate exposed credentials and revoke keys that are no longer
    needed.
-   Scan repositories for accidentally committed secrets.
-   Require MFA for sensitive access and actions.
-   Monitor anomalous API calls, suspicious sign-ins, and unusual
    privilege changes.

**Room question:** Which AWS service can be used instead of storing
secrets in code?

**Answer:** AWS Secrets Manager.

------------------------------------------------------------------------

# Real-World Example: Publicly Exposed S3 Bucket

## Incident Summary

A misconfigured S3 bucket can expose sensitive data when its bucket
policy or access controls allow unintended public access. The room
references the reported Pegasus Airlines exposure as an example of the
risks associated with publicly accessible cloud storage.

## Root Cause

Storage may be made public for testing, integrations, or temporary
sharing and then left exposed. Without preventive controls and
continuous monitoring, an overly permissive policy or access control
list can make data accessible to unauthorized parties.

## Defensive Measures

-   Enable **S3 Block Public Access** at the account and bucket levels
    where appropriate.
-   Use policy guardrails to prevent unintended public access.
-   Apply AWS Config rules or equivalent controls to identify public
    buckets.
-   Monitor bucket-policy and access-control changes.
-   Review data access permissions and lifecycle settings regularly.

**Room question:** What common misconfiguration is referred to as a
"leaky bucket"?

**Answer:** S3 public access.

------------------------------------------------------------------------

# Key Cloud Security Risks

The scenarios in this room highlight several recurring causes of cloud
incidents:

-   **Over-permissive IAM:** Excessive permissions can increase the
    impact of compromised identities.
-   **Public exposure:** Misconfigured S3 buckets, security groups, or
    endpoints can expose resources.
-   **Leaked secrets:** Credentials stored in source code can enable
    unauthorized cloud access.
-   **Insufficient monitoring:** Missing logs and alerts can delay
    detection and response.
-   **Application vulnerabilities:** Issues such as SSRF can provide a
    route to cloud metadata or credentials.

------------------------------------------------------------------------

# Practical Security Checklist

-   [ ] Verify IAM permissions follow least-privilege principles.
-   [ ] Avoid committing credentials, tokens, or secrets to source
    control.
-   [ ] Prefer IAM roles and short-lived credentials where possible.
-   [ ] Enable S3 Block Public Access where public access is not
    required.
-   [ ] Centralize and review relevant CloudTrail logs.
-   [ ] Monitor unusual STS activity and unexpected S3 access.
-   [ ] Alert on changes to sensitive policies and cloud resource
    configurations.
-   [ ] Use preventive guardrails and continuous configuration checks.

------------------------------------------------------------------------

# Lessons Learned

The AWS Shared Responsibility Model makes clear that cloud security
depends on both provider controls and customer configuration. The
Capital One, Uber, and S3 exposure scenarios demonstrate how SSRF,
leaked credentials, excessive IAM permissions, and public storage access
can contribute to data breaches.

Applying least privilege, protecting secrets, restricting public access,
and monitoring cloud activity are essential practices for reducing risk.
These concepts are directly relevant to cloud security assessments, SOC
monitoring, threat detection, and incident response.

------------------------------------------------------------------------

# Skills and Technologies

**Cloud Platform:** Amazon Web Services (AWS)\
**Cloud Services:** EC2, Lambda, S3, RDS\
**Identity and Access:** IAM, IAM roles, least privilege\
**Security and Monitoring:** CloudTrail, GuardDuty, AWS Config\
**Secret Management:** AWS Secrets Manager, Systems Manager Parameter
Store\
**Security Concepts:** Shared Responsibility Model, SSRF, credential
exposure, public storage misconfiguration, cloud monitoring

------------------------------------------------------------------------

# Challenge Answer Summary

  -----------------------------------------------------------------------
  Question                            Answer
  ----------------------------------- -----------------------------------
  Name one area the customer must     Application code
  secure for Lambda                   

  What IAM best practice should       Least privilege
  always be applied?                  

  What AWS service can store secrets  AWS Secrets Manager
  instead of hardcoding them?         

  What is a common "leaky bucket"     S3 public access
  misconfiguration?                   
  -----------------------------------------------------------------------

------------------------------------------------------------------------

**Learning Platform:** [TryHackMe](https://tryhackme.com/)\
**Focus:** AWS cloud security, shared responsibility, IAM, secure
credential management, and cloud misconfiguration prevention.
