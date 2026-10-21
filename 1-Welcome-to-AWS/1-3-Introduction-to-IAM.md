# AWS Security 1-3-Introduction-to-IAM

### Task 1 - Introduction

Security starts and ends with Identity and Access Management. AWS is no different, and throughout this room, you will learn the foundational concepts on which to build your AWS knowledge and understanding further.

**Learning Objectives**

- AWS IAM identities and when to use them
- IAM policies 101
- Common AWS credential types
- The principle of least privilege

### Task 2 - IAM Identities

AWS identities are entities within the AWS IAM service that are authenticated to access resources based on their assigned permissions. You will encounter the following types:

- **Root User** - this is the identity created with an AWS account and has full access to all resources.
- **IAM User** - people/applications with permanent credentials (password, access keys).
- **IAM Group** - a collection of users with the main purpose of easily managing permissions for multiple users.
- **IAM Role** - identities with no permanent credentials, which provide a more flexible way to assign temporary access.

**Security Best Practices**

- Do not use the root user for day-to-day activities. Lock it down with MFA and a strong password and store it away.
- Human users should be assigned IAM users, but ideally, a federated authentication method, such as SSO, should handle authentication.
- Groups are a great way to manage permissions.
- For AWS services (e.g., EC2, Lambda), roles are better suited.

**Practical Exercise**

You can dive right in and start by exploring the lab environment. So, generate a lab and log in to the AWS Console with the provided credentials.

**Info:** To start the AWS environment, click the `Cloud Details` button at the top of the room, then click `Generate Environment`. When the environment is ready, use the Credentials tab to navigate to the AWS Console and log in. In the AWS web interface, you can find the users, groups, roles, and policies under the IAM service.

1. Search for the IAM service.

![Search for IAM](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1769702323773.png)

1. And, on the left side, you should see the links.

![On the left side of the IAM dashboard, you can find the users, groups, roles, and policies links.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1779961501630.png)

1. To find out details about your user (ARN, permissions, groups, etc.) or set up different capabilities (e.g., MFA, Access Keys, etc.), you can navigate to IAM Users and select your username. By default, in labs, this is the account ID.

![Find your user](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1769772991046.png)

As we dive deeper into AWS, it is useful to become comfortable with the CLI.

So, as an alternative to the Console UI, you can run the following commands from either CloudShell (make sure you are in the right region/account) or AWS CLI (make sure you have the default profile configured).

1. List account users:

```bash
           $ aws iam list-users   #IAM Identities

{
    "Users": [
        {
            "Path": "/",
            "UserName": "060795900697",
            "UserId": "AIDAQ4J5X2MM2R67SDNAN",
            "Arn": "arn:aws:iam::060795900697:user/060795900697",
            "CreateDate": "2026-01-15T07:48:32+00:00",
            "PasswordLastUsed": "2026-01-30T11:32:38+00:00"
        }
    ]
}
```

1. List account groups:

```bash
           $ aws iam list-groups #IAM Identities

{
    "Groups": [
        {
            "Path": "/",
            "GroupName": "[REDACTED]",
            "GroupId": "AGPAQ4J5X2MM32EYCG4WS",
            "Arn": "arn:aws:iam::060795900697:group/[REDACTED]",
            "CreateDate": "2026-01-30T11:29:25+00:00"
        },
        {
            "Path": "/",
            "GroupName": "[REDACTED]",
            "GroupId": "AGPAQ4J5X2MM7SCLPSYWR",
            "Arn": "arn:aws:iam::060795900697:group/[REDACTED]",
            "CreateDate": "2026-01-15T07:48:32+00:00"
        },
        {
            "Path": "/",
            "GroupName": "[REDACTED]",
            "GroupId": "AGPAQ4J5X2MM5EBBEIXYU",
            "Arn": "arn:aws:iam::060795900697:group/[REDACTED]",
            "CreateDate": "2026-01-30T11:29:23+00:00"
        }
    ]
}
```

**Answer the questions below**

> What is the name of the groups your user is part of (listed alphabetically)?
> 

AWS103, LabReadOnly

### Task 3 - Understanding Policies

AWS policies have a JSON structure that lets you define permissions, specify allow/deny actions, and set conditions for IAM users, groups, or roles.

**Policy Types**

- **Identity-based policy** - the most common type; it applies to users, groups, or roles.
- **Resource-based policy** - attached to resources (e.g., S3 bucket policy).
- **Permissions-boundaries policy** - an advanced IAM feature that defines the maximum extent of permissions a policy can grant.
- **Service control policy** - a feature of the AWS Organizations service, its main purpose being to provide uniform security guardrails across an organization (accounts, OUs, whole organization).
- **Session policy** - similar to Permissions-boundaries but limited to a specific session during programmatic role assumption.

**Permissions Evaluation**

Before we dive into the evaluation logic, it's worth noting that AWS compiles a request context before evaluating an access request. This can be easily remembered as PARC (Principal, Action, Resource, Condition). This is especially useful when troubleshooting access issues.

An access request goes through a policy evaluation logic that results in an allow or deny decision. The core logic in the evaluation goes as follows:

1. **Explicit Deny** - if any policy explicitly denies a request, the evaluation is stopped, and the resulting decision is deny. Deny always overrides an allow.
2. **Permission Boundary Evaluation** - Permission boundaries act as constraints, and AWS checks if a user or role has a permission boundary policy attached.
3. **IAM Policies** evaluation of all relevant policies attached to a user or role.
4. **Allow** - if the action is explicitly allowed in at least one policy and not restricted by any of the above, then the resulting decision is allow.
5. **Default Deny** - if none of the policies or permission boundaries explicitly allow an action, the default decision is deny.

Regarding policy types, they are evaluated in a specific order.

![AWS Evaluation Logic](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1781258873346.png)

**Security Best Practices**

In many security architectures, policies are the backbone on which you layer security measures. As such, it is wise to spend more time understanding how they work and practice as much as you can in a sandbox environment. When it comes to AWS identities and policies, here are a couple of strong recommendations to get things going:

- For applications and services, lean towards IAM Roles.
- Avoid "catch-all" policies where permissions are too broad.
- Use explicit denials on "must never happen" actions or situations.
- For regular users, provide only the minimal access needed for day-to-day tasks and elevate access via a controlled role, ideally requiring MFA.
- Workloads can have dedicated roles with service-specific permissions.
- Regularly review policies.

**Answer the questions below**

> Which policy type is the most common?
> 

Identity-based

> What contextual information does AWS gather before evaluating a request (mnemonic reference order)?
> 

Principal,Action,Resource,Condition

> For a regular user, name one security best practice you should apply?
> 

MFA

### Task 4 - Policy Structure

We saw the logic in evaluating a policy. Now, let us understand what it is made of.

The backbone of any policy can be structured as follows:

- **Version** - specifies the language syntax rules for processing a policy. The latest version is `2012-10-17`, but you should always check if a newer version is available.
- **Statement** - the main and mandatory part of a policy, where you define one or more elements that will be processed during the policy evaluation. The usual components of an element are:
    - **Sid** - optional field, usually used as a short description of the element.
    - **Effect** - required field which specifies the result of the element. Value is case-sensitive and can either be `Allow` or `Deny`.
    - **Principal** - required in some circumstances, specifies the account, user, or role to which the statement applies.
    - **Action** - each AWS service includes a set of actions you can perform, and here you specify which actions the statement applies to.
    - **Resource** - define the object or objects the statement applies to.
    - **Condition** - optionally, you can specify the logic under which the statement applies.

**Policy Example**

```bash
           {
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "trylabS3Access",
			"Effect": "Allow",
			"Action": [
				"s3:ListBucket",
				"s3:ListBucketVersions",
				"s3:GetObject",
				"s3:PutObject"
			],
			"Resource": [
				"arn:aws:s3:::thm-bucket/*"
			],
			"Condition": {
				"ArnLike": {
					"aws:PrincipalArn": "arn:aws:iam::111122223333:user/trylab"
				}
			}
		}
	]
}
```

Identify the main components and build a narrative of what is going on. Something like: "*This policy will allow the trylab user to list, get, or put objects in the thm-bucket resource.*"

Here is another example.

```bash
           {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "ec2:TerminateInstances",
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::111122223333:user/try-terminate-me"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": "ec2:TerminateInstances",
      "Resource": "*",
      "Condition": {
        "ArnLike": {
          "aws:PrincipalArn": "arn:aws:iam::111122223333:user/try-terminate-me"
        }
      }
    }
  ]
}
```

**Security Best Practices**

When it comes to implementing policies, specific beats general and saves you potential headaches later. Here are a couple of guidelines to get you started when shaping a policy:

- List the exact API action needed, for example, `s3:ListBucket`, and steer away from "catch-all" actions like `s3:*`.
- Scope to exact resources whenever the service supports ARN.
- Split statements by resource type and required permissions, and use Sid as shorthand descriptions. In this way, policies are more "human-readable" while ensuring they do not overscope access.
- Use conditions to tighten access instead of adding more permissions, for example, `aws:MultiFactorAuthPresent`, `aws:SourceIp`, `aws:RequestedRegion`.
- Use explicit Deny only for guardrails.

The road to shaping a good policy is rarely straightforward, but with good practice and knowledge, it becomes easier.

**Answer the questions below**

> In the first example above, which action allows the trylab user to retrieve objects from the thm-bucket?
> 

s3:GetObject

> In the second example above, when the user try-terminate-me requests an EC2 termination, what will be the result when evaluating the policy?
> 

Allow

### Task 5 - Credentials

In AWS, common types of credentials you will see are:

- **Console Passwords** - this is a user-defined password for the root user or IAM user to access the AWS Management Console.
- **Access Keys** - long-term programmatic access credentials.
- **Temporary Credentials** - AWS Security Token Service is a managed service that enables you to request short-lived, limited-privilege credentials.
- **Role Credentials** - especially used for AWS compute, it provides permissions for compute instances without storing the credentials on disk.

**Practical Exercise**

In this exercise, we will put everything together and create a new user with console credentials and assign it to a "special" group:

1. Navigate to the `IAM service`, `Users`, and then click `Create User`:

![Create a new user](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1769774061749.png)

1. Fill in the username (e.g., `trylogme`), check the `Provide user [...]` checkbox, and uncheck the `Users must create [...]` checkbox.

![Fill in user details](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1769770614851.png)

1. For the purpose of this exercise, add the user to the LogsReaders group.

![Add user to logsreaders group](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1769774059910.png)

1. Review and create the user.

![Create the user](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1769774059845.png)

1. Make sure you retrieve the credentials (copy/paste or CSV download) as this is the only time they will be shown.

![Download the credentials](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1769774059896.png)

1. In an incognito browser window, log in to the newly created user. Fill in the Account ID, username, and password.

**Note:** You can retrieve the Account ID from the user who was initially provided.

![Log in with the new user](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1769774059889.png)

1. Make sure you are in the `us-east-1` region and do some exploration, see if you find anything interesting.

**Security Best Practices**

- Do not generate access keys for humans unless you understand the blast radius.
- Always favor roles in combination with temporary STS.
- Rotate or remove long-lived keys.
- Use MFA for sensitive operations.

**Answer the questions below**

> What is the prefix of the bucket you found?
> 

try-log-me

> If you dig into the bucket, what flag do you find?
> 

THM{MY_SECRET_STASH}

### Task 6 - The Principle Of Least Privilege

The Principle of Least Privilege, or PoLP for short, means granting only the minimum set of permissions needed for the minimum resources, for the minimum period of time. Simple in theory but hard to apply.

As a set of practical approaches, here are the starting points:

- Understand the user or service requirements. More often than not, an "I want admin" statement can be broken down into more specific actions (e.g., create an EC2 instance in region X, put or get objects in a specific bucket).
- Start with a narrow set of action/resource pairs and build on them.
- Avoid wildcards ( ) unless you really understand the blast radius; and even then, you should still avoid them.
- Use conditions to further restrict an action, for example, for sensitive operations, condition MFA to be used.

**Practical Exercise**

Select one option and check whether the solution adheres to the least privilege principle. If a solution is valid, you can advance to the next level.

After successfully completing all three examples, you will receive the flag.

**Answer the questions below**

> What is the flag after finishing all three exercises?
> 

THM{POLP_IT_DOWN}

### Task 7 - Conclusion

In this room, you have looked at the fundamental components of the AWS IAM service and taken your first steps toward defining well-architected, secure policies.

**Key Takeaways**

- Policies are the cornerstone of a good security architecture and should not be treated lightly.
- Applying the Principle of Least Privilege can mitigate the most common high-impact misconfigurations and attack patterns.
- Be knowledgeable of the who, what, where, and for how long of an IAM identity when designing or troubleshooting policies.
- Credentials are the keys to the kingdom, so take good care of them. Even more, for sensitive operations, it is best to enforce MFA.
- Avoid the "I'll fix it later" pitfall, no matter how many complaints you receive.
