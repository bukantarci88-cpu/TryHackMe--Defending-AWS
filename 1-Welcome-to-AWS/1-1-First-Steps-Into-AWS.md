# AWS 1.1. First Steps Into AWS

### Task 1 - Introduction

In this room, you will get comfortable with how TryHackMe's AWS environment works, how to navigate the AWS Console, and how to run simple commands using CloudShell and AWS CLI.

### Task 2 - TryHackMe AWS Environment Overview

Time to start your first practical exercise, so go ahead and set up your environment and log in to your AWS account:

1. Open the `Cloud Details` window.
2. Click `Generate Environment` to provision a lab environment.
3. Once the environment state is `Ready`, click the `Credentials` tab.
4. Open the AWS Console link. This should put you in the `us-east-1` region after logging in.
5. Use the provided Username and Console Password to log in.

**Answer the questions below**

> After you log in, what is the name of the account?
> 

LabRoom (Check the top-right corner)

### Task 3 - AWS Web Interface Overview

Services Search

![Search bar layout](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1768817334117.png)

Region Selection

![Select region from top-right](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1769582250751.png)

Account Menu

![Showing account options](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1769582250636.png)

CloudShell

![CloudShell at the top](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1768817334679.png)

**Answer the questions below**

> What is the default region TryHackMe usually deploys lab environments in?
> 

us-east-1

### Task 4 - AWS CloudShell Overview

CloudShell is a terminal that runs directly in your AWS account session, in the browser. It is already authenticated with your AWS Console login credentials.

CloudShell is a great way to do quick checks without installing anything locally. Using the AWS web interface is okay, but for a professional user, being comfortable with CLI commands (either CloudShell or AWS CLI) speeds up deployments and troubleshooting.

**Practical Exercise**

1. Open CloudShell from the Console

![CloudShell loading screen](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1769587811596.png)

1. Run your first command. This is the equivalent of `whoami` from Linux and will quickly help you get your bearings, especially when assuming roles and creating sessions.

```bash
           $ aws sts get-caller-identity

{
    "[REDACTED]": "AIDAQ6YNVVZIMRSN4NKG2",
    "[REDACTED]": "158878467779",
    "[REDACTED]": "arn:aws:iam::158878467779:user/158878467779"
}
```

1. Then run the following command, which will show the profile information.

```bash
           $ aws configure list

NAME       : VALUE                    : TYPE             : LOCATION
profile    : <not set>                : None             : None
access_key : ****************MOHZ     : container-role   :
secret_key : ****************fA0f     : container-role   :
region     : us-east-1                : env              : ['AWS_REGION', 'AWS_DEFAULT_REGION']
```

1. A quick way to check which region CloudShell is using is by running either of the following commands:

```bash
           $ aws ec2 describe-availability-zones --output text --query 'AvailabilityZones[0].[RegionName]'

us-east-1

### OR ###$ echo $AWS_DEFAULT_REGION

us-east-1
```

**Answer the questions below**

> What key names do you see when running the AWS equivalent of the `whoami` command?
> 

Account,Arn,UserId

```jsx
~ $ aws sts get-caller-identity
{
"UserId": "AIDAUXMPGGCXZTXMEB6U3",
"Account": "325107200175",
"Arn": "arn:aws:iam::325107200175:user/325107200175"
```

### Task 5 - AWS CLI Setup

1. Open a terminal and check that AWS CLI is installed.

```bash
           $ aws --version

aws-cli/2.31.20 Python/3.13.7 Linux/6.17.0-8-generic exe/aarch64.ubuntu.25
```

1. Run the `aws configure` command.

```bash
           $ aws configure

AWS Access Key ID [None]: ****************I4OF
AWS Secret Access Key [None]: ****************AmgN
Default region name [None]: us-east-1
Default output format [None]: json
```

1. Verify configuration.

```bash
           $ aws configure list

      Name                    Value             Type    Location
      ----                    -----             ----    --------
   profile                <not set>             None    None
access_key     ****************I4OF shared-credentials-file
secret_key     ****************AmgN shared-credentials-file
    region                us-east-1      config-file    ~/.aws/config$ aws sts get-caller-identity

{
    "UserId": "AIDAR6DQWN2T7L2ZLYOS3",
    "Account": "158878467779",
    "Arn": "arn:aws:iam::158878467779:user/158878467779"
}
```

**Profiles And Environment Variables**

When you first run the `aws configure` command and set up the credentials, they are automatically saved as a default profile.

**Note:** MS Windows stores the credentials and config file in `C:\Users\USERNAME\.aws\`.

| **Information** | **Local Profile Files** | **Environment Variables** |
| --- | --- | --- |
| **Files** | • `~/.aws/credentials` - stores keys/credentials/session tokens |  |
| • `~/.aws/config` - stores profile settings (region, output) | • `~/.bashrc` |  |
| **Common Layout** | • Credentials file: [default] or [<<profile-name>>] |  |
| • Config file: [default] or [profile <<profile-name>>] | • `export AWS_ACCESS_KEY_ID="AKIA..."` |  |
| • `export AWS_SECRET_ACCESS_KEY="..."` |  |  |
| • `export AWS_SESSION_TOKEN="..."` |  |  |
| • `export AWS_DEFAULT_REGION="us-east-1"` |  |  |
| **Commands** | • `aws configure set aws_access_key_id "AKIA..." --profile thm` |  |
| • `aws configure set aws_secret_access_key "..." --profile thm` |  |  |
| • `aws configure set aws_session_token "..." --profile thm` |  |  |
| • `aws configure set region "us-east-1" --profile thm` | • `export AWS_ACCESS_KEY_ID="AKIA..."` |  |
| • `export AWS_SECRET_ACCESS_KEY="..."` |  |  |
| • `export AWS_SESSION_TOKEN="..."` |  |  |
| • `export AWS_DEFAULT_REGION="us-east-1"` |  |  |
| **Usage** | • `aws sts get-caller-identity --profile thm` | • `aws sts get-caller-identity` |
| **Comments** | AWS CLI configuration files are more flexible and provide a way to easily switch context by appending the `--profile <<profile-name>>` parameter to commands. | A bit messy, hard to set up, and hard to use. The current profile is always overwritten if you update the environment variables. |

An example of typical credentials and configuration files is shown below.

Credentials File

```bash
           [default]
aws_access_key_id=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPEXAMPLEKEY
aws_session_token = IQoJb3JpZ2luX2IVERYLONGSTRINGEXAMPLE

[thm-user]
aws_access_key_id=AKIAI44QH8DHBEXAMPLE
aws_secret_access_key=je7MtGbClwBF/2Zp9Utk/h3yEXAMPLEKEY
aws_session_token = fcZib3JpZ2luX2IVERYLONGSTRINGEXAMPLE
```

Config File

```bash
           [default]
region=us-east-1
output=json

[profile thm-user]
region=eu-west-1
output=text
```

**Configurations Priority Rules**

1. Environment variables.
2. Explicit profile flag (`profile <<profile-name>>`).
3. `AWS_PROFILE` environment variables.
4. Default profile in `~/.aws/credentials + ~/.aws/config`.

### Task 6 - AWS CLI Commands Structure

AWS CLI commands might seem daunting at first, but they have a consistent baseline structure:

`aws <service> <operation> [--parameters] [--region <region>] [--output <format>]`

- `<service>` - the target service for the command (e.g., ec2, s3, sts)
- `<operation>` - the operation to apply to the specified service (e.g., attach-volume, allocate-address)
- `[--parameters]` - each operation has specific parameters which can be set (e.g., domain, address, tag, region)
- `[--region]` - overwrites the default profile region and runs the command in the specified region
- `[--output]` - the format of the resulting output (e.g., text, JSON, table)

```bash
           $ aws ec2 describe-regions --query "Regions[].RegionName" --output text

ap-south-1      eu-north-1      eu-west-3       eu-west-2       eu-west-1
ap-northeast-3  ap-northeast-2  ap-northeast-1  ca-central-1    sa-east-1
ap-southeast-1  ap-southeast-2  eu-central-1    us-east-1       us-east-2
us-west-1       us-west-2
```

AWS CLI Terminal

```bash
           $ aws iam list-groups

{
    "Groups": [
        {
            "Path": "/",
            "GroupName": "AWS101",
            "GroupId": "AGPAR6DQWN2TU2A5SAY2L",
            "Arn": "arn:aws:iam::158878467779:group/AWS101",
            "CreateDate": "2026-01-16T08:13:05+00:00"
        },
        {
            "Path": "/",
            "GroupName": "LabReadOnly",
            "GroupId": "AGPAR6DQWN2T6LVLY6F6K",
            "Arn": "arn:aws:iam::158878467779:group/LabReadOnly",
            "CreateDate": "2026-01-14T09:46:57+00:00"
        }
    ]
}
```

**Answer the questions below**

> What is the first available command for the EC2 service?
> 

accept-address-transfer

> When you run the aws s3 ls command, what is the prefix of the S3 bucket that includes the current account ID?
> 

firststeps

```jsx
root@ip-10-112-92-17:~# aws s3 ls
2026-10-08 02:20:44 firststeps-325107200175
```

### Task 7 - Conclusion

You should now know how to:

- Start/Reset/Terminate the TryHackMe AWS environment.
- Navigate the AWS Console.
- Use CloudShell and AWS CLI .
- Configure AWS CLI.
- Run basic AWS CLI commands.
