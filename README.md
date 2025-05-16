# aws-sso

Proof-of-concept tool to safely store AWS SSO credentials in your keychain.

## Why

I've used [aws-vault](https://github.com/99designs/aws-vault) forever, and I like that it keeps the credentials away from the file system. This tool aims to solve two problems I have with aws-vault:

1. aws-vault hasn't been updated to use the newer PKCE auth method for SSO, and since the project seems to have been abandoned, I expect it probably won't be
2. aws-vault really just moves the problem: anything can execute it to extract credentials, and the only confirmation you can have is setting your keychain timeout quite low and having to type in your password again. I solve this by showing a Touch ID confirmation each time that credentials are requested, which includes details of the calling process and what credentials have been requested.

![screenshot of Touch ID prompt](./docs/touch-id.png)

## Install

> [!CAUTION]
> I'm not a security expert. You probably shouldn't install this tool.

> [!NOTE]
> This tool only works on MacOS.

```bash
go install github.com/gordonmleigh/aws-sso
```

## Usage

The tool currently has only one sub command `sso`, which provides credentials
for the given account and role.

```
Usage: aws-sso sso <session-name> <account-id> <role-name> [<command> [<arguments> ...]] [flags]

Authenticate via SSO

Arguments:
  <session-name>       The name of the sso-session section in the config file
  <account-id>         The AWS Account ID
  <role-name>          The SSO Role Name
  [<command>]          A command to execute
  [<arguments> ...]    Arguments for the command
```

For example, to get credentials for account 100000000001 with SSO Role AdministratorAccess, run the following:

```bash
aws-sso sso my-sso 100000000001 AdministratorAccess
```

This will output credentials in the [AWS Process Credential Provider format](https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html), so that you may use it with `credential_process` in your AWS config (see below).

You can optionally supply a command to execute at the end of the command line, in which case the command will be started with the relevant `AWS_*` environment variables for the credentials:

```base
aws-sso sso my-sso 100000000001 AdministratorAccess aws sts get-caller-identity
```

## Configure

Set up your AWS config file (`~/.aws/config`) with an `sso-profile` and whatever
`profile` sections you want:

```ini
[sso-session my-sso]
sso_region=eu-central-1
sso_start_url=https://my-sso-start-url.awsapps.com/start

[profile prod-admin]
region=eu-central-1
credential_process=aws-sso sso my-sso 100000000001 AdministratorAccess

[profile sandbox-dev]
region=eu-central-1
credential_process=aws-sso sso my-sso 100000000002 Developer

[profile sandbox-admin]
region=eu-central-1
credential_process=aws-sso sso pw 100000000002 AdministratorAccess
```
