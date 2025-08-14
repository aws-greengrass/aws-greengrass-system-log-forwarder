# aws.greengrass.SystemLogForwarder

A generic component which uploads system logs to CloudWatch.

This works by uploading active system logs directly to CloudWatch using
CloudWatch's HTTPS API.

### Build

To build the project, you will need the following build dependencies:

- GCC or Clang
- CMake (at least version 3.22)
- Make or Ninja
- pkg-config
- git
- libssl-dev

On Ubuntu, these can be installed with:

```sh
sudo apt update && sudo apt install build-essential pkg-config cmake git libssl-dev libsystemd-dev
```

To make a release build configured for minimal size, run:

```sh
cmake -B build -D CMAKE_BUILD_TYPE=MinSizeRel
```

The following configuration flags may be set with cmake (with `-D`):

- `CMAKE_BUILD_TYPE`: This can be set to `MinSizeRel`, `Debug`, `Release` or
  `RelWithDebInfo` for different optimizations

- `GGL_LOG_LEVEL`: This can be set to `NONE`, `ERROR`, `WARN`, `INFO`, `DEBUG`,
  or `TRACE` for various logging levels.

To build, then run `make`:

```sh
make -C build -j$(nproc)
```

### Component Creation

To deploy this component to Greengrass, you need to create a directory hierarchy
as below:

```
components
├── artifacts
│   └── aws.greengrass.SystemLogForwarder
│       └── x.y.z [replace with version number]
│           └── system-log-forwarder
└── recipes
    └── aws.greengrass.SystemLogForwarder-x.y.z.yaml
```

The component's recipe is at the root of the directory, whereas the binary
`system-log-forwarder` is in the `./build/bin` folder after successfully
building the project.

You may also build and run this binary outside of Greengrass independently, but
you would need to provide environment variables to access your account.

```
# Provide your AWS account access credentials
export AWS_ACCESS_KEY_ID=[REPLACE HERE]
export AWS_SECRET_ACCESS_KEY=[REPLACE HERE]
export AWS_SESSION_TOKEN=[REPLACE HERE]
export AWS_REGION=[REPLACE HERE]

# To get usage help
./build/bin/system-log-forwarder --help

# Sample use case
./build/bin/system-log-forwarder --logGroup test/logs --thingName testName
```

### Prerequisites

Before deploying this component as a generic component, you should set up the
cloud infrastructure to receive the output from this component.

The component requires access to create log and stream groups in CloudWatch as
well as permission to perform the putLogs HTTP call. You need to provide the
following additional policy to your Greengrass device's role alias at minimum
for the component to work.

#### Development/Testing Policy (Permissive)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

#### Least Privilege Policy

For production deployments, use this least privilege policy that restricts
access to the specific log group:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup"],
      "Resource": "arn:aws:logs:<REGION>:<ACCOUNT-ID>:log-group:greengrass/systemLogs"
    },
    {
      "Effect": "Allow",
      "Action": ["logs:CreateLogStream", "logs:DescribeLogStreams"],
      "Resource": "arn:aws:logs:<REGION>:<ACCOUNT-ID>:log-group:greengrass/systemLogs:log-stream:*"
    },
    {
      "Effect": "Allow",
      "Action": ["logs:PutLogEvents"],
      "Resource": "arn:aws:logs:<REGION>:<ACCOUNT-ID>:log-group:greengrass/systemLogs:log-stream:*"
    }
  ]
}
```

Replace `<REGION>` with your AWS region (e.g., `us-east-1`), `<ACCOUNT-ID>` with
your AWS account ID, and `greengrass/systemLogs` with your custom log group name
if using a different configuration. The log stream name defaults to the
Greengrass device/thing name.

For running independent of Greengrass, users need an access key with the
appropriate permissions from either policy above.

### Local Deploy

Run from your install directory, specifying the current version of
SystemLogForwarder in place of x.y.z:

```
/usr/local/bin/ggl-cli deploy --recipe-dir components/recipes --artifacts-dir components/artifacts --add-component aws.greengrass.SystemLogForwarder=x.y.z
```

Check the nucleus logs to verify that the deployment has SUCCEEDED.

### Check the component logs

After the deployment completes, read the logs from the component:

```
journalctl -f -u ggl.aws.greengrass.SystemLogForwarder.service
```
