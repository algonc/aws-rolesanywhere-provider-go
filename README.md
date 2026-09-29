# AWS Roles Anywhere Provider for Go

A pure Go credentials provider for the AWS SDK for Go v2. It uses an X.509
certificate and private key to obtain temporary AWS credentials through IAM Roles
Anywhere, without running an external credential helper.

The provider caches credentials and retrieves a new session when they approach
expiration.

## Installation

```sh
go get github.com/algonc/aws-rolesanywhere-provider-go
```

## Setup

Before using the provider, configure IAM Roles Anywhere with:

- A trust anchor that trusts your certificate authority.
- A profile and an IAM role that the workload can assume.
- A PEM-encoded X.509 certificate and its matching private key.

See the [IAM Roles Anywhere documentation](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html)
for service setup and permissions.

## Usage

Pass the provider to the AWS SDK's `config.WithCredentialsProvider` option.
The example below also uses the SDK's configuration module:

```sh
go get github.com/aws/aws-sdk-go-v2/config
```

Replace the file paths and ARNs with your own values.

```go
package main

import (
	"context"
	"log"

	rolesanywhere "github.com/algonc/aws-rolesanywhere-provider-go"
	"github.com/aws/aws-sdk-go-v2/config"
)

func main() {
	ctx := context.Background()
	region := "eu-central-1"

	provider := rolesanywhere.NewProvider(
		rolesanywhere.WithPrivateKeyPath("/path/to/private_key.pem"),
		rolesanywhere.WithCertificatePath("/path/to/certificate.pem"),
		rolesanywhere.WithRegion(region),
		rolesanywhere.WithSessionName("my-workload"),
		rolesanywhere.WithProfileArn("arn:aws:rolesanywhere:eu-central-1:123456789012:profile/PROFILE_ID"),
		rolesanywhere.WithRoleArn("arn:aws:iam::123456789012:role/MyRole"),
		rolesanywhere.WithTrustAnchorArn("arn:aws:rolesanywhere:eu-central-1:123456789012:trust-anchor/TRUST_ANCHOR_ID"),
	)

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(provider),
	)
	if err != nil {
		log.Fatal(err)
	}

	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Credentials expire at %s", creds.Expires)
}
```

Use `cfg` to create AWS service clients, for example with `s3.NewFromConfig(cfg)`.
The SDK retrieves credentials from the provider when making requests.

The default session duration is one hour, and credentials are refreshed on retrieval
within five minutes of expiration. Use `WithDurationSeconds` and
`WithRefreshMargin` to adjust these values. `WithSessionName` sets the role session
name, and `WithHTTPClient` supplies a custom HTTP client.

## Supported private keys

The provider detects the key type automatically. Supported PEM formats are:

- RSA: PKCS#1 (`RSA PRIVATE KEY`) or PKCS#8 (`PRIVATE KEY`).
- EC (ECDSA): SEC1 (`EC PRIVATE KEY`) or PKCS#8 (`PRIVATE KEY`).

Private keys must be unencrypted and match the certificate's public key.

## License

Licensed under the Apache License 2.0.
