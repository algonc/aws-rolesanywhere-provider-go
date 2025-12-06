## AWS RolesAnywhere Provider GO

An alternative for rolesanywhere-credential-helper in pure Go.


## Example

```
	ctx := context.Background()

	// Construct provider with your local files and ARNs
	provider := rolesanywhere.NewProvider(
		rolesanywhere.WithPrivateKeyPath("/path/to/private_key.pem"),
		rolesanywhere.WithCertificatePath("/path/to/certificate.pem"),
		rolesanywhere.WithRegion("eu-central-1"),
		rolesanywhere.WithDurationSeconds(3600),
		rolesanywhere.WithProfileArn("arn:aws:rolesanywhere:...:profile/..."),
		rolesanywhere.WithRoleArn("arn:aws:iam::123456789012:role/MyRole"),
		rolesanywhere.WithTrustAnchorArn("arn:aws:rolesanywhere:...:trust-anchor/..."),
		rolesanywhere.WithSessionName("gosession"),
	)

	// Use provider as credentials provider for AWS SDK v2
	cfg, err := config.LoadDefaultConfig(ctx, config.WithCredentialsProvider(provider), config.WithRegion("eu-central-1"))
	if err != nil {
		panic(err)
	}

	// S3 upload example
	s3client := s3.NewFromConfig(cfg)
	uploader := manager.NewUploader(s3client)
```


## License

This project is licensed under the Apache-2.0 License.