module github.com/sigstore/sigstore/pkg/signature/kms/plugin

replace github.com/sigstore/sigstore => ../../../../

go 1.21

require (
	github.com/sigstore/protobuf-specs v0.3.1
	github.com/sigstore/sigstore v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.63.2
	google.golang.org/protobuf v1.33.0
)

require (
	github.com/google/go-containerregistry v0.19.1 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/letsencrypt/boulder v0.0.0-20230907030200-6d76a0f91e1e // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.8.0 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	go.opentelemetry.io/otel/trace v1.24.0 // indirect
	golang.org/x/crypto v0.22.0 // indirect
	golang.org/x/net v0.24.0 // indirect
	golang.org/x/sys v0.19.0 // indirect
	golang.org/x/term v0.19.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto v0.0.0-20240227224415-6ceb2ff114de // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240227224415-6ceb2ff114de // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240415180920-8c6c420018be // indirect
	gopkg.in/go-jose/go-jose.v2 v2.6.3 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
