# Bastion-go
[![Tests](https://github.com/adfinis/bastion-go/actions/workflows/test.yml/badge.svg)](https://github.com/adfinis/bastion-go/actions/workflows/test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/adfinis/bastion-go)](https://goreportcard.com/report/github.com/adfinis/bastion-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/adfinis/bastion-go.svg)](https://pkg.go.dev/github.com/adfinis/bastion-go)

A go library to interact with [The Bastion](https://github.com/ovh/the-bastion/).

## Installation

```bash
go get github.com/adfinis/bastion-go
```

## Example

```go
cfg := bastion.Config{
    Host:                  "bastion.mycompany.org",
    Port:                  22,
    Username:              "clarkkent",
}

client, err := bastion.New(&cfg, bastion.WithPrivateKeyFileAuthWithPassphrase(
    "/path/to/private/key",
    os.Getenv("BASTION_PRIVATE_KEY_PASSPHRASE"),
))
if err != nil {
    panic(err)
}

groupServers, err := client.GroupListServers("mygroup1")
if err != nil {
    panic(err)
}
_ = groupServers
```