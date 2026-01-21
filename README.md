# Bastion-go

A go library to interact with [The Bastion](https://github.com/ovh/the-bastion/).


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