# edgeproxy
Allow Transport TCP Traffic over different proxy transport protocols in a secured and simply way

## Generating a keypair
You generate a keypair for authenticating WSS clients 

```shell
openssl genrsa -out private.pem 4096
openssl rsa -in private.pem -pubout -out public.pem
```

And give the private key to the client with `--private-key` and validate it with the server using `--public-key`