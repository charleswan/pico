# Pico

## Usage

Generate keys:

```sh
go run main.go generate-keys -p public.pem -k private.pem
```

Start the server:

```sh
go run main.go server -l :8080 -k private.pem -o ./received_files
```

Send a file from the client:

```sh
go run main.go client -f ./test.txt -s 127.0.0.1:8080 -p public.pem
```

## Generate RSA keys with OpenSSL

```sh
openssl genpkey -algorithm RSA -out private.pem
openssl rsa -pubout -in private.pem -out public.pem
```
