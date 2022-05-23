# IPCachePool
A simple cache pool for IPCache.

## How to use

#### Generate ECC Key

```
$ ./IPCachePool -genkey
Private Key: 
==>
LS0tLS1CRUdJTiBZYW90dCBFQ0MgUFJJVkFURSBLRVktLS0tLQpNSGNDQVFFRUlIdGlqL0s1YnpObVQrUUs1RHcyWmNldVd4RkI5UkZHZml0aTViaXVXS0Fxb0FvR0NDcUdTTTQ5CkF3RUhvVVFEUWdBRVUvS3RGQ1BrSjhhOVpXUmd6YmFtaVpQc2FRQXhSNE10OFEwbkVyWU5ieTQ5L0dWV1k0N1IKNUJUQXRscTdVM2JkRElwSXdQY0xSN3NrREFRMkxxR1BDdz09Ci0tLS0tRU5EIFlhb3R0IEVDQyBQUklWQVRFIEtFWS0tLS0tCg==
<==

Public Key: 
==>
LS0tLS1CRUdJTiBZYW90dCBFQ0MgUFVCTElDIEtFWS0tLS0tCk1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRVUvS3RGQ1BrSjhhOVpXUmd6YmFtaVpQc2FRQXgKUjRNdDhRMG5FcllOYnk0OS9HVldZNDdSNUJUQXRscTdVM2JkRElwSXdQY0xSN3NrREFRMkxxR1BDdz09Ci0tLS0tRU5EIFlhb3R0IEVDQyBQVUJMSUMgS0VZLS0tLS0K
<==

```

#### Write A Client Config
```
{
  "script": [],
  "servers": [
    {
      "name": "server1",
      "client_id": "client1",
      "public_key": "##public_key##",
      "transport": {
        "address": "",
        "port": 0,
        "http": {
          "host": "",
          "path": "/"
        },
        "tls": {
          "enable": true,
          "sni": "server1",
        }
      },
      "interval": 10,
      "ttl": 10
    }
  ]
}
```

#### Write A Server Config
```
{
  "log": {
    "file": "./server.log"
  },
  "clients": [
    {
      "name": "client1",
      "client_id": "client1",
      "private_key": "##private_key##",
      "ttl": 60
    }
  ],
  "transport": {
    "listen": "::",
    "port": 0,
    "http": {
      "path": "/",
    },
    "tls": {
      "enable": true,
      "cert": "./cert.pem",
      "key": "./key.pem",
    }
  },
  "scripts": {
    "pre": [
      {
        "script": "./pre.sh",
        "fatal": true,
        "return": true
      }
    ],
    "post": [
      {
        "script": "./post.sh",
        "fatal": true,
        "return": true
      }
    ]
  },
  "ipset": {
    "enable": true,
    "name4": "CacheV4",
    "name6": "CacheV6"
  }
}
```

#### Run Server
```
$ ./IPCachePool -m server -c ./server.json
```

#### Run Client
```
$ ./IPCachePool -m client -c ./client.json
```


## Support

- Support HTTP(S) Channel
- Support TLS Client Verify
- Support TLS ALPN
- Support IPSet (Server) (Just Linux Only && Has IPSet Support)
- Support Custom Script
- Support HTTP/2 (TLS) (Auto Support When Enable TLS)
- Support HTTP/3(QUIC) (TLS) (From [quic-go](https://github.com/lucas-clemente/quic-go))