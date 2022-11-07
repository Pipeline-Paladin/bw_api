# Taime
A sample application to test OpenID Connect.

Components:

- A protected "powerful" day prediction API to predict what day it currently is.
- A Single Page application with beautiful UI
- Keycloak as IdP
- Open Policy Agent to verify claims

## Setup

1. Add dns entries in hosts

Add to redirect http://keycloak:8080 to localhost:
```
keycloak 127.0.0.1
```

2. Start with docker-compose

```console
$ docker compose build
$ docker compose up -d
```
3. Navigate To keycloak

Login with `admin`/`uiouiop`

4. Create a realm & use `realm-export.json`

5. Create users in the group taimeUser or taimeAdmin

6. Navigate to http://localhost:4200
