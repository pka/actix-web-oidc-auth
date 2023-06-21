Actix web OIDC example
======================

This repo contains an example for using OpenID Connect authentication in an [Actix Web](https://actix.rs/) application.

## Running the examples

Create credentials with origin URL http://127.0.0.1:5000 and redirect URL http://127.0.0.1:5000/auth

### OIDC login with Google

Create credentials at https://console.developers.google.com/apis/credentials

```sh
OIDC_CLIENT_ID=xxx OIDC_CLIENT_SECRET=yyy cargo run
x-www-browser http://127.0.0.1:5000/login
```

### OIDC login with Gitlab

Create credentials at https://gitlab.example.com/admin/applications

```sh
OIDC_ISSUER_URL=https://gitlab.example.com OIDC_CLIENT_ID=xxx OIDC_CLIENT_SECRET=yyy cargo run
x-www-browser http://127.0.0.1:5000/
```
