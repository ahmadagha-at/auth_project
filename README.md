# Spring Security Authentication API

A learning-focused REST API built with **Spring Boot**, **Spring Security**, **PostgreSQL**, and **JWT**. It demonstrates how local username/password authentication and Google OpenID Connect can share one application-owned token and authorization system.

## Features

- Local registration and login with BCrypt password hashing
- Google login with OAuth 2.0 and OpenID Connect
- Short-lived JWT access tokens
- Database-backed refresh tokens with rotation and reuse detection
- Logout through refresh-token revocation
- Role- and permission-based authorization with `@PreAuthorize`
- Centralized JSON error handling
- CORS configuration for a separate frontend

## What I learned

This project explores the core concepts of Spring Security:

- configuring a `SecurityFilterChain`
- authenticating requests with a custom JWT filter
- separating authentication from authorization
- implementing roles and fine-grained permissions
- handling access-token expiration and refresh-token rotation
- integrating an external identity provider while continuing to issue application-owned tokens

## Authentication flows

### Local authentication

```text
Register or log in with username and password
→ Backend authenticates the user
→ Application issues an access token and refresh token
→ Access token authorizes protected requests
```

### Google authentication

```text
Open /oauth2/authorization/google
→ Authenticate with Google
→ Spring Security processes the callback
→ Application issues its own access token and refresh token
```

Google verifies the user's identity. Roles, permissions, JWTs, and refresh tokens remain controlled by this application.

## Getting started

### Requirements

- Java 17
- PostgreSQL
- A Google OAuth client for Google login

### Configuration

Provide the following environment variables through your IDE, shell, or a local `.env` integration:

```dotenv
DB_URL=jdbc:postgresql://localhost:5432/auth_project_db
DB_USERNAME=postgres
DB_PASSWORD=replace-me
JWT_ACCESS_SECRET_KEY=replace-with-a-long-base64-secret
GOOGLE_CLIENT_ID=replace-with-your-client-id
GOOGLE_CLIENT_SECRET=replace-with-your-client-secret
```

`application.yaml` reads these values using `${VARIABLE_NAME}` placeholders. Never commit real credentials.

Spring Boot does not load `.env` files automatically unless an IDE plugin or another integration provides that functionality.

Configure this authorized redirect URI in the Google OAuth client:

```text
http://localhost:8080/login/oauth2/code/google
```

Start the application:

```bash
./gradlew bootRun
```

On Windows:

```powershell
.\gradlew.bat bootRun
```

The API runs at `http://localhost:8080`. Ready-to-use request examples are available in `requests.http`.

## Main endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/auth/register` | Register a local user |
| `POST` | `/auth/login` | Log in with username and password |
| `GET` | `/oauth2/authorization/google` | Start Google authentication |
| `POST` | `/auth/refresh` | Rotate the refresh token and issue new tokens |
| `POST` | `/auth/logout` | Revoke the current refresh token |
| `GET` | `/auth/profile` | Access a protected user endpoint |

## Educational admin account

For demonstration purposes, registering the username `chef` assigns `ROLE_ADMIN`. This allows the protected admin endpoints to be tested without a separate administration interface.

> **Security notice:** This behavior is intentionally insecure and must not be used in production. A real application should provision administrators through a controlled database migration or another trusted administrative process.

## Disclaimer

This is an educational project for learning Spring Security, not a production-ready identity provider. Secrets, database credentials, and generated tokens must remain outside version control.
