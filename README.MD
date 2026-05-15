# AuthAPI

A microservice for handling authentication and JWT token generation for FitLife users. The service creates authorization tokens for members, personal trainers, and admins based on validated user information.

## Endpoints

- `POST /api/Auth/member` - Generate a JWT token for a member
- `POST /api/Auth/trainer` - Generate a JWT token for a personal trainer
- `POST /api/Auth/admin` - Generate a JWT token for an admin

## Technologies

- **C#**
- **ASP.NET Core**
- **JWT Authentication**
- **Microsoft ILogger**
- **Dependency Injection**
