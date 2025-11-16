# 🚀 Auth-SaaS

### **Production-Ready Authentication Module for Modern SaaS Applications**

Auth-SaaS is a fully-scalable, real-world authentication module designed for **SaaS products, microservices, mobile apps, and API-first platforms**.

Built with clean architecture, JWT security, Flyway migrations, and enterprise-grade patterns — this module is crafted to be **reused across any SaaS you build**.

This is part of the **RaiseHigh Tech – SaaS Starter Template**, engineered for founders who want to launch MVPs fast and scale without friction.

---

# 🔥 Features

### **Everything a serious SaaS authentication system needs**

* ✔ User Signup (email, password, full name)
* ✔ Login with JWT Access Token
* ✔ Refresh Token Generation
* ✔ BCrypt Password Hashing
* ✔ Stateless Authentication (ready for scaling)
* ✔ Role Support (USER, ADMIN – extensible)
* ✔ Flyway Database Migrations
* ✔ Swagger / OpenAPI documentation
* ✔ Clean folder structure (microservice-ready)
* ✔ Ready for multi-tenancy, RBAC & billing integration

---

# 🧱 Tech Stack

* **Spring Boot 3.5**
* **Spring Security (Stateless)**
* **PostgreSQL**
* **Flyway**
* **JWT (JJWT)**
* **Maven**
* **Java 17**

---

# 🗂 Folder Structure

```
Auth-SaaS/
│── README.md
│── pom.xml
│── .gitignore
│
├── src/main/java/com/raisehigh/saas/auth/
│   ├── AuthServiceApplication.java
│   ├── _config/SecurityConfig.java
│   ├── _security/JwtAuthFilter.java
│   ├── _security/JwtUtil.java
│   ├── controller/AuthController.java
│   ├── service/AuthService.java
│   ├── repository/UserRepository.java
│   ├── domain/User.java
│   └── dto/
│       ├── SignupRequest.java
│       ├── LoginRequest.java
│       └── AuthResponse.java
│
└── src/main/resources/
    ├── application.yaml
    └── db/migration/V1__create_users_table.sql
```

---

# ⚙️ Setup Instructions

## **1️⃣ Clone the repository**

```sh
git clone https://github.com/<your-username>/Auth-SaaS.git
cd Auth-SaaS
```

---

## **2️⃣ Configure environment variables**

Generate a secure Base64 32-byte JWT secret:

### Mac/Linux

```sh
export APP_JWT_SECRET=$(openssl rand -base64 32)
```

### Windows PowerShell

```powershell
$env:APP_JWT_SECRET = [Convert]::ToBase64String((New-Object Byte[] 32 | %{[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($_)}))
```

---

## **3️⃣ Update Postgres credentials**

Edit:

```
src/main/resources/application.yaml
```

Set:

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/saasdb
    username: saasuser
    password: saaspass
```

---

## **4️⃣ Run Flyway + Application**

```sh
mvn spring-boot:run
```

Flyway will auto-apply migration:

```
V1__create_users_table.sql
```

---

# 🧪 API Endpoints

## **Signup**

```
POST /api/auth/signup
```

Body:

```json
{
  "fullName": "John Doe",
  "email": "john@mail.com",
  "password": "password123"
}
```

---

## **Login**

```
POST /api/auth/login
```

Body:

```json
{
  "email": "john@mail.com",
  "password": "password123"
}
```

Returns:

```json
{
  "accessToken": "xxxxx",
  "refreshToken": "yyyyy",
  "tokenType": "Bearer",
  "userId": "uuid",
  "role": "USER"
}
```

---

## **Swagger UI**

```
http://localhost:8080/swagger-ui/index.html
```

---

# 📌 Why This Exists

I built this module as part of a **reusable SaaS Starter Framework** for founders and clients at **RaiseHigh Tech**.

The goal is simple:

### Build SaaS products 10× faster.

With a reusable, production-grade Auth module,
you eliminate:

* repetitive boilerplate
* inconsistent security practices
* authentication bugs
* setup delays

and deliver **scalable SaaS MVPs in weeks, not months**.

---

# 🛠 Upcoming Add-ons

This module will expand into a full SaaS starter kit:

* 🔐 Refresh token persistence (DB)
* 🏢 Multi-Tenant Architecture
* 👥 RBAC (Role & Permission Engine)
* 💳 Stripe / Razorpay Billing Module
* 📩 Email verification + password reset
* 📊 Admin dashboard starter
* 🌩 AWS deployment templates (Docker + CI/CD)

---

# ❤️ Contributing

Feel free to open issues and PRs — or DM me if you're building a SaaS and want help with architecture.

---

# 👋 About the Author

**SaaS Architect – Rajesh Ayyavu**
Founder @ RaiseHigh Tech
Helping founders launch scalable SaaS products.


