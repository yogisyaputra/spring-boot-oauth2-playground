
# OAuth2 Login Demo (Spring Boot + Google/GitHub + JWT + Redis)

Project ini adalah contoh implementasi **login dengan Google & GitHub** menggunakan Spring Boot.  
Setelah login, sistem akan menerbitkan **JWT Access Token & Refresh Token** yang disimpan di cookie **HttpOnly**.  
Token dikelola di **Redis** sehingga bisa di-**revoke**, dan sistem mendukung **Role/Authority** (`USER` & `ADMIN`) untuk proteksi route.

## ✨ Fitur Utama

- ✅ Login via **Google** & **GitHub** (OAuth2 / OIDC).
- ✅ **JWT Access & Refresh Token** disimpan di cookie HttpOnly.
- ✅ **Stateless authentication** (tidak pakai HttpSession).
- ✅ Token di-whitelist di **Redis** (support revoke/logout).
- ✅ **Refresh token rotation** → refresh lama dicabut saat pakai.
- ✅ Role-based access control:
  - `USER` → akses API normal.
  - `ADMIN` → akses `/api/admin/**`.
- ✅ Support authentication:
  - securityFilterChain.
  - @PreAuthorize -> anotasi dilevel service (sebelum dieksekusi)
  - PostAuthorize -> anotasi dilevel service (setelah dieksekusi)
- ✅ CORS config → support FE di domain berbeda (dev: `http://localhost:8181`).
- ✅ Logout endpoint → hapus Access & Refresh + revoke di Redis.

## Setup Project

1. Clone & Build

```bash
git clone https://github.com/yogisyaputra/spring-boot-oauth2-playground.git
cd spring-boot-oauth2-playground
./mvnw clean install
```

2. Konfigurasi application.yml

```bash
app:
  jwt:
    secret: ${APP_JWT_SECRET:this_is_only_for_dev_change_me_32+}
  oauth2:
    post-login-redirect: http://localhost:8181/
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
          github:
            client-id: ${GITHUB_CLIENT_ID}
            client-secret: ${GITHUB_CLIENT_SECRET}
  data:
    redis:
      host: localhost
      port: 6379

```
Tips:
- Buat OAuth2 Client ID di [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
- Buat OAuth App di [GitHub Developer Settings](https://github.com/settings/developers)
- Redirect URI:
  - http://localhost:8080/login/oauth2/code/google
  - http://localhost:8080/login/oauth2/code/github.

3. Jalankan Backend

```bash
./mvnw spring-boot:run
```
4. Jalankan FE (opsional)
```bash
npx http-server fe -p 8181 --cors
```
## Endpoint Utama

Login
- http://localhost:8080/oauth2/authorization/google
- http://localhost:8080/oauth2/authorization/github

→ Redirect ke provider, lalu kembali dengan cookies:
- ACCESS_TOKEN (15 menit, HttpOnly)
- REFRESH_TOKEN (14 hari, HttpOnly)
## Profile Links
[![linkedin](https://img.shields.io/badge/linkedin-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/yogisyaputra/)
