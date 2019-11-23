
① 认证 vs 授权

- Authentication —— identity (401 Unauthorized)
- Authorization —— identity (403 Forbidden)

② 状态

- stateful (e.g `session` using `cookie`)
  - session
    1. user submits---`credentials`(name,pwd)---> server
    2. server verifies---credentials--->`DB` ,if TRUE，-->3
    3. server creates---`session` --->temporary stored in `memory/cache(e.g redis)/DB(e.g MongoDB)`
    4. server issues `cookie` from `session ID` ---> user
    5. browser stores cookie
    6. user sends with `cookie` every request--->server
    7. server ensures whether it `validates`
    8. A bit time later,server `deletes` session
  - Cookies
    - `Request Headers`
      appended with `cookie` by browser
    - `Response Headers`
      `Set-Cookie` set with server
  - Security
    - `HMAC` 防篡改
    - usually encoded `URL` for 兼容
    - 极少`AES`类型的加密 无甚意义
  - Attributes
    - `Domain` and `path`
    - `Expiration`
  - Flags
    - `HttpOnly`  js unable
    - `Secure`  `HTTP` unable
    - `SameSite`  only same domain,e.g no CORS sharing
- stateless (token using `JWT`/`OAuth`/other)
  - Tokens　server responds in body or header
    1. not stored server-side,only client -> stateless
    2. signed with a secret -> against tampering
    3. typically sent in `Authorization` header
    4. opaque or self-contained
       - carries all required user data in payload
       - reduces db lookup,but exposes to XSS
    5. can be refreshed when to be expire
       - issued both access & refresh tokens
    6. used in SPA web apps/APIs,mobile apps
- JWT (JSON Web Tokens)