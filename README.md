## using Nodejs, cryptography with AES, RSA, HMAC, PBKDF2


**AES256** is a fast cryptography algorithm for text and file encryption.

**RSA** is a more secure cryptography algorithm for text and file encryption.

---

**HMAC** - SHA256(Password + Salt) 

_HMAC is more complex and secure than SHA256_

**PBKDF2** - N...SHA256(Password + SHA256(Password + Salt)) 

_PBDKF2 is more complex and secure than HMAC_

---

### JWT
```javascript
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload), 
  "your-256-bit-secret"  
)
```
`npm install base64url` or native base64 and url encoder
```javascript
encodeURIComponent(Buffer.from('{name:"ali"}').toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'))
encodeURIComponent(btoa('{name:"ali"}').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'))
```

---

**Postman** Collection for text and file crypto request

https://www.getpostman.com/collections/f12246b2ac128c4660af

