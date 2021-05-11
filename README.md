## using Nodejs, cryptography with AES, HMAC, PBKDF2


**AES256** algorithm for text and file encrypt

**HMAC** - SHA256(Password + Salt)

**PBKDF2** - N...SHA256(Password + SHA256(Password + Salt))

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
encodeURIComponent(Buffer.from('{name:"ali"}').toString('base64').replaceAll('=',''))
encodeURIComponent(btoa('{name:"ali"}').replaceAll('=',''))
```

Postman Collection for text and file crypto request

https://www.getpostman.com/collections/f12246b2ac128c4660af

