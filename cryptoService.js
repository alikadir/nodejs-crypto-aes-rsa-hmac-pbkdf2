import crypto from 'crypto'
import CryptoJS from 'crypto-js'
import fs from 'fs'
import base64url from 'base64url'

const cryptoSecretKey = 'alikadir-123'

// region RSA Key Generation
export const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  // The standard secure default length for RSA keys is 2048 bits
  modulusLength: 2048
})
console.log(publicKey.export({ type: 'pkcs1', format: 'pem' }))
console.log(privateKey.export({ type: 'pkcs1', format: 'pem' }))
// endregion

export const encryptTextAes = (text) => {
  return CryptoJS.AES.encrypt(text, cryptoSecretKey).toString()
}

export const decryptTextAes = (text) => {
  return CryptoJS.AES.decrypt(text, cryptoSecretKey).toString(
    CryptoJS.enc.Utf8
  )
}

export const encryptTextRsa = (text, isUsingPrivateKey) => {
  return crypto
    .publicEncrypt(
      {
        key: isUsingPrivateKey ? privateKey : publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      Buffer.from(text)
    )
    .toString('base64')
}

export const decryptTextRsa = (text, isUsingPrivateKey) => {
  return crypto
    .privateDecrypt(
      {
        key: isUsingPrivateKey ? privateKey : publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      Buffer.from(text, 'base64')
    )
    .toString()
}

export const encryptFileAes = (sourceFilePath, destinationFilePath) => {
  const sourceFileBase64 = fs.readFileSync(sourceFilePath).toString('base64')
  const sourceFileEncrypted = encryptTextAes(sourceFileBase64)
  fs.writeFileSync(
    destinationFilePath,
    Buffer.from(sourceFileEncrypted, 'base64')
  )
}

export const decryptFileAes = (sourceFilePath, destinationFilePath) => {
  const sourceFileBase64 = fs.readFileSync(sourceFilePath).toString('base64')
  const sourceFileDecrypted = decryptTextAes(sourceFileBase64)
  fs.writeFileSync(
    destinationFilePath,
    Buffer.from(sourceFileDecrypted, 'base64')
  )
}

export const passwordHashGenerateHmac = (password) => {
  // return 64 char. it is mean, 256 bit
  return CryptoJS.HmacSHA256(password, cryptoSecretKey).toString()
}

export const passwordHashGeneratePBKDF2 = (password) => {
  // keySize = 256 / 32 for 256 bit (return 64 char)
  // keySize = 512 / 32 for 512 bit (return 128 char)
  // recommended iteration 1000 for more secure key
  return CryptoJS.PBKDF2(password, cryptoSecretKey, {
    iterations: 1000,
    keySize: 256 / 32
  }).toString()
}

export const jwtTokenGenerate = (data) => {
  const headerText = JSON.stringify({
    alg: 'HS256',
    typ: 'JWT'
  })
  const payloadText = JSON.stringify(data)
  const encodedHeader = base64url(headerText)
  const encodedPayload = base64url(payloadText)

  const signature = CryptoJS.HmacSHA256(
    encodedHeader + '.' + encodedPayload,
    cryptoSecretKey
  ).toString(CryptoJS.enc.Base64)

  return (
    encodedHeader +
    '.' +
    encodedPayload +
    '.' +
    base64ClearSpecialCharForJwt(signature)
  )
}

export const jwtTokenValidate = (token) => {
  const [header, payload, signature] = token.split('.')

  const verifySignature = CryptoJS.HmacSHA256(
    header + '.' + payload,
    cryptoSecretKey
  ).toString(CryptoJS.enc.Base64)

  return base64ClearSpecialCharForJwt(verifySignature) === signature
}

export const jwtTokenDecode = (token) => {
  if (!jwtTokenValidate(token)) return null

  const [header, payload, signature] = token.split('.')
  console.log({ header, payload, signature })
  const jsonPayload = base64url.decode(payload)

  return JSON.parse(jsonPayload)
}

const base64ClearSpecialCharForJwt = (base64) => {
  // I didn't understand why jwt libraries clear following chars in signature
  return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}
