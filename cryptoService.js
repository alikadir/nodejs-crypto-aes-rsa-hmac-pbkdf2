import CryptoJS from 'crypto-js';
import fs from 'fs';

const cryptoSecretKey = 'alikadir-123';

export const encryptText = (text) => {
  return CryptoJS.AES.encrypt(text, cryptoSecretKey).toString();
};

export const decryptText = (text) => {
  return CryptoJS.AES.decrypt(text, cryptoSecretKey).toString(CryptoJS.enc.Utf8);
};

export const encryptFile = (sourceFilePath, destinationFilePath) => {
  const sourceFileBase64 = fs.readFileSync(sourceFilePath).toString('base64');
  const sourceFileEncrypted = encryptText(sourceFileBase64);
  fs.writeFileSync(destinationFilePath, Buffer.from(sourceFileEncrypted, 'base64'));
};

export const decryptFile = (sourceFilePath, destinationFilePath) => {
  const sourceFileBase64 = fs.readFileSync(sourceFilePath).toString('base64');
  const sourceFileDecrypted = decryptText(sourceFileBase64);
  fs.writeFileSync(destinationFilePath, Buffer.from(sourceFileDecrypted, 'base64'));
};

export const passwordHashGenerateHmac = (password) => {
  // return 64 char. it is mean, 256 bit
  return CryptoJS.HmacSHA256(password, cryptoSecretKey).toString();
};

export const passwordHashGeneratePBKDF2 = (password) => {
  // keySize = 256 / 32 for 256 bit (return 64 char)
  // keySize = 512 / 32 for 512 bit (return 128 char)
  // recommended iteration 1000 for more secure key
  return CryptoJS.PBKDF2(password, cryptoSecretKey, { iterations: 1000, keySize: 256 / 32 }).toString();
};
