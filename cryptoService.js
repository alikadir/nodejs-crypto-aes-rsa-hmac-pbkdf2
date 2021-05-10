import CryptoJS from 'crypto-js';
import fs from 'fs';

const aesKey = 'alikadir-123';

export const encryptText = (text) => {
  return CryptoJS.AES.encrypt(text, aesKey).toString();
};

export const decryptText = (text) => {
  return CryptoJS.AES.decrypt(text, aesKey).toString(CryptoJS.enc.Utf8);
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
