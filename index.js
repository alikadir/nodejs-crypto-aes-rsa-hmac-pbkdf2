import CryptoJS from 'crypto-js';
import fs from 'fs';
const aesKey = 'aliveli';

const samplePlainText = 'Hello World!';

const encryptedText = CryptoJS.AES.encrypt(samplePlainText, aesKey).toString();
console.log({ encryptedText });

const decryptedText = CryptoJS.AES.decrypt(encryptedText, aesKey).toString(CryptoJS.enc.Utf8);
console.log({ decryptedText });

console.log('----------------------------------------------');

const readSampleFile = fs.readFileSync('sample-plain-image.png').toString('base64');

const encryptedFile = CryptoJS.AES.encrypt(readSampleFile, aesKey).toString();
console.log({ encryptedFile });
const encryptedFileBuffer = Buffer.from(encryptedFile, 'base64');
fs.writeFileSync('encrypted-image.png', encryptedFileBuffer);
console.log('created: encrypted-image.png');

console.log('-----------');

const readEncryptedFile = fs.readFileSync('encrypted-image.png').toString('base64');

const decryptedFile = CryptoJS.AES.encrypt(readEncryptedFile, aesKey).toString();
console.log({ decryptedFile });
const decryptedFileBuffer = Buffer.from(decryptedFile, 'base64');
fs.writeFileSync('decrypted-image.png', decryptedFileBuffer);
console.log('created: decrypted-image.png');

console.log('DONE');
