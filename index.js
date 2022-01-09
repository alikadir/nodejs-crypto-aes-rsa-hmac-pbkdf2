import express from "express";
import formidable from "formidable";
import path from "path";
import {
  decryptFileAes,
  decryptTextAes,
  decryptTextRsa,
  encryptFileAes,
  encryptTextAes,
  encryptTextRsa,
  jwtTokenDecode,
  jwtTokenGenerate,
  passwordHashGenerateHmac,
  passwordHashGeneratePBKDF2,
} from "./cryptoService.js";

const port = 8000;
const app = express();
app.use(express.json());

app.post("/text-encrypt-aes", (req, res) => {
  const { text } = req.body;
  const encryptedText = encryptTextAes(text);
  res.json({ encryptedText });
});

app.post("/text-decrypt-aes", (req, res) => {
  const { text } = req.body;
  const decryptedText = decryptTextAes(text);
  res.json({ decryptedText });
});

app.post("/text-encrypt-rsa", (req, res) => {
  const { text, isUsingPrivateKey } = req.body;
  const encryptedText = encryptTextRsa(text, isUsingPrivateKey);
  res.json({ encryptedText, isUsingPrivateKey });
});

app.post("/text-decrypt-rsa", (req, res) => {
  const { text, isUsingPrivateKey } = req.body;
  const decryptedText = decryptTextRsa(text, isUsingPrivateKey);
  res.json({ decryptedText, isUsingPrivateKey });
});

app.post("/file-encrypt", (req, res, next) => {
  const form = formidable();

  form.parse(req, (err, fields, files) => {
    if (err) next(err);

    const { file1 } = files;
    const encryptedFilePath = path.join(
      process.cwd(),
      "encrypted-files",
      file1.name
    );
    encryptFileAes(file1.path, encryptedFilePath);
    res.json({ encryptedFilePath });
  });
});

app.post("/file-decrypt", (req, res, next) => {
  const form = formidable();

  form.parse(req, (err, fields, files) => {
    if (err) next(err);

    const { file1 } = files;
    const decryptedFilePath = path.join(
      process.cwd(),
      "decrypted-files",
      file1.name
    );
    decryptFileAes(file1.path, decryptedFilePath);
    res.json({ decryptedFilePath });
  });
});

app.post("/password-hash-hmac", (req, res) => {
  const { password } = req.body;
  const hashedPassword = passwordHashGenerateHmac(password);
  res.json({ password, hashedPassword });
});

app.post("/password-hash-pbkdf2", (req, res) => {
  const { password } = req.body;
  const hashedPassword = passwordHashGeneratePBKDF2(password);
  res.json({ password, hashedPassword });
});

app.post("/jwt-generate", (req, res) => {
  const { data } = req.body;
  const jwtToken = jwtTokenGenerate(data);
  res.json({ jwtToken });
});

app.post("/jwt-decode", (req, res) => {
  const { token } = req.body;
  const data = jwtTokenDecode(token);
  res.json({ data });
});

app.listen(port, () => {
  console.log(`server start http://localhost:${port}`);
});
