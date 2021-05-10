import express from 'express';
import bodyParser from 'body-parser';
import formidable from 'formidable';
import path from 'path';
import { decryptFile, decryptText, encryptFile, encryptText } from './cryptoService.js';

const port = 8000;
const app = express();
app.use(bodyParser.json());

app.post('/text-encrypt', (req, res) => {
  const { text } = req.body;
  const encryptedText = encryptText(text);
  res.json({ encryptedText });
});

app.post('/text-decrypt', (req, res) => {
  const { text } = req.body;
  const decryptedText = decryptText(text);
  res.json({ decryptedText });
});

app.post('/file-encrypt', (req, res, next) => {
  const form = formidable();

  form.parse(req, (err, fields, files) => {
    if (err) next(err);

    const { file1 } = files;
    const encryptedFilePath = path.join(process.cwd(), 'encrypted-files', file1.name);
    encryptFile(file1.path, encryptedFilePath);
    res.json({ encryptedFilePath });
  });
});

app.post('/file-decrypt', (req, res, next) => {
  const form = formidable();

  form.parse(req, (err, fields, files) => {
    if (err) next(err);

    const { file1 } = files;
    const decryptedFilePath = path.join(process.cwd(), 'decrypted-files', file1.name);
    decryptFile(file1.path, decryptedFilePath);
    res.json({ decryptedFilePath });
  });
});

app.listen(port, () => {
  console.log(`server start http://localhost:${port}`);
});
