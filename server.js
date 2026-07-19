import 'dotenv/config';
import express from 'express';
import http from 'http';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);

const SITE_PASSWORD = process.env.SITE_PASSWORD || 'changeme';

app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.static(path.join(__dirname, "public")));

const gmailUsage = {};
const MAX_PER_HOUR = 28;

function checkLimit(email) {
  const now = Date.now();
  if (!gmailUsage[email]) {
    gmailUsage[email] = { count: 0, resetTime: now + 3600000 };
  }
  if (now > gmailUsage[email].resetTime) {
    gmailUsage[email] = { count:
