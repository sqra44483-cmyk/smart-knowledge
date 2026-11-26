'use strict';

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PRODUCTION = NODE_ENV === 'production';

app.disable('x-powered-by');
app.use(express.json({ limit: '25kb' }));

const allowedOrigin = process.env.FRONTEND_URL;

if (allowedOrigin) {
  app.use(cors({
    origin(origin, callback) {
      if (!origin || origin === allowedOrigin) {
        return callback(null, true);
      }
      return callback(new Error('Origin not allowed'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type']
  }));
}

const loginAttempts = new Map();
const MAX_ATTEMPTS = 8;
const WINDOW_MS = 10 * 60 * 1000;

function getClientKey(req) {
  return req.ip || req.socket.remoteAddress || 'unknown';
}

function isRateLimited(req) {
  const key = getClientKey(req);
  const now = Date.now();
  const entry = loginAttempts.get(key);

  if (!entry || now - entry.startedAt > WINDOW_MS) {
    loginAttempts.set(key, {
      startedAt: now,
      count: 1
    });
    return false;
  }

  entry.count += 1;
  return entry.count > MAX_ATTEMPTS;
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ''), 'utf8');
  const right = Buffer.from(String(b || ''), 'utf8');

  return left.length === right.length &&
    crypto.timingSafeEqual(left, right);
}
