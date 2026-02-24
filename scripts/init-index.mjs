#!/usr/bin/env node

import { createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { writeFileSync, readFileSync } from 'node:fs';

function signData(data, privKeyB64) {
  const ko = createPrivateKey({ key: Buffer.from(privKeyB64, 'base64'), format: 'der', type: 'pkcs8' });
  return cryptoSign(null, data, ko).toString('base64');
}

function sortDeep(val) {
  if (val === null || typeof val !== 'object') return val;
  if (Array.isArray(val)) return val.map(sortDeep);
  const sorted = {};
  for (const key of Object.keys(val).sort()) sorted[key] = sortDeep(val[key]);
  return sorted;
}

function canonicalJson(obj) {
  return JSON.stringify(sortDeep(obj));
}

function verifyData(data, sigB64, pubB64) {
  const ko = createPublicKey({ key: Buffer.from(pubB64, 'base64'), format: 'der', type: 'spki' });
  return cryptoVerify(null, data, ko, Buffer.from(sigB64, 'base64'));
}

const privKey = process.env.KITHKIT_CATALOG_PRIVATE_KEY;
if (!privKey) {
  console.error('Set KITHKIT_CATALOG_PRIVATE_KEY env var');
  process.exit(1);
}

const pubKey = readFileSync('catalog-authority.pub', 'utf8').trim();

// Empty index
const index = { version: 1, updated: new Date().toISOString(), skills: [] };
const indexCanonical = canonicalJson(index);
const indexSig = signData(Buffer.from(indexCanonical, 'utf8'), privKey);
const signedIndex = { ...index, signature: indexSig };
writeFileSync('index.json', canonicalJson(signedIndex));
console.log('index.json written');

// Empty revocation list
const entries = [];
const revCanonical = canonicalJson(entries);
const revSig = signData(Buffer.from(revCanonical, 'utf8'), privKey);
const signedRev = { entries, signature: revSig };
writeFileSync('revoked.json', canonicalJson(signedRev));
console.log('revoked.json written');

// Verify both
const { signature: iSig, ...iBody } = signedIndex;
const iOk = verifyData(Buffer.from(canonicalJson(iBody), 'utf8'), iSig, pubKey);
console.log('index.json verified:', iOk);

const rOk = verifyData(Buffer.from(canonicalJson(signedRev.entries), 'utf8'), signedRev.signature, pubKey);
console.log('revoked.json verified:', rOk);
