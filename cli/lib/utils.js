'use strict';

const crypto = require('crypto');

function levenshtein(a, b) {
  if (a.length < b.length) return levenshtein(b, a);
  if (b.length === 0) return a.length;
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 0; i < a.length; i++) {
    const curr = [i + 1];
    for (let j = 0; j < b.length; j++) {
      curr.push(Math.min(
        prev[j + 1] + 1,
        curr[j] + 1,
        prev[j] + (a[i] !== b[j] ? 1 : 0)
      ));
    }
    prev.splice(0, prev.length, ...curr);
  }
  return prev[b.length];
}

function sha256(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

function extractHooks(packageJsonString) {
  try {
    const pkg = JSON.parse(packageJsonString);
    const scripts = pkg.scripts || {};
    const hookNames = ['prepare', 'preinstall', 'install', 'postinstall', 'prepublish', 'prepublishOnly', 'prepack'];
    const hooks = [];
    for (const name of hookNames) {
      if (scripts[name]) {
        hooks.push([name, scripts[name]]);
      }
    }
    return hooks;
  } catch {
    return [];
  }
}

function extractDeps(packageJsonString) {
  try {
    const pkg = JSON.parse(packageJsonString);
    return {
      dependencies: pkg.dependencies || {},
      devDependencies: pkg.devDependencies || {},
      all: { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) }
    };
  } catch {
    return { dependencies: {}, devDependencies: {}, all: {} };
  }
}

const TOP_PACKAGES = [
  'express', 'lodash', 'chalk', 'debug', 'react', 'axios', 'request', 'commander',
  'moment', 'webpack', 'typescript', 'underscore', 'async', 'bluebird', 'uuid',
  'glob', 'minimist', 'yargs', 'inquirer', 'semver', 'mkdirp', 'rimraf',
  'body-parser', 'cookie-parser', 'cors', 'dotenv', 'mongoose', 'mysql',
  'pg', 'redis', 'socket.io', 'ws', 'jsonwebtoken', 'bcrypt', 'passport',
  'nodemon', 'jest', 'mocha', 'chai', 'sinon', 'eslint', 'prettier',
  'babel-core', 'babel-cli', 'webpack-cli', 'rollup', 'vite', 'esbuild',
  'next', 'nuxt', 'vue', 'angular', 'svelte', 'ember', 'backbone',
  'jquery', 'bootstrap', 'tailwindcss', 'postcss', 'autoprefixer', 'sass',
  'less', 'stylus', 'pug', 'ejs', 'handlebars', 'mustache', 'nunjucks',
  'cheerio', 'puppeteer', 'playwright', 'cypress', 'selenium-webdriver',
  'supertest', 'nock', 'faker', 'colors', 'ora', 'listr', 'prompts',
  'execa', 'shelljs', 'cross-env', 'concurrently', 'lerna', 'nx',
  'turbo', 'pnpm', 'npm', 'yarn', 'got', 'node-fetch', 'superagent',
  'http-proxy', 'express-validator', 'joi', 'zod', 'yup', 'ajv',
  'luxon', 'dayjs', 'date-fns', 'ramda', 'rxjs', 'immutable',
  'graphql', 'apollo-server', 'prisma', 'sequelize', 'typeorm', 'knex',
  'sharp', 'jimp', 'canvas', 'pdf-lib', 'xlsx', 'csv-parser',
  'winston', 'pino', 'bunyan', 'morgan', 'helmet', 'compression',
  'multer', 'formidable', 'busboy', 'archiver', 'tar', 'adm-zip',
  'crypto-js', 'bcryptjs', 'uuid', 'nanoid', 'shortid', 'cuid',
  'nodemailer', 'sendgrid', 'twilio', 'stripe', 'paypal-rest-sdk',
  'aws-sdk', 'firebase', 'firebase-admin', 'googleapis',
  'react-dom', 'react-router', 'react-router-dom', 'react-redux', 'redux',
  'redux-thunk', 'redux-saga', 'mobx', 'recoil', 'zustand', 'jotai',
  'styled-components', 'emotion', 'framer-motion', 'react-spring',
  'material-ui', 'antd', 'chakra-ui', 'headlessui', 'radix-ui',
  'formik', 'react-hook-form', 'swr', 'react-query', 'tanstack',
  'electron', 'nw', 'tauri', 'capacitor', 'cordova', 'react-native',
  'expo', 'ionic', 'three', 'd3', 'chart.js', 'echarts',
  'socket.io-client', 'mqtt', 'amqplib', 'bull', 'agenda', 'cron',
  'pm2', 'forever', 'cluster', 'http-server', 'serve', 'live-server',
  'cross-spawn', 'open', 'fs-extra', 'graceful-fs', 'chokidar',
  'commander', 'meow', 'cac', 'clipanion', 'oclif',
  'p-limit', 'p-queue', 'p-map', 'retry', 'bottleneck',
  'lru-cache', 'keyv', 'conf', 'lowdb', 'nedb',
  'passport-local', 'passport-jwt', 'passport-google-oauth20',
  'connect', 'koa', 'fastify', 'hapi', 'restify', 'polka'
];

const KNOWN_SCOPES = [
  '@angular', '@babel', '@types', '@aws-sdk', '@google-cloud', '@azure',
  '@nestjs', '@react-native', '@storybook', '@testing-library', '@emotion',
  '@mui', '@chakra-ui', '@prisma', '@trpc', '@tanstack', '@sveltejs',
  '@nuxtjs', '@vue', '@vitejs', '@rollup', '@esbuild', '@typescript-eslint',
  '@eslint', '@octokit', '@vercel', '@supabase', '@clerk', '@auth0',
  '@sentry', '@datadog', '@opentelemetry', '@grpc', '@protobufjs',
  '@apollo', '@graphql-tools', '@reduxjs', '@remix-run', '@expo',
  '@react-navigation', '@floating-ui', '@radix-ui', '@headlessui',
  '@heroicons', '@tailwindcss', '@ctrl'
];

// Common version-aliased / variant suffixes that should NOT be flagged as
// typosquats of their root package. e.g. `prettier-2` is a documented
// workspace alias for prettier v2, not an attack.
const VARIANT_SUFFIX_RE = /-(?:\d+|next|new|alpha|beta|rc|canary|legacy|classic|experimental|preview|nightly|core|cli|server|client|browser|node|esm|cjs|types?|test|tests?)$/i;

// Legitimate packages that happen to be Levenshtein-close to a popular
// package. Hand-curated allowlist — adding a name here is a deliberate
// "this is a real distinct project, not a typosquat" claim.
const TYPOSQUAT_ALLOWLIST = new Set([
  'enquirer',     // legit, distinct from inquirer
  'tslint',       // legit (deprecated), distinct from eslint
  'preact',       // legit, distinct from react
  'koa',          // sometimes hits short-name typosquat heuristics
  'hapi',         // 4-char popular package, false-prone
  'fast-glob',    // distinct from glob
  'micromatch',   // distinct from minimatch
  'bcryptjs',     // distinct from bcrypt
  'bcrypt-nodejs',// distinct from bcrypt
  'redux-saga',   // distinct
  'redux-thunk',
  'react-router-dom-v5-compat',
  'yjs',          // CRDT library, distinct from ejs
  'uid',          // legit short-id package, distinct from uuid
  'sax',          // XML parser, distinct from sass
  'wrap-ansi',
  'cli-spinners'
]);

// Legitimate scoped orgs that fall inside Levenshtein-distance-2 of a
// known scope but are themselves real, distinct projects. Adding a scope
// here means the project is a genuinely separate org/maintainer, not a
// scope-confusion attack against the lookalike.
const SCOPE_ALLOWLIST = new Set([
  '@vue', '@vitejs', '@vitest', '@svitejs', '@bazel',
  '@nrwl', '@npmcli', '@octokit', '@floating-ui', '@radix-ui',
  '@webcomponents', '@nestjs', '@graphql-tools', '@reduxjs',
  '@grpc',         // gRPC, distinct project from @trpc
  '@swc',          // Speedy Web Compiler, distinct from @vue/@mui shapes
  '@parcel',       // distinct
  '@rollup',
  '@bundle',
  '@types'
]);

// Single source of truth for typosquat detection used by both checkD16
// (drives the verdict floor) and DC-001 (drives the score). Centralizing
// avoids drift like the prettier-2 false positive where one fired and the
// other didn't.
//
// Returns an array of { dep, top, distance } matches. Caller decides weight.
function findTyposquats(deps, { topList = TOP_PACKAGES, includeAll = false } = {}) {
  const matches = [];
  const top = includeAll ? topList : topList.slice(0, 20);
  const topSet = new Set(top);
  for (const dep of Object.keys(deps)) {
    if (topSet.has(dep)) continue;
    if (dep.startsWith('@')) continue;          // scoped names → DC-004
    if (TYPOSQUAT_ALLOWLIST.has(dep)) continue; // hand-curated legit-but-close
    if (VARIANT_SUFFIX_RE.test(dep)) continue;  // prettier-2, react-next, etc.
    // dep ends with a digit and stripping the digit yields a top package?
    // e.g. prettier2, react16, vue3 — workspace aliases, not typosquats.
    const stripped = dep.replace(/\d+$/, '');
    if (stripped !== dep && topSet.has(stripped)) continue;
    const depLower = dep.toLowerCase();
    let matched = false;
    for (const t of top) {
      const tLower = t.toLowerCase();
      // Skip when dep is `<top>-<anything>` or `<top>.<anything>` —
      // common workspace pattern, not a typosquat.
      if (depLower.startsWith(tLower + '-') || depLower.startsWith(tLower + '.')) continue;
      const minLen = Math.min(dep.length, t.length);
      const d = levenshtein(depLower, tLower);
      if (d === 1 && minLen >= 3) { matches.push({ dep, top: t, distance: d }); matched = true; break; }
      // Bumped from minLen >= 6 to >= 8: real distance-2 typosquats targeting
      // names shorter than 8 chars are rare; the FP cost (e.g. prettier vs
      // prettier-2) dominated.
      if (d === 2 && minLen >= 8) { matches.push({ dep, top: t, distance: d }); matched = true; break; }
    }
    void matched; // (fall-through guard for future logic)
  }
  return matches;
}

module.exports = {
  levenshtein,
  sha256,
  extractHooks,
  extractDeps,
  findTyposquats,
  TYPOSQUAT_ALLOWLIST,
  SCOPE_ALLOWLIST,
  TOP_PACKAGES,
  KNOWN_SCOPES
};
