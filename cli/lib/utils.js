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

module.exports = {
  levenshtein,
  sha256,
  extractHooks,
  extractDeps,
  TOP_PACKAGES,
  KNOWN_SCOPES
};
