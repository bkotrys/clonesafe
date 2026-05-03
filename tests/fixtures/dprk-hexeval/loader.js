// Synthetic — DPRK HexEval-style loader. Long hex blob decoded into a buffer.
// D30 fires from the DPRK content_signatures pattern.
'use strict';

const blob = Buffer.from('48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f', 'hex');
new Function(blob.toString())();
