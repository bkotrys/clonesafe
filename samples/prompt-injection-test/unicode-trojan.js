// ====================================================================
// TEST FIXTURE: demonstrates PI-008 (hidden Unicode characters).
//
// This file contains Unicode bidirectional override characters and
// zero-width characters that can be used in "Trojan Source" attacks
// (CVE-2021-42574) and in the "GlassWorm" npm supply chain campaign
// (2026).
//
// The characters are inserted in comments and identifiers below.
// Your editor may render them invisibly or cause text direction to
// flip unexpectedly. This is the point — they're designed to hide
// malicious content from human reviewers.
//
// PI-008 should fire on every instance of these characters outside of
// the initial BOM position.
// ====================================================================

// Example 1: Right-to-left override in a string
// The following string contains U+202E (RIGHT-TO-LEFT OVERRIDE) between
// "safe" and "_function". When rendered, it may appear reversed or
// as an entirely different word depending on the editor.
const description = "This is a safe‮_function";

// Example 2: Zero-width space in an identifier
// The following variable name contains U+200B (ZERO WIDTH SPACE)
// between "normal" and "Variable". It looks like one identifier but
// is actually two separate character sequences to the JavaScript parser.
const normal​Variable = "hidden zero-width separator above";

// Example 3: Zero-width joiner in a comment
// This comment contains U+200D (ZERO WIDTH JOINER) characters
// that have‍no visible effect but can be used to smuggle data through
// content filters.

// Example 4: LTR/RTL embedding pair for Trojan Source style attack
// The following line contains embedding characters that could make
// the code render differently than it executes:
if (/* safe guard condition ‪ // */ true) {
  // The above comment may render as if the condition is commented out,
  // but the parser sees different tokens entirely.
  console.log("This line will execute");
}

// Example 5: BOM in the middle of a file (byte order mark where it shouldn't be)
// ﻿ <-- that's U+FEFF ZERO WIDTH NO-BREAK SPACE

// ====================================================================
// End of fixture. PI-008 detector should flag every non-BOM instance
// of U+200B, U+200C, U+200D, U+202A..U+202E, U+2066..U+2069, U+FEFF.
// ====================================================================

module.exports = {
  description,
  normalVariable: normal​Variable, // references the zero-width-containing identifier
};
