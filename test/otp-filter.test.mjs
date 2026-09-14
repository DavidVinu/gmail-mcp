// The one-time-code filter, checked against the copy it came from.
//
// This server carries its own copy of `src/otp-filter.mjs`, deliberately: the
// two servers are separate deployments with separate blast radii, and a shared
// library between them would make an edit for one silently change the other.
//
// The price of that decision is drift, and drift in a filter is invisible
// until a code reaches a model. So the copies are not shared, they are
// *compared* -- by behaviour, not by text, because part of the divergence is
// intended. `scrub` and STRUCTURAL_FIELDS are excluded on purpose: Gmail
// identifies messages by opaque hex strings where IMAP uses decimal UIDs, and
// that difference is the whole reason the copies are not byte-identical.
//
// The fixed cases and the differential test against the Python original live
// in the protonmail-mcp repo. Point this at that repo and the filter here is
// held to the same characters:
//
//   OTP_FILTER_SIBLING=../protonmail-mcp/src/otp-filter.mjs npm test

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import { MASK, REDACTED, maskCodes, maskTable, redact } from '../src/otp-filter.mjs';

const SIBLING = process.env.OTP_FILTER_SIBLING;
const siblingPresent = Boolean(SIBLING) && fs.existsSync(SIBLING);

// One sample per branch of the announcement list, plus every exception it
// carves out. A corpus that misses a branch lets a change to that branch
// through -- the first version of this test did exactly that.
const SAMPLES = [
  '', 'nothing special', 'Your verification code is 010299',
  'TAN 8821', 'OTP 4711', '2FA 123456', 'MFA-Code 99213',
  'two factor 8821', 'two-factor 8821', '2-factor 8821',
  'Zwei-Faktor 8821', 'zwei faktor 8821',
  'one-time code 416107', 'one time password 416107',
  'onetime passcode 416107', 'Einmal-Kennwort 416107',
  'einmalpasswort 416107', 'passcode 416107',
  'Zugangscode 416107', 'Bestaetigungscode 416107',
  'Sicherheitscode 416107', 'Bestätigungscode 416107',
  'login code 416107', 'log-in code 416107', 'log in code 416107',
  'auth code 416107', 'authy code 416107', 'sms code 416107',
  'pin code 416107', 'zugangs code 416107',
  'verification code 416107', 'security code 416107',
  'access code 416107', 'confirmation code 416107',
  'Freigabe 416107',
  // ordinary words ending in "code" -- these must survive
  'Barcode 416107', 'QR-Code 416107', 'Quellcode 416107',
  'Unicode 416107', 'Dresscode 416107', 'Postcode 416107',
  'Zipcode 416107', 'Laendercode 416107', 'Ländercode 416107',
  'Farbcode 416107', 'Morsecode 416107', 'Geocode 416107',
  // the masking shapes themselves
  'PIN 123 456', '8 4 2 1 9 9', 'AB12-CD34', 'X7K9M2',
  // and the things that must never be touched
  'Rechnung 1234,50 EUR', 'am 2026-09-14', 'am 14-09-26',
  'Telefon (030) 123-4567', 'Jahr 2026', 'iPhone15',
  'Bestellnummer 1234567890123', 'Version 1.2.3', 'Raum 4711',
  '│ 7529 │ 416107 is your code │',
];

test('the filter masks and keeps what it is supposed to', () => {
  // A handful of anchors that hold without the sibling, so a stranger who
  // clones only this repo still measures something.
  assert.ok(maskCodes('Your verification code is 010299').includes(MASK));
  assert.ok(redact('Your verification code is 010299').includes(REDACTED));
  assert.equal(maskCodes('Version 1.2.3'), 'Version 1.2.3');
  assert.equal(maskCodes('Jahr 2026'), 'Jahr 2026');
  assert.equal(maskCodes(''), '');
});

test('the sibling server masks exactly the same characters',
  { skip: siblingPresent ? false : 'OTP_FILTER_SIBLING not set' },
  async () => {
    const other = await import(path.resolve(SIBLING));
    for (const input of SAMPLES) {
      assert.equal(other.maskCodes(input), maskCodes(input),
        `maskCodes differs at ${JSON.stringify(input)}`);
      assert.equal(other.redact(input), redact(input),
        `redact differs at ${JSON.stringify(input)}`);
      assert.equal(other.maskTable(input), maskTable(input),
        `maskTable differs at ${JSON.stringify(input)}`);
    }
    // The masks themselves must agree, or one server hides a code behind a
    // word the other does not use and the difference is invisible in review.
    assert.equal(other.MASK, MASK);
    assert.equal(other.REDACTED, REDACTED);
  });
