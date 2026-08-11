import crypto from "crypto";
import { Request, Response, NextFunction } from "express";

// Express augments the Request type here so TypeScript knows about the
// extra fields we're attaching (rawBody comes from server.ts, signatureValid
// is set below).
declare global {
  namespace Express {
    interface Request {
      rawBody?: Buffer;
      signatureValid?: boolean;
    }
  }
}

// IMPORTANT: this checks the signature but does NOT reject invalid requests itself. Instead it attaches the result to req.signatureValid and lets the
// route handler decide what to do -- because we want to LOG rejected
// attempts to the database, not just silently 401 them. A support/integration
export function verifySignature(req: Request, _res: Response, next: NextFunction) {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  const signatureHeader = req.get("X-Hub-Signature-256"); // format: "sha256=<hex>"

  if (!secret || !signatureHeader || !req.rawBody) {
    req.signatureValid = false;
    return next();
  }

  // Recompute the signature ourselves using the shared secret and compare
  // it to what GitHub sent. This proves the request actually came from
  // GitHub (or whoever holds the secret) and wasn't forged or tampered with.
  const expected =
    "sha256=" +
    crypto.createHmac("sha256", secret).update(req.rawBody).digest("hex");

  // timingSafeEqual prevents a timing attack: a naive string comparison
  // (===) returns faster the sooner it finds a mismatched character, which
  // an attacker could exploit to guess the signature byte by byte. This
  // comparison always takes the same amount of time regardless of where
  // the strings differ.
  const expectedBuf = Buffer.from(expected);
  const receivedBuf = Buffer.from(signatureHeader);

  req.signatureValid =
    expectedBuf.length === receivedBuf.length &&
    crypto.timingSafeEqual(expectedBuf, receivedBuf);

  next();
}