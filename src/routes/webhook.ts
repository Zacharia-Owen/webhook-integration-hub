import { Router, Request, Response } from "express";
import { pool } from "../db";
import { verifySignature } from "../middleware/verifySignature";

export const webhookRouter = Router();

// This is the one endpoint GitHub will actually call. Everything else in
// the project (idempotency, retries, the analyzer) reads from what this
// function writes to the events table.
webhookRouter.post(
  "/webhooks/github",
  verifySignature,
  async (req: Request, res: Response) => {
    // Everything below can throw (most likely: the DB isn't reachable, or
    // the events table doesn't exist yet). Wrapping the whole handler in
    // try/catch means a database problem returns a 500 to the caller
    // instead of crashing the entire Node process -- one bad request
    // should never be able to take down the whole server.
    try {
      const deliveryId = req.get("X-GitHub-Delivery");
      const eventType = req.get("X-GitHub-Event");
      const signatureValid = req.signatureValid ?? false;

      // A missing delivery ID means this isn't a well-formed GitHub request
      // at all -- we still log it so nothing silently disappears, but we
      // can't check it for duplicates without an ID to key on.
      if (!deliveryId) {
        await logEvent({
          deliveryId: "unknown-" + Date.now(),
          eventType,
          payload: req.body,
          signatureValid,
          status: "rejected",
          errorCategory: "malformed",
        });
        return res.status(400).json({ error: "Missing X-GitHub-Delivery header" });
      }

      // Reject (and log) anything that fails signature verification BEFORE
      // touching the payload any further. Never trust a request you can't verify.
      if (!signatureValid) {
        await logEvent({
          deliveryId,
          eventType,
          payload: req.body,
          signatureValid: false,
          status: "rejected",
          errorCategory: "auth",
        });
        return res.status(401).json({ error: "Invalid signature" });
      }

      // Try to insert. The UNIQUE(source, delivery_id) constraint from
      // schema.sql does the actual duplicate-detection work here -- if this
      // delivery_id already exists, the insert conflicts and we know it's a
      // redelivery rather than a new event.
      const inserted = await tryInsertEvent({
        deliveryId,
        eventType,
        payload: req.body,
        signatureValid: true,
      });

      if (!inserted) {
        // This is a normal, expected situation -- not an error. GitHub
        // guarantees "at least once" delivery, so redeliveries will happen.
        return res.status(200).json({ status: "duplicate, already processed" });
      }

      // Real event-handling logic (e.g. syncing data, notifying another
      // service) would go here. For now we just mark it processed.
      await pool.query(
        `UPDATE events SET status = 'processed', processed_at = now()
         WHERE delivery_id = $1 AND source = 'github'`,
        [deliveryId]
      );

      return res.status(200).json({ status: "processed" });
    } catch (err) {
      // Log the real error server-side for debugging, but never leak
      // internal details (stack traces, connection strings) to the caller.
      console.error("Error handling webhook:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

async function tryInsertEvent(params: {
  deliveryId: string;
  eventType?: string;
  payload: unknown;
  signatureValid: boolean;
}): Promise<boolean> {
  const result = await pool.query(
    `INSERT INTO events (delivery_id, source, event_type, payload, signature_valid, status)
     VALUES ($1, 'github', $2, $3, $4, 'received')
     ON CONFLICT (source, delivery_id) DO NOTHING
     RETURNING id`,
    [params.deliveryId, params.eventType, params.payload, params.signatureValid]
  );
  return (result.rowCount ?? 0) > 0;
}

async function logEvent(params: {
  deliveryId: string;
  eventType?: string;
  payload: unknown;
  signatureValid: boolean;
  status: string;
  errorCategory: string;
}) {
  await pool.query(
    `INSERT INTO events (delivery_id, source, event_type, payload, signature_valid, status, error_category)
     VALUES ($1, 'github', $2, $3, $4, $5, $6)
     ON CONFLICT (source, delivery_id) DO NOTHING`,
    [
      params.deliveryId,
      params.eventType,
      params.payload,
      params.signatureValid,
      params.status,
      params.errorCategory,
    ]
  );
}