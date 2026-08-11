import "dotenv/config";
import express from "express";
import { webhookRouter } from "./routes/webhook";

const app = express();

app.use(
  express.json({
    verify: (req, _res, buf) => {
      (req as express.Request).rawBody = buf;
    },
  })
);

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.use(webhookRouter);

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`webhook-integration-hub listening on port ${port}`);
});