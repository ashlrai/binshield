import { serve } from "@hono/node-server";

import { createApp } from "./app";
import { readApiEnv } from "./lib/env";
import { createServices } from "./lib/repository";

const env = readApiEnv();
const app = createApp(createServices(env));
const port = env.port;

serve({
  fetch: app.fetch,
  port
});

console.log(`BinShield API running on http://localhost:${port} (${env.mode})`);
