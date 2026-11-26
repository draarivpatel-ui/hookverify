// ESM facade. Node's createRequire keeps this facade and the CommonJS engine
// on exactly the same implementation, so both module systems cannot diverge.
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const engine = require('../cjs/internal.cjs');

export const {
  HookVerifyError,
  ERROR_CODES,
  MemoryReplayStore,
  defineProvider,
  registerProvider,
  getProvider,
  listProviders,
  verify,
  verifyAsync,
  isValid,
  createVerifier,
  providers,
  github,
  stripe,
  slack,
  shopify,
  linear,
  svix,
  standardWebhooks,
  discord,
  helpers,
} = engine;

export default engine;
