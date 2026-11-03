/**
 * Dual-shape plugin entry for universal opencode v1/v2 compatibility.
 *
 * Per the OpenCode plugin docs, a package can support both generations from
 * one default export: spread the V2 `Plugin.define(...)` result and add a V1
 * `server` function. V1 calls `server()`; V2 reads `id`/`setup()` and ignores
 * `server()`. See: https://opencode.ai/v2/docs/build/plugins (Support V1).
 */

import { ContextSanitizer } from './index';
import v2 from './v2/index';

export default {
  ...v2,
  server: ContextSanitizer,
};
