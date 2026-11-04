/**
 * Dual-shape entry: V2 reads `id`/`setup()`, V1 (>= 1.18.29) calls `server()`.
 * See https://opencode.ai/v2/docs/build/plugins/migrate-v1
 */
import { ContextSanitizer } from './index';
import v2 from './v2/index';

// Older V1 loaders call every function export; same reference as `server` so it is deduped.
export { ContextSanitizer };

export default {
  ...v2,
  server: ContextSanitizer,
};
