/**
 * Dual-shape plugin entry for universal opencode v1/v2 compatibility.
 *
 * opencode v1's loader takes `default.server(input, options)`; opencode v2's
 * loader takes `default.setup(context)`. One object serves both hosts.
 */

import { ContextSanitizer } from "./index"
import v2 from "./v2/index"

const noopDispose = () => {}

const dispatcher = {
    id: "opencode-log-sanitizer",
    server: ContextSanitizer,
    setup: async (ctx: any) => {
        if (ctx?.app?.version) return v2.setup(ctx)
        if (typeof ctx?.event?.subscribe === "function") {
            return v2.setup(ctx)
        }
        if (ctx?.serverUrl || ctx?.client) {
            return ContextSanitizer(ctx, ctx?.options)
        }
        console.warn("[opencode-log-sanitizer] unrecognised host context — plugin disabled.")
        return noopDispose
    },
}
export default dispatcher
