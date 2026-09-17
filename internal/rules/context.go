package rules

import "context"

type unsafeWritesKey struct{}

// WithAllowUnsafeWrites returns a context that permits rules issuing
// non-idempotent write requests (PUT/PATCH/DELETE) against the target — used
// only by CACHE-005, which must send a real write to verify precondition
// enforcement. Off by default: a conformance probe must never mutate a live
// target's state unless the caller has explicitly opted in via the CLI's
// --allow-unsafe-writes flag.
func WithAllowUnsafeWrites(ctx context.Context, allow bool) context.Context {
	return context.WithValue(ctx, unsafeWritesKey{}, allow)
}

// allowUnsafeWrites reports whether the context has opted into unsafe
// writes; absent a value, it defaults closed (false).
func allowUnsafeWrites(ctx context.Context) bool {
	allow, _ := ctx.Value(unsafeWritesKey{}).(bool)
	return allow
}
