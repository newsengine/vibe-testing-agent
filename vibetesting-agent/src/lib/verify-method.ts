import { BadRequestError } from './errors';

export const OWNERSHIP_METHODS = ['dns', 'email', 'file', 'meta'] as const;
export type OwnershipMethod = (typeof OWNERSHIP_METHODS)[number];

function isOwnershipMethod(value: unknown): value is OwnershipMethod {
  return typeof value === 'string' && (OWNERSHIP_METHODS as readonly string[]).includes(value);
}

/**
 * Parse the verify-route body. Method is required — missing or unknown values are 400,
 * never silently rewritten to dns.
 */
export function parseVerifyMethod(body: unknown): OwnershipMethod {
  if (body == null || typeof body !== 'object' || Array.isArray(body)) {
    throw new BadRequestError('method is required: dns | email | file | meta');
  }
  const method = (body as { method?: unknown }).method;
  if (method === undefined || method === null || method === '') {
    throw new BadRequestError('method is required: dns | email | file | meta');
  }
  if (!isOwnershipMethod(method)) {
    throw new BadRequestError(`invalid method "${String(method)}"; expected dns | email | file | meta`);
  }
  return method;
}

/** Read JSON from a Request and parse the ownership method. Invalid JSON → missing method → 400. */
export async function parseVerifyRequest(req: Request): Promise<OwnershipMethod> {
  let body: unknown = {};
  try {
    body = await req.json();
  } catch {
    body = {};
  }
  return parseVerifyMethod(body);
}
