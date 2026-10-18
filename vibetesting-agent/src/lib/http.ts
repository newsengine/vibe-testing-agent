import { AuthError, ForbiddenError, QuotaError } from './auth';
import { BadRequestError } from './errors';
import { NextResponse } from 'next/server';

export { BadRequestError };

export function json(data: unknown, status = 200) {
  return NextResponse.json(data, { status });
}

export function errorResponse(err: unknown) {
  if (err instanceof AuthError) return json({ error: err.message }, err.status);
  if (err instanceof ForbiddenError) return json({ error: err.message }, err.status);
  if (err instanceof QuotaError) return json({ error: err.message, code: 'quota' }, err.status);
  if (err instanceof BadRequestError) return json({ error: err.message }, err.status);
  const message = err instanceof Error ? err.message : 'Internal error';
  console.error(err);
  return json({ error: message }, 500);
}

export async function readJson<T>(req: Request): Promise<T> {
  return (await req.json()) as T;
}

export function clientIp(req: Request): string {
  return (
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('x-real-ip') ||
    'unknown'
  );
}
