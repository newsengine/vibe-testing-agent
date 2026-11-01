import { json, errorResponse } from '@/lib/http';
import { enqueueDueScheduledCrawls } from '@/lib/schedule';

/**
 * Nightly cadence tick. Cloudflare Cron or an external scheduler POSTs here
 * with Authorization: Bearer $CRON_SECRET. Reuses the existing scan queue.
 */
export async function POST(req: Request) {
  try {
    const secret = process.env.CRON_SECRET || '';
    const header = req.headers.get('authorization') || '';
    const token = header.toLowerCase().startsWith('bearer ') ? header.slice(7).trim() : '';
    if (!secret || token !== secret) {
      return json({ error: 'Unauthorized' }, 401);
    }
    const result = await enqueueDueScheduledCrawls();
    return json({ ok: true, ...result });
  } catch (err) {
    return errorResponse(err);
  }
}

export async function GET(req: Request) {
  return POST(req);
}
