/** Shared HTTP-ish errors used by API routes. Kept Next-free so unit tests can import them. */

export class BadRequestError extends Error {
  status = 400;
  constructor(message = 'Bad request') {
    super(message);
    this.name = 'BadRequestError';
  }
}
