import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { SecretName, secretsService } from '#services/secrets-service';
import { assertUrlAllowed } from '#util/ssrf';

import { handlers as app } from './app-simplefin';

vi.mock('#util/ssrf', () => ({
  assertUrlAllowed: vi.fn().mockResolvedValue(undefined),
}));

const VALID_ACCESS_KEY = 'https://user:pass@bridge.example.com/simplefin';
const FILE_ACCESS_KEY = 'https://file:secret@bridge.example.com/simplefin';
const FILE_ID = 'simplefin-budget-file';
const OTHER_FILE_ID = 'simplefin-other-budget-file';
const SETUP_TOKEN = Buffer.from(
  'https://bridge.example.com/claim/abc',
).toString('base64');

const statusResponse = (status, body = '') => ({
  ok: status >= 200 && status < 300,
  status,
  headers: { get: () => null },
  text: () => Promise.resolve(body),
});

const okResponse = body => statusResponse(200, body);

// The claim is a POST to the bridge; listing accounts is a GET. Route the mock
// by method so a test can stub one or both.
function mockFetch({ claim, accounts }) {
  global.fetch = vi
    .fn()
    .mockImplementation((url, options) =>
      Promise.resolve(options?.method === 'POST' ? claim : accounts),
    );
}

const post = path =>
  request(app).post(path).set('x-actual-token', 'valid-token');

const basicAuth = accessKey => {
  const { username, password } = new URL(accessKey);
  return `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
};

describe('app-simplefin', () => {
  beforeEach(() => {
    secretsService.set(SecretName.simplefin_token, null);
    secretsService.set(SecretName.simplefin_accessKey, null);
    for (const fileId of [FILE_ID, OTHER_FILE_ID]) {
      secretsService.reset(SecretName.simplefin_token, fileId);
      secretsService.reset(SecretName.simplefin_accessKey, fileId);
    }
    vi.spyOn(console, 'log').mockImplementation(vi.fn());
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('/status', () => {
    it('reports configured when a real token is stored', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN);

      const res = await post('/status');

      expect(res.body.data.configured).toBe(true);
    });

    it('reports not configured when the stored token is a Forbidden message', async () => {
      secretsService.set(
        SecretName.simplefin_token,
        'Forbidden (was it already claimed?)',
      );

      const res = await post('/status');

      expect(res.body.data.configured).toBe(false);
    });

    it('reports the global source when only a global token is stored', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN);

      const res = await post('/status').set('X-Actual-File-Id', FILE_ID);

      expect(res.body.data).toEqual({ configured: true, source: 'global' });
    });

    it('prefers the token stored for the budget file', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN);
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN, FILE_ID);

      const res = await post('/status').set('X-Actual-File-Id', FILE_ID);

      expect(res.body.data).toEqual({
        configured: true,
        source: 'per-budget-file',
      });
    });

    it('does not report another budget file as configured', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN, FILE_ID);

      const res = await post('/status').set('X-Actual-File-Id', OTHER_FILE_ID);

      expect(res.body.data).toEqual({ configured: false, source: null });
    });

    it('rejects an invalid budget file ID', async () => {
      const res = await post('/status').set('X-Actual-File-Id', '../file');

      expect(res.statusCode).toBe(400);
      expect(res.body.reason).toBe('invalid-file-id');
    });

    it('rejects a budget file the user cannot access', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN, FILE_ID);

      const res = await request(app)
        .post('/status')
        .set('x-actual-token', 'valid-token-user')
        .set('X-Actual-File-Id', FILE_ID);

      expect(res.statusCode).toBe(403);
      expect(res.body.reason).toBe('file-access-denied');
    });
  });

  describe('/accounts', () => {
    it('claims the token, trims the access key and returns accounts', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN);
      mockFetch({
        claim: okResponse(`${VALID_ACCESS_KEY}\n`),
        accounts: okResponse(
          JSON.stringify({ accounts: [{ id: 'account-1' }] }),
        ),
      });

      const res = await post('/accounts');

      expect(res.body.data.accounts).toEqual([{ id: 'account-1' }]);
      expect(secretsService.get(SecretName.simplefin_accessKey)).toBe(
        VALID_ACCESS_KEY,
      );
    });

    it('claims the budget file token and keeps its access key separate from the global one', async () => {
      secretsService.set(SecretName.simplefin_accessKey, VALID_ACCESS_KEY);
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN, FILE_ID);
      mockFetch({
        claim: okResponse(FILE_ACCESS_KEY),
        accounts: okResponse(
          JSON.stringify({ accounts: [{ id: 'file-account' }] }),
        ),
      });

      const res = await post('/accounts').set('X-Actual-File-Id', FILE_ID);

      expect(res.body.data.accounts).toEqual([{ id: 'file-account' }]);
      expect(secretsService.get(SecretName.simplefin_accessKey, FILE_ID)).toBe(
        FILE_ACCESS_KEY,
      );
      expect(secretsService.get(SecretName.simplefin_accessKey)).toBe(
        VALID_ACCESS_KEY,
      );
      expect(global.fetch).toHaveBeenLastCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: { Authorization: basicAuth(FILE_ACCESS_KEY) },
        }),
      );
    });

    it('uses the global credentials for a budget file without its own token', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN);
      secretsService.set(SecretName.simplefin_accessKey, VALID_ACCESS_KEY);
      mockFetch({
        accounts: okResponse(
          JSON.stringify({ accounts: [{ id: 'account-1' }] }),
        ),
      });

      const res = await post('/accounts').set('X-Actual-File-Id', FILE_ID);

      expect(res.body.data.accounts).toEqual([{ id: 'account-1' }]);
      expect(
        secretsService.get(SecretName.simplefin_accessKey, FILE_ID),
      ).toBeNull();
      expect(global.fetch).toHaveBeenLastCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: { Authorization: basicAuth(VALID_ACCESS_KEY) },
        }),
      );
    });

    it('rejects a budget file the user cannot access without contacting SimpleFIN', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN, FILE_ID);
      global.fetch = vi.fn();

      const res = await request(app)
        .post('/accounts')
        .set('x-actual-token', 'valid-token-user')
        .set('X-Actual-File-Id', FILE_ID);

      expect(res.statusCode).toBe(403);
      expect(global.fetch).not.toHaveBeenCalled();
    });

    it('treats a "Forbidden (was it already claimed?)" claim response as invalid and does not persist it', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN);
      mockFetch({ claim: okResponse('Forbidden (was it already claimed?)') });

      const res = await post('/accounts');

      expect(res.body.data.error_code).toBe('INVALID_ACCESS_TOKEN');
      expect(secretsService.get(SecretName.simplefin_accessKey)).toBeNull();
    });

    it('treats a blank claim response as invalid and does not persist it', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN);
      mockFetch({ claim: okResponse('   \n') });

      const res = await post('/accounts');

      expect(res.body.data.error_code).toBe('INVALID_ACCESS_TOKEN');
      expect(secretsService.get(SecretName.simplefin_accessKey)).toBeNull();
    });

    it('re-claims when a stale Forbidden access key is cached', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN);
      secretsService.set(
        SecretName.simplefin_accessKey,
        'Forbidden (was it already claimed?)',
      );
      mockFetch({
        claim: okResponse(VALID_ACCESS_KEY),
        accounts: okResponse(
          JSON.stringify({ accounts: [{ id: 'account-1' }] }),
        ),
      });

      const res = await post('/accounts');

      expect(res.body.data.accounts).toEqual([{ id: 'account-1' }]);
      expect(secretsService.get(SecretName.simplefin_accessKey)).toBe(
        VALID_ACCESS_KEY,
      );
    });

    it('re-claims when a stale empty access key is cached', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN);
      secretsService.set(SecretName.simplefin_accessKey, '');
      mockFetch({
        claim: okResponse(VALID_ACCESS_KEY),
        accounts: okResponse(
          JSON.stringify({ accounts: [{ id: 'account-1' }] }),
        ),
      });

      const res = await post('/accounts');

      expect(res.body.data.accounts).toEqual([{ id: 'account-1' }]);
      expect(secretsService.get(SecretName.simplefin_accessKey)).toBe(
        VALID_ACCESS_KEY,
      );
    });

    it('re-claims when a stale non-URL access key is cached', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN);
      secretsService.set(
        SecretName.simplefin_accessKey,
        '<html>Bad Gateway</html>',
      );
      mockFetch({
        claim: okResponse(VALID_ACCESS_KEY),
        accounts: okResponse(
          JSON.stringify({ accounts: [{ id: 'account-1' }] }),
        ),
      });

      const res = await post('/accounts');

      expect(res.body.data.accounts).toEqual([{ id: 'account-1' }]);
      expect(secretsService.get(SecretName.simplefin_accessKey)).toBe(
        VALID_ACCESS_KEY,
      );
    });

    it('treats a claim response that is not an access URL as invalid and does not persist it', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN);
      mockFetch({ claim: okResponse('<html>Service unavailable</html>') });

      const res = await post('/accounts');

      expect(res.body.data.error_code).toBe('INVALID_ACCESS_TOKEN');
      expect(secretsService.get(SecretName.simplefin_accessKey)).toBeNull();
    });

    it('rejects a token that does not decode to a claim URL without contacting SimpleFIN', async () => {
      secretsService.set(
        SecretName.simplefin_token,
        Buffer.from('not a claim url').toString('base64'),
      );
      global.fetch = vi.fn();

      const res = await post('/accounts');

      expect(res.body.data.error_code).toBe('INVALID_ACCESS_TOKEN');
      expect(global.fetch).not.toHaveBeenCalled();
    });

    it('treats a 403 Forbidden claim as an invalid token and does not persist it', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN);
      mockFetch({
        claim: statusResponse(403, 'Forbidden (was it already claimed?)'),
      });

      const res = await post('/accounts');

      expect(res.body.data.error_code).toBe('INVALID_ACCESS_TOKEN');
      expect(secretsService.get(SecretName.simplefin_accessKey)).toBeNull();
    });

    it('reports SERVER_DOWN when the claim response is a redirect', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN);
      mockFetch({ claim: statusResponse(302) });

      const res = await post('/accounts');

      expect(res.body.data.error_code).toBe('SERVER_DOWN');
      expect(secretsService.get(SecretName.simplefin_accessKey)).toBeNull();
    });

    it('reports SERVER_DOWN when the claim fails with a server error', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN);
      mockFetch({
        claim: statusResponse(502, '<html>Bad Gateway</html>'),
      });

      const res = await post('/accounts');

      expect(res.body.data.error_code).toBe('SERVER_DOWN');
      expect(secretsService.get(SecretName.simplefin_accessKey)).toBeNull();
    });

    it('reports SERVER_DOWN when the claim request fails at the network level', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN);
      global.fetch = vi.fn().mockRejectedValue(new TypeError('fetch failed'));

      const res = await post('/accounts');

      expect(res.body.data.error_code).toBe('SERVER_DOWN');
      expect(secretsService.get(SecretName.simplefin_accessKey)).toBeNull();
    });

    it('reports SERVER_DOWN when the claim URL fails the SSRF preflight', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN);
      assertUrlAllowed.mockRejectedValueOnce(
        new Error('Unable to resolve host: bridge.example.com'),
      );
      global.fetch = vi.fn();

      const res = await post('/accounts');

      expect(res.body.data.error_code).toBe('SERVER_DOWN');
      expect(global.fetch).not.toHaveBeenCalled();
      expect(secretsService.get(SecretName.simplefin_accessKey)).toBeNull();
    });
  });

  describe('/transactions', () => {
    it('reports an invalid token when the cached access key is not an access URL', async () => {
      secretsService.set(
        SecretName.simplefin_accessKey,
        '<html>Bad Gateway</html>',
      );
      global.fetch = vi.fn();

      const res = await post('/transactions').send({
        accountId: 'account-1',
        startDate: '2026-07-01',
      });

      expect(res.body.data.error_code).toBe('INVALID_ACCESS_TOKEN');
      expect(global.fetch).not.toHaveBeenCalled();
    });

    it('downloads with the access key stored for the budget file', async () => {
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN);
      secretsService.set(SecretName.simplefin_accessKey, VALID_ACCESS_KEY);
      secretsService.set(SecretName.simplefin_token, SETUP_TOKEN, FILE_ID);
      secretsService.set(
        SecretName.simplefin_accessKey,
        FILE_ACCESS_KEY,
        FILE_ID,
      );
      mockFetch({
        accounts: okResponse(JSON.stringify({ accounts: [], errors: [] })),
      });

      await post('/transactions').set('X-Actual-File-Id', FILE_ID).send({
        accountId: 'account-1',
        startDate: '2026-07-01',
      });

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: { Authorization: basicAuth(FILE_ACCESS_KEY) },
        }),
      );
    });

    it('rejects a budget file the user cannot access', async () => {
      secretsService.set(
        SecretName.simplefin_accessKey,
        FILE_ACCESS_KEY,
        FILE_ID,
      );
      global.fetch = vi.fn();

      const res = await request(app)
        .post('/transactions')
        .set('x-actual-token', 'valid-token-user')
        .set('X-Actual-File-Id', FILE_ID)
        .send({ accountId: 'account-1', startDate: '2026-07-01' });

      expect(res.statusCode).toBe(403);
      expect(global.fetch).not.toHaveBeenCalled();
    });
  });
});
