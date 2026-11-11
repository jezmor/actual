import { app } from '#server/auth/app';
import * as encryption from '#server/encryption';

const storage = vi.hoisted(() => new Map<string, unknown>());

vi.mock('#platform/server/asyncStorage', () => ({
  getItem: async (key: string) => storage.get(key),
  multiRemove: async (keys: string[]) => {
    keys.forEach(key => storage.delete(key));
  },
}));

async function loadSavedKey() {
  const key = await encryption.createKey({
    id: 'key-1',
    password: 'mypassword',
    salt: 'salt',
  });
  await encryption.loadKey(key);
  storage.set(
    'encrypt-keys',
    JSON.stringify({ 'cloud-file-1': key.serialize() }),
  );
  storage.set('user-token', 'token-1');
}

afterEach(() => {
  encryption.unloadAllKeys();
  storage.clear();
});

describe('subscribe-sign-out', () => {
  test('drops saved encryption keys by default', async () => {
    await loadSavedKey();

    await app.handlers['subscribe-sign-out']();

    expect(storage.has('user-token')).toBe(false);
    expect(storage.has('encrypt-keys')).toBe(false);
    expect(encryption.hasKey('key-1')).toBe(false);
  });

  test('keeps saved encryption keys when asked to', async () => {
    await loadSavedKey();

    await app.handlers['subscribe-sign-out']({ keepEncryptionKeys: true });

    expect(storage.has('user-token')).toBe(false);
    expect(storage.has('encrypt-keys')).toBe(true);
    expect(encryption.hasKey('key-1')).toBe(true);
  });
});
