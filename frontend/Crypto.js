/**
 * SkillSwap — End-to-End Encryption Module
 *
 * Algorithm:  ECDH (P-256) for key agreement
 *             AES-GCM 256-bit  for symmetric encryption
 * Key storage: Private key lives ONLY in IndexedDB on this device.
 *              Public  key is uploaded to the server once.
 *              The server stores only encrypted ciphertext and can never read messages.
 */

const SkillSwapCrypto = (() => {
  const IDB_NAME    = 'SkillSwapCrypto';
  const IDB_STORE   = 'keys';
  const KEY_RECORD  = 'myECDHKeyPair';

  /* ── IndexedDB helpers ── */
  function openIDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(IDB_NAME, 1);
      req.onupgradeneeded = e => e.target.result.createObjectStore(IDB_STORE);
      req.onsuccess       = e => resolve(e.target.result);
      req.onerror         = e => reject(e.target.error);
    });
  }

  async function idbPut(key, value) {
    const db = await openIDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, 'readwrite');
      tx.objectStore(IDB_STORE).put(value, key);
      tx.oncomplete = resolve;
      tx.onerror    = e => reject(e.target.error);
    });
  }

  async function idbGet(key) {
    const db = await openIDB();
    return new Promise((resolve, reject) => {
      const tx  = db.transaction(IDB_STORE, 'readonly');
      const req = tx.objectStore(IDB_STORE).get(key);
      req.onsuccess = e => resolve(e.target.result ?? null);
      req.onerror   = e => reject(e.target.error);
    });
  }

  /* ── Key generation & persistence ── */

  /** Generate a new ECDH key pair and save it to IndexedDB. */
  async function generateKeyPair() {
    const kp = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      /* extractable = */ true,   // so we can export the public key to the server
      ['deriveKey', 'deriveBits']
    );
    await idbPut(KEY_RECORD, kp);
    return kp;
  }

  /** Load key pair from IndexedDB, generating one if it doesn't exist yet. */
  async function getOrCreateKeyPair() {
    const stored = await idbGet(KEY_RECORD);
    if (stored) return stored;
    return generateKeyPair();
  }

  /* ── Key export / import ── */

  /** Export the *public* key as JWK (safe to send to the server). */
  async function exportPublicKey(keyPair) {
    return crypto.subtle.exportKey('jwk', keyPair.publicKey);
  }

  /** Import a peer's public key from a JWK received from the server. */
  async function importPublicKey(jwk) {
    return crypto.subtle.importKey(
      'jwk', jwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      /* extractable = */ false,
      []   // public keys have no usages — only used in deriveKey calls
    );
  }

  /* ── Shared key derivation (ECDH) ── */

  /**
   * Derive a shared AES-GCM key from MY private key + THEIR public key.
   * Both sides independently derive the *same* key without exchanging it.
   */
  async function deriveSharedKey(myPrivateKey, theirPublicKey) {
    return crypto.subtle.deriveKey(
      { name: 'ECDH', public: theirPublicKey },
      myPrivateKey,
      { name: 'AES-GCM', length: 256 },
      /* extractable = */ false,
      ['encrypt', 'decrypt']
    );
  }

  /* ── Encrypt / Decrypt ── */

  /**
   * Encrypt a plaintext string.
   * Returns { ciphertext: base64string, iv: base64string }
   */
  async function encrypt(sharedKey, plaintext) {
    const iv      = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plaintext);
    const buf     = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, sharedKey, encoded);
    return {
      ciphertext: _toBase64(new Uint8Array(buf)),
      iv:         _toBase64(iv),
    };
  }

  /**
   * Decrypt a { ciphertext: base64, iv: base64 } object.
   * Returns the plaintext string.
   */
  async function decrypt(sharedKey, ciphertext, iv) {
    const buf     = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: _fromBase64(iv) },
      sharedKey,
      _fromBase64(ciphertext)
    );
    return new TextDecoder().decode(buf);
  }

  /* ── Shared-key cache (one derived key per peer, per session) ── */
  const _keyCache = new Map();   // peerId → CryptoKey

  /**
   * Convenience method: get (or derive and cache) the shared AES key for a peer.
   * @param {CryptoKeyPair} myKeyPair
   * @param {object}        theirPublicKeyJwk  — JWK from server
   * @param {string|number} peerId
   */
  async function getSharedKey(myKeyPair, theirPublicKeyJwk, peerId) {
    const cacheKey = String(peerId);
    if (_keyCache.has(cacheKey)) return _keyCache.get(cacheKey);
    const theirKey  = await importPublicKey(theirPublicKeyJwk);
    const sharedKey = await deriveSharedKey(myKeyPair.privateKey, theirKey);
    _keyCache.set(cacheKey, sharedKey);
    return sharedKey;
  }

  /* ── Internal base64 helpers ── */
  function _toBase64(u8) {
    return btoa(String.fromCharCode(...u8));
  }
  function _fromBase64(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  }

  /* ── Public API ── */
  return {
    getOrCreateKeyPair,
    exportPublicKey,
    importPublicKey,
    deriveSharedKey,
    getSharedKey,
    encrypt,
    decrypt,
  };
})();