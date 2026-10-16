'use strict';

const { MemoryStore } = require('./memory');
const { SupabaseStore } = require('./supabase');

const truthy = (v) => /^(1|true|yes|on)$/i.test(String(v || ''));

// Supabase when credentials are configured, otherwise the local file store.
// A configured-but-broken Supabase is a hard error in production: silently
// writing incidents to a local file on one node is worse than not starting.
async function createStore(env = process.env) {
  const demo = truthy(env.AEGIS_DEMO);
  const url = env.SUPABASE_URL;
  const key = env.SUPABASE_SERVICE_ROLE_KEY || env.SUPABASE_SECRET_KEY;
  if (url && key) {
    const store = new SupabaseStore(url, key, { demo });
    try {
      await store.init();
      return { store, warning: null, demo };
    } catch (err) {
      if (!demo && !truthy(env.AEGIS_ALLOW_FALLBACK)) throw new Error(`Supabase is configured but not usable: ${err.message}`);
      const fallback = new MemoryStore({ demo, ...(env.AEGIS_DATA_FILE ? { file: require('path').resolve(env.AEGIS_DATA_FILE) } : {}) });
      await fallback.init();
      return { store: fallback, warning: `Supabase unavailable (${err.message}). Using the local file store.`, demo };
    }
  }
  const store = new MemoryStore({ demo, ...(env.AEGIS_DATA_FILE ? { file: require('path').resolve(env.AEGIS_DATA_FILE) } : {}) });
  await store.init();
  return { store, warning: null, demo };
}

module.exports = { createStore, truthy };