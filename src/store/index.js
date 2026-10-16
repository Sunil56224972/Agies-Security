'use strict';

const { MemoryStore } = require('./memory');
const { SupabaseStore } = require('./supabase');

// Picks Supabase when credentials are configured, otherwise the local sandbox.
// If Supabase is configured but unreachable or unmigrated, we fall back loudly
// rather than leaving every screen broken.
async function createStore(env = process.env) {
  const url = env.SUPABASE_URL;
  const key = env.SUPABASE_SERVICE_ROLE_KEY || env.SUPABASE_SECRET_KEY;
  if (url && key) {
    const store = new SupabaseStore(url, key);
    try {
      await store.init();
      return { store, warning: null };
    } catch (err) {
      const fallback = new MemoryStore();
      await fallback.init();
      return { store: fallback, warning: `Supabase unavailable (${err.message}). Using local sandbox.` };
    }
  }
  const store = new MemoryStore();
  await store.init();
  return { store, warning: null };
}

module.exports = { createStore };