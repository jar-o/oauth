import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { RocksDatabase } from "@harperfast/rocksdb-js";
import { config } from "./config.js";

/**
 * Embedded RocksDB datastore. One database directory (`DATA_DIR`), one column family per
 * collection. Values are plain JS objects (the library serializes them with msgpack).
 *
 * RocksDB takes an exclusive file lock on the directory, so exactly one server process can
 * have it open; a second process fails at startup instead of corrupting data. That also means
 * one replica, and in k8s a `Recreate` rollout so old and new pods never overlap.
 *
 * All operations are synchronous. Reads are usually served from the memtable/block cache in
 * microseconds, and because Node runs each sync call to completion, read-modify-write
 * sequences such as `take()` cannot interleave with another request.
 */

let db: RocksDatabase | undefined;

export function openDb(): void {
  const dir = resolve(config.dataDir);
  mkdirSync(dir, { recursive: true, mode: 0o700 }); // holds refresh tokens and possibly the signing key
  // Small memtables: this is a tiny dataset spread over a few column families (default is 16 MB each).
  db = RocksDatabase.open(dir, { writeBufferSize: 4 * 1024 * 1024 });
  console.log(`[db] RocksDB opened at ${dir}`);
}

export function closeDb(): void {
  db?.close();
  db = undefined;
}

export class Collection<T> {
  private cf?: RocksDatabase;
  constructor(readonly name: string) {}

  private get store(): RocksDatabase {
    if (!db) throw new Error(`Database not open (collection "${this.name}")`);
    return (this.cf ??= db.use(this.name));
  }

  get(key: string): T | undefined {
    return this.store.getSync(key) as T | undefined;
  }

  has(key: string): boolean {
    return this.get(key) !== undefined;
  }

  put(key: string, value: T): void {
    this.store.putSync(key, value);
  }

  delete(key: string): void {
    this.store.removeSync(key);
  }

  /** Read and delete in one step — for single-use values like authorization codes. */
  take(key: string): T | undefined {
    const value = this.get(key);
    if (value !== undefined) this.delete(key);
    return value;
  }

  /** All entries in key order. */
  *entries(): Generator<[string, T]> {
    for (const { key, value } of this.store.getRange()) yield [String(key), value as T];
  }

  /** Deletes every entry matching `predicate`; returns how many were removed. */
  deleteWhere(predicate: (value: T, key: string) => boolean): number {
    const doomed: string[] = [];
    for (const [k, v] of this.entries()) if (predicate(v, k)) doomed.push(k);
    for (const k of doomed) this.delete(k);
    return doomed.length;
  }
}
