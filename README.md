# Crash-Resilient Key-Value Server (C++)

A multithreaded, encrypted key-value and user-profile server, extended with
**incremental, crash-resilient persistence**: every change is appended to an
on-disk log and `fsync`'d *before* the client is told "OK," so acknowledged data
survives a crash.

Built for CSE 303 (Operating Systems), on a framework provided by
Prof. Spear. Language: C++17 · Linux · OpenSSL · pthreads.

## How It Works

**Atomic, ordered log appends.** The hash map runs a caller-supplied lambda
*inside* the bucket's critical section. Every mutating operation (insert,
upsert, delete, set-profile) passes a lambda that writes its log record. The
in-memory change and the on-disk append therefore happen under the same lock.
If two threads update the same key, their log records land in the same order
as their updates.

**No torn or interleaved records.** Each record is fully encoded into a buffer
first, then written with a single `write()` system call. Concurrent appends
can't interleave, even when they touch different buckets.

**Durable before acknowledged.** Each append is followed by `fsync()` before
the operation returns, so a write the client has seen acknowledged is
already on disk.

**Recovery by replay.** On startup, `load_file()` streams the file record by
record. It starts from the last full snapshot and applies each diff in order,
so it never reads the whole file into memory.

**Compaction.** `SAVE` writes a compact snapshot to `<file>.tmp`, `fsync`s it,
and `rename()`s it over the original. The rename is atomic, so a crash
mid-save leaves either the old file or the new one, never a partial file.

### On-Disk Record Format

Each record starts with a 4-byte tag, followed by 32-bit lengths and the
payload, and is zero-padded to a 4-byte boundary.

| Tag | Written by | Payload |
| --- | --- | --- |
| `AUTH` | register user | username, salt, password hash, profile |
| `KVKV` | KV insert, or an upsert that inserts | key, value |
| `AUP_` | set user profile | username, new profile |
| `KVU_` | upsert that updates | key, new value |
| `KVD_` | KV delete | key |

## Repository Layout

```
server/       storage layer and server headers
common/       shared networking, crypto, and file helpers (course framework)
scripts/      course-provided functional tests (p4.py) and their helpers
docs/         the original assignment handout
*.mk          alternate build configurations used by the grading scripts
```

## Building

The server builds against precompiled course objects that aren't included in
this repo, so the code here is for reading rather than running.

## Known Limitations

- Return values from `write()` and `fsync()` aren't checked, so a failed disk
  write isn't reported back to the client.
- `SAVE` briefly closes and reopens the log file. Updates that land in that
  window are applied in memory but not logged. A per-file lock around
  `SAVE` and the log appends would close this gap.

The full assignment specification is in [`docs/ASSIGNMENT.md`](docs/ASSIGNMENT.md).
