# Negative-cache TDB sizing

## Conclusion

`tdb_map_size()` is suitable for triggering negative-cache destruction and
recreation to limit retained capacity under repeated unique, attacker-controlled
insertions. **A 1 MiB threshold is a reasonable starting point for roughly
10,000 entries with the tested record sizes**, without requiring an exact
record-count limit.

## Setup and growth

Tested libtdb **1.4.14** in `tb-devel`, with 4 KiB pages and the same call as
`sss_ncache_init()` in `src/responder/common/negcache.c`:

```c
tdb_open("memcache", 0, TDB_INTERNAL, O_RDWR | O_CREAT, 0);
```

- **Initial map size: 696 bytes**, comprising the header and default
  131-bucket hash table.
- Growth is stepwise: initially small chunks, then approximately **25% per
  expansion**, rounded to page boundaries. Overall capacity grows approximately
  linearly with stored data, not exponentially per inserted record.
- Randomizing key contents did not change allocation behavior. Random key
  lengths of **8-64 characters** introduced fragmentation under deletion/reuse.
- Values were 10-digit timestamps; keys and values included terminating NULs,
  matching SSSD's string storage.

## Verification against TDB source

Verified against `/var/home/pbrezina/workspace/samba/lib/tdb` (version **1.4.15**).
Its `common/open.c`, `common/freelist.c`, `common/io.c` and
`common/tdb_private.h` are byte-identical to the upstream 1.4.14 files inspected
for the experiments. References below are relative to that TDB directory.

### Initial allocation

`common/open.c:62` calculates the database buffer size:

```c
size = sizeof(struct tdb_header) + (hash_size+1)*sizeof(tdb_off_t);
```

For `TDB_INTERNAL`, `common/open.c:105-107` assigns this size directly to
`tdb->map_size`. With a 168-byte header, the default 131 buckets and 4-byte
offsets, this gives **168 + 132 × 4 = 696 bytes**.

### Approximately 25% growth

`tdb_expand_adjust()` in `common/io.c:560-580` explicitly documents and
implements the percentage policy. Relevant statements, with overflow checks
omitted:

```c
/* always make room for at least top_size more records, and at
   least 25% more space. if the DB is smaller than 100MiB,
   otherwise grow it by 10% only. */
if (map_size > 100 * 1024 * 1024) {
    new_size = map_size * 1.10;
} else {
    new_size = map_size * 1.25;
}

/* Round the database up to a multiple of the page size */
new_size = MAX(top_size, new_size);
return TDB_ALIGN(new_size, page_size) - map_size;
```

Here `top_size` is the old map size plus a minimum increment. That increment
is selected at `common/io.c:547-551`:

```c
if (size > 100 * 1024) {
    increment = size * 2;
} else {
    increment = size * 100;
}
```

`size` is the allocation request for the record triggering expansion. Thus,
for our small records and maps below 100 MiB, the rule is:

```text
next_map = align_up(max(old_map + 100 × record_allocation,
                       floor(old_map × 1.25)), page_size)
```

This explains the early chunk-based growth and later 25% expansions, including
small increases above 25% due to page rounding. The function returns the
**additional bytes**, not the final map size. It also handles 32-bit size limits.

### Reported size is actual retained buffer capacity

`common/io.c:629-638` grows internal databases with
`realloc(tdb->map_ptr, new_size)` and assigns `tdb->map_size = new_size` after
successful allocation. The accessor in `common/tdb.c:874-877` simply returns it:

```c
_PUBLIC_ size_t tdb_map_size(struct tdb_context *tdb)
{
    return tdb->map_size;
}
```

`common/freelist.c:533-536` requests expansion only when the free-list search
cannot satisfy the allocation. Deletion returns space to that list without
shrinking the map (`common/freelist.c:277-319`). Closing the internal database
frees its buffer (`common/open.c:807-809`); clearing entries alone does not.

## Last expansion steps around the 1 MiB threshold

Representative seed-1 results. Counts are **live records at the insertion
triggering each expansion**, not cumulative insertions. The deletion workload
removes 500 randomly selected records after every 1,000 insertions.

| Map size after expansion | Increase | 32-character keys, insert-only | Random 8-64-character keys, insert-only | Random 8-64-character keys, with deletions |
|---:|---:|---:|---:|---:|
| 606,208 bytes (592 KiB) | 25.42% | 5,742 | 5,426 | 5,228 |
| 757,760 bytes (740 KiB) | 25.00% | 7,204 | 6,799 | 6,561 |
| 950,272 bytes (928 KiB) | 25.41% | 9,008 | 8,484 | 8,212 |
| **1,187,840 bytes (1,160 KiB)** | **25.00%** | **11,299** | **10,654** | **10,322** |

The final row crosses **1 MiB = 1,048,576 bytes**; the map does not pass through
the threshold exactly. Across the tested random-length seeds and deletion
profiles, crossings occurred at approximately **10.2-10.7k live records**.
Actual capacity depends on complete key lengths, values and deletion patterns.

## Deletion, fragmentation and reset semantics

Deleting records makes space reusable but **does not shrink the map**. With
variable sizes, a freed small block may not fit the next larger record;
reusing oversized blocks can also leave additional slack inside allocations.
Consequently, even a constant live-record count can require expansion. In a
5,000-live-record test, the map grew from 483,328 to 606,208 bytes during churn,
then stayed unchanged through 100,000 total insertions.

**Map size does not measure fragmentation directly.** It measures the entire
allocated database buffer, including record allocations and free space. It
therefore reflects additional capacity required because of fragmentation,
unlike a record counter. It is not total process memory usage.

Check the size after successful stores and recreate the cache when it reaches
the configured threshold. This allows an allocation-step overshoot, so it is
**not a strict memory ceiling**. Recreation must also restore any required
configured permanent negative-cache entries.
