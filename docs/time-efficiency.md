# Attendance Export — making it time efficient

Notes on what actually makes a large attendance export fast, written for anyone
reimplementing this logic in another language or tuning their own Learn
integration. Language-agnostic: the reasoning, not the syntax.

`batch_attendance3.py` in this repository implements everything described here.
All latency and size figures are measured against a live Learn site, not
estimated.

Assumption: the integration runs with a **raised rate limit**, as a production
application should. Daily quota is not a design constraint. **Time is.**

---

## The time model

Everything below follows from one equation:

```
total time  ≈  (requests × latency) ÷ concurrency  +  CPU pairing  +  write time
```

Four terms, four independent levers. Each optimization attacks exactly one of
them, so they multiply rather than overlap:

| Term | Lever | Measured effect |
|---|---|---|
| `latency` | Reuse one HTTP connection | 732 ms → 40 ms per request |
| `concurrency` | Fetch records in parallel | ÷ 4 to ÷ 8 |
| `requests` | Fetch along the cheaper axis | up to 70% fewer |
| `CPU pairing` | Index records, don't scan | 11.3 s → 0.012 s per large course |
| `write time` | Stream rows to disk | avoids GB-scale buffering |

---

## Where the time goes

For a typical course (30 meetings, 200 students) the export costs **64
requests**:

| What | Requests | Share |
|---|---|---|
| Course detail | 1 | 2% |
| Meetings list | 1 | 2% |
| Membership list | 2 | 3% |
| **Attendance records** | **60** | **94%** |

Attendance records are fetched one call per meeting
(`30 meetings × ceil(200 students ÷ 100 per page) = 60`).

**Optimize the record fetch. Everything else is rounding error.** This is also
why field trimming barely helps time — it shrinks payloads, not the number of
round trips.

---

## Lever 1 — Reuse one connection (18x, the big one)

Opening a fresh TLS connection per request costs **732 ms**. Reusing an
established one costs **40 ms**. Same request, same data.

| 1,000 typical courses = 64,000 requests | Time |
|---|---|
| New connection per call | **13.0 hours** |
| One reused connection | **43 minutes** |

That single decision is worth more than every other optimization combined. The
default behaviour of most HTTP convenience wrappers is the slow path — they open
and close per call unless you explicitly hand them a persistent session or
client. Create one session at startup, use it for every request, keep it alive
for the whole batch.

Note this is about the *connection*, not authentication. Hold the session
separately from the token so a mid-batch token refresh doesn't tear down the
connection pool.

---

## Lever 2 — Fetch records concurrently

The per-meeting record fetches are 94% of the calls and are independent of one
another — a natural fan-out.

| Batch | Requests | Sequential | 4 workers | 8 workers |
|---|---|---|---|---|
| 100 courses, 30m × 200s | 6,400 | 4m | 64s | 32s |
| 1,000 courses, 30m × 200s | 64,000 | 43m | 11m | 5m |
| 1,000 courses, 45m × 400s | 186,000 | 2.1h | 31m | 16m |
| 5,000 courses, 30m × 200s | 320,000 | 3.6h | 53m | 27m |

Design points:

- **Parallelise within a course, not across courses.** Meetings of one course
  fan out; courses stay sequential. This keeps log lines and output rows in
  course order, makes a failure attributable to one course, and bounds how much
  is in flight.
- **Start at 4–8 and measure.** The ceiling is the server's, not yours. Raised
  is not unlimited.
- **Still honour backoff.** Respect `Retry-After` and back off on 429/5xx even
  with a raised limit, otherwise concurrency converts a transient blip into a
  batch-wide failure.
- **Refresh the token on the shared client**, not per worker, or you will
  stampede the token endpoint.

---

## Lever 3 — Fetch along the cheaper axis

Attendance records are available two ways, returning the **identical record
shape** (`meetingId`, `userId`, `status`) in the same envelope — so the choice
is invisible downstream:

```
per meeting:   cost = meetings × ceil(students ÷ 100)
per student:   cost = students × ceil(meetings ÷ 100)
```

Compute both per course, take the smaller:

| Course shape | Per meeting | Per student | Saving |
|---|---|---|---|
| 30 mtgs × 200 students | 60 | 200 | — |
| 45 mtgs × 400 students | 180 | 400 | — |
| **200 mtgs × 30 students** | **200** | **60** | **70%** |

A wash for normal lecture courses, a large win for meeting-heavy,
low-enrollment ones. Costs nothing to implement.

Related: keep page size at the maximum of 100. A smaller limit multiplies round
trips for no benefit.

---

## Lever 4 — Index records, don't scan them

Once records are fetched, each student/meeting pair needs its status. The
obvious implementation — scan the record list looking for a match — is
quadratic, because the record list itself grows as `meetings × students`:

```
for each meeting:
  for each student:
    find record where meetingId and userId match     ← scans the whole list
```

Build a lookup keyed on `(meetingId, userId)` once, then each pair is a single
hash hit:

```
index = {}
for each record:  index[(record.meetingId, record.userId)] = record

for each meeting:
  for each student:
    record = index[(meeting.id, student.id)]         ← constant time
```

| Course | Scanning | Indexed | Speedup |
|---|---|---|---|
| 12 mtgs × 25 students | 0.003 s | 0.0002 s | 17x |
| 30 mtgs × 200 students | 1.10 s | 0.003 s | 398x |
| 45 mtgs × 400 students | 11.3 s | 0.012 s | 978x |

This is pure CPU and easy to miss — it looks fine on a small test course and
collapses on a real one. At 1,000 typical courses, scanning adds ~18 minutes of
pure computation to the batch; indexing adds 3 seconds.

---

## Lever 5 — Stream the output

Rows are written as they are produced, never accumulated. A large batch produces
millions of rows; buffering them to write at the end turns tens of megabytes of
working memory into gigabytes.

Records are held **per course** and released when that course finishes:

| Course | Records in flight | Memory |
|---|---|---|
| typical 30m × 200s | 6,000 | 3 MB |
| big 45m × 400s | 18,000 | 9 MB |
| huge 60m × 1200s | 72,000 | 36 MB |

Keep that scoping. Accumulating across the batch is the one change that turns a
comfortable memory profile into an out-of-memory failure.

---

## What the modes do for time

The three export modes exist mainly for **output volume**, which matters for
write time and for whatever consumes the file. They barely change request count
(64 → 63 → 61).

| | Full | Minimal | Records only |
|---|---|---|---|
| Columns | 18 | 8 | 8 |
| Names / usernames | yes | no | no |
| `Null` rows for unmarked students | yes | yes | **no** |
| Bytes per row (measured) | ~220 | ~70 | ~70 |
| Rows | courses × mtgs × students | same | fill rate × that |

- **Full** — complete grid with human-readable identifiers. Use when a person
  reads the output, or when "marked absent" must be distinguishable from "never
  marked".
- **Minimal** — same rows, primary keys only. Roughly **3x smaller output**, and
  the membership payload itself drops ~7x because the user object is no longer
  expanded. Default choice for any large batch feeding a database.
- **Records only** — just the attendance that exists, no padding. The only mode
  whose row count tracks real data rather than the full grid. Changes the
  meaning of the export: you can no longer distinguish "no record" from "not
  enrolled".

**Volume reality check:**

| Batch | Rows | Full | Minimal |
|---|---|---|---|
| 1,000 courses, 30m × 200s | 6,000,000 | 1.32 GB | 0.42 GB |
| 5,000 courses, 30m × 200s | 30,000,000 | 6.60 GB | 2.10 GB |

Spreadsheets cap at 1,048,576 rows, so anything past roughly 175 typical courses
needs a database load rather than a file someone opens. Worth setting that
expectation before the first big run.

---

## Two things that look promising and aren't

**A bulk attendance download endpoint** (`/meetings/downloadUrl`) appears to
collapse the whole per-meeting loop into one call. It is not usable: it returns
a legacy web-application URL that 404s with an API bearer token, because it
expects a browser session cookie. Tested against a live site.

**Field selection on the meetings endpoint** is ignored — identical response
with and without. That response is already minimal. Field selection *does* work
on memberships, which is where the Minimal mode payload saving comes from.

---

## Putting it together

Same workload, 1,000 typical courses (30 meetings, 200 students), naive versus
optimized:

| | Naive | Optimized |
|---|---|---|
| Connection | new per call | one reused |
| Concurrency | sequential | 8 workers |
| Axis | always per meeting | cheaper of the two |
| Pairing | scan the record list | hash index |
| Network | 13.0 h | 5.3 m |
| CPU pairing | ~18 m | ~3 s |
| **Total** | **~13.3 hours** | **~5.4 minutes** |

Roughly **150x**, and none of it requires a faster server or a higher rate
limit — only the four structural choices above.

Order of implementation, by payoff per unit of effort:

1. Reuse the connection — one line, 18x
2. Index the pairing — a few lines, removes a quadratic
3. Stream the writes — structural, prevents a memory wall
4. Choose the axis — small calculation, helps some course shapes a lot
5. Add concurrency — most effort, biggest remaining win
