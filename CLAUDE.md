# CLAUDE.md

Guidance for Claude Code working in this repo.

## What this is

A single-file Python 3.11 script that pulls Blackboard Learn attendance records
for a list of courses via the Learn REST API and writes one pipe-delimited row
per student/meeting pair.

    python batch_attendance3.py list_of_courses.csv [--env-file PATH]

It is a standalone utility distributed to clients — not a package, not a
library, no test suite, no CI. Optimize for "a Learn admin can download this and
run it on Windows," not for architectural purity.

Setup is plain `python -m venv` + `pip install -r`. The two `.bat` wrappers that
used to do this were removed — they were Windows-only and wrapped three standard
commands. Don't reintroduce wrapper scripts; document the commands instead.

## Layout

| Path | Purpose |
|---|---|
| `batch_attendance3.py` | The entire program |
| `.env.example` | Committed config template — `BB_HOST`/`BB_KEY`/`BB_SECRET`/paging/session buffer |
| `sample_list_of_course_IDs.csv` | Template input, one courseId per line |
| `attendance_requirements.txt` | pip requirements |
| `INSTALL.md` | End-user setup guide (was a .docx; converted to Markdown) |
| `docs/time-efficiency.md` | Public engineering note on scaling — measured latency, volume and the four levers |
| `internal/` | **Gitignored.** Local scratch, real credentials (`internal/.env`), real course lists, kept output |

## Running it

Each run creates a `YYYYMMDD-HHMMSS/` folder at the repo root containing
`attendance_output_*.csv` and `attendance_logfile_*.log`. Those folders are
gitignored by pattern. Never commit one, and never commit a filled-in `.env` or
a real course list — put those in `internal/`.

Do not run the script against a live Learn site without asking. It burns the
tenant's daily REST request quota and needs real credentials.

## Configuration

Config is `.env` only — the old `properties.ini` / `configparser` path was
removed. Variables are `BB_HOST`, `BB_KEY`, `BB_SECRET`, and the optional
`BB_RESULT_LIMIT` (default 100) and `BB_SESSION_BUFFER` (default 30). Names
deliberately match `Blackboard_REST_Test_Suite/src/bb_client/config.py` so
credentials are portable between the two repos.

Lookup order is `--env-file`, then `./.env`, then `./internal/.env`.
`load_dotenv(..., override=False)` means a real environment variable beats the
file, which is how a scheduler supplies a secret without writing it to disk.

`BB_HOST` is a bare hostname; `parse_arguments_and_config` strips any pasted
scheme and trailing slash before prepending `https://`. Don't add `BB_TOKEN`
support to match the test suite — this script runs long batches and depends on
`Authenticator` refreshing an expiring token, which a static token can't do.

## Code conventions in this file

Follow what's already there rather than modernizing it:

- `main()` behind an `if __name__ == '__main__'` guard. Importing the module has
  no side effects, which is what makes the fetchers and `build_rows` testable.
- `camelCase` locals, `UPPERCASE` config constants, `snake_case` functions.
- `LearnClient` owns the `requests.Session`, the auth header, paging and the
  request count. Every GET goes through `client._get`, so the
  `count_get_requests` decorator tallies them — never call `requests.get` or
  `session.get` directly.
- One `requests.Session` for the whole batch. Measured against Learn: ~730ms per
  request without it (fresh TLS handshake each time) versus ~40ms with it. Don't
  replace it with bare `requests.get`.
- `LearnClient` holds the `Authenticator` object, not its token string, so a
  mid-batch reauthentication is picked up by later requests automatically.
- A new endpoint is a module-level `fetch_*(client, ...)` function calling
  `client.get_json` (single object) or `client.get_paged` (follows
  `paging.nextPage`). Don't reintroduce a class per resource — the four old
  `Get*` classes were ~160 lines of near-identical boilerplate.
- Attendance records are paired to students through the `(meetingId, userId)`
  dict built in `build_rows`. The original linear scan was O((meetings ×
  students)²) — 11s of CPU for one 45-meeting, 400-student course. Keep it a
  dict lookup.
- Logging only — no `print`. `logging.info` for run narration, `logging.debug`
  for per-course/per-meeting detail, `logging.error` before a `sys.exit(1)`.
- Section headers are `#########################` comment banners.
- The author's typos in comments and log strings (`itterate`, `Recomend`,
  `privliges`) are pre-existing. Leave them unless the fix is the point of the
  change.

## Blackboard REST specifics

Endpoints in use (see https://developer.blackboard.com/portal/displayApi):

    POST /learn/api/public/v1/oauth2/token
    GET  /learn/api/public/v3/courses/{courseId}
    GET  /learn/api/public/v1/courses/{courseId}/users
    GET  /learn/api/public/v1/courses/{courseId}/meetings
    GET  /learn/api/public/v1/courses/{courseId}/meetings/{meetingId}/users

- Input lines are treated as batch UIDs and prefixed `courseId:` in URLs.
  `course_ident()` is the exception: it regex-matches `_\d+_1` and passes a pk1
  through unprefixed. The membership and meeting fetchers hardcode the prefix,
  so a pk1 in the input file resolves the course but then fails downstream.
- `Authenticator.is_token_nearly_expired(SESSIONBUFFER)` is checked at the top of
  each course iteration; token refresh happens there. Any new long loop needs the
  same check.
- Merged courses: `fetch_members` attaches child course info to each member,
  which fills the `child*` output columns. It looks up each distinct child once
  and skips members with no `childCourseId` — indexing that key unconditionally
  used to raise `KeyError` on students enrolled in the parent.
- A meeting with no attendance record for an enrolled student is written with
  `status` = `Null`. That's intentional, not a gap.
- `LearnClient.display_rates()` runs at start and `fetch_rates()` at the end, to
  report how many requests the run consumed. The rate headers come back even on
  a 404, so `fetch_rates` deliberately doesn't require `response.ok`.
- `fetch_all_records` picks the cheaper axis per course: per meeting costs
  `meetings * ceil(students/limit)`, per student costs
  `students * ceil(meetings/limit)`. Both endpoints return the same
  `AttendanceRecord` shape, so callers can't tell which was used.
- Request counts are dominated by the attendance fetch (~94% on a typical
  course). Trimming fields saves payload, not requests — the argument for
  `--minimal` is output volume (~3x smaller rows), not quota.
- `/meetings/downloadUrl` looks like a bulk escape hatch but is not usable: it
  returns a legacy `/webapps/` servlet URL that 404s with a REST bearer token.
- Daily quota is not a design constraint — a production integration can have its
  rate limit raised. The binding constraints are wall-clock time and output
  size. Measured at 40ms/request with keep-alive, 1000 typical courses is
  ~64,000 requests and ~43 minutes sequential. The same batch without connection
  reuse is ~13 hours, which is why the shared `requests.Session` matters more
  than any other optimization here.
- Output volume is the real ceiling: 1000 typical courses is ~6M rows / ~1.3GB
  in full mode, well past Excel's 1,048,576-row limit. Rows stream to disk per
  row; keep record accumulation scoped per course (36MB worst case) rather than
  per batch.

Config is read before the batch folder is created, so a bad invocation reports
an error without leaving an empty timestamped folder behind.
`setup_console_logging()` runs first so those early errors still use the normal
`[timestamp]|LEVEL|message` format; `setup_logging(batchId)` adds the file
handler once the folder exists.

## Known rough edges

Pre-existing; don't silently "fix" them as a side effect of other work, but
they're fair game if asked:

- Output is `|`-delimited but named `.csv`. `INSTALL.md` documents that, so
  don't change the delimiter without flagging it.
- The `TODO` at the top of the script (course with dates and no attendance
  records at all) is still open.

## Branding

The Anthology → Blackboard rename is complete: README, LICENSE, the script
header and warranty text, the author contact, and the setup guide. Keep new
text on **Blackboard**,
`developer.blackboard.com` and `docs.blackboard.com`. The old
`docs.anthology.com` deep links 404; the `docs.blackboard.com/docs/blackboard/…`
equivalents resolve.
