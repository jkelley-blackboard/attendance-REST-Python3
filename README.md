# attendance-REST-Python3

A single Python module that exports Blackboard Learn attendance data for a list
of courses. One row per student/meeting pair, pipe-delimited, with a timestamped
log alongside it.

**New here? Start with [INSTALL.md](INSTALL.md)** — registering the developer
portal application, creating the Blackboard system role and REST integration,
setting up the local Python environment, and a troubleshooting table.

---

## Requirements

- Python 3.11 or newer
- `requests` and `python-dotenv` (see [attendance_requirements.txt](attendance_requirements.txt));
  everything else the script imports is in the standard library
- A Blackboard REST integration with the privileges listed below

## Install

```
python -m venv venv_batch_attendance

venv_batch_attendance\Scripts\activate       # Windows
source venv_batch_attendance/bin/activate    # macOS / Linux

pip install -r attendance_requirements.txt
```

## Configure

Credentials come from a `.env` file:

```
copy .env.example .env
```

| Variable | Required | Default | Notes |
|---|---|---|---|
| `BB_HOST` | yes | — | Bare hostname, e.g. `mysite.blackboard.com` |
| `BB_KEY` | yes | — | Application key from developer.blackboard.com |
| `BB_SECRET` | yes | — | Application secret, 32+ characters |
| `BB_RESULT_LIMIT` | no | `100` | REST page size, 1-100 |
| `BB_SESSION_BUFFER` | no | `30` | Seconds before token expiry to reauthenticate |

The script looks for `./.env`, then `./internal/.env`. Point it elsewhere with
`--env-file`. Real environment variables take precedence over the file, so a
scheduler can supply `BB_SECRET` without it ever touching disk.

## Run

```
python batch_attendance3.py list_of_courses.csv
python batch_attendance3.py list_of_courses.csv --env-file internal/.env
```

The input file is one course ID per line, as shown in the Learn GUI — see
[sample_list_of_course_IDs.csv](sample_list_of_course_IDs.csv).

Each run creates a `YYYYMMDD-HHMMSS/` folder containing the output file and a
log.

### Export modes

| Mode | Flag | Columns | Rows |
|---|---|---|---|
| Full | *(default)* | 18 | every student × meeting, `Null` where no record |
| Minimal | `--minimal` | 8 | same rows, primary keys only |
| Records only | `--records-only` | 8 | only records that exist, no `Null` rows |

`--minimal` drops names, usernames and child course detail, keeping pk1
identifiers. Output is roughly 3x smaller, which matters on large batches.

`--records-only` additionally skips the membership request and emits only
attendance that was actually taken. It implies `--minimal`.

## Output

Pipe (`|`) delimited despite the `.csv` extension. Full mode columns:

```
courseId, courseName, courseExtKey, course_pk1,
meeting_id, meeting_start, meeting_end, status,
user_pk1, username, external_user_key, student_id, firstname, lastname,
childCourseId, childCourseName, childExtKey, child_pk1
```

Minimal and records-only modes emit:

```
courseId, course_pk1, meeting_id, meeting_start, meeting_end,
status, user_pk1, child_pk1
```

Where a meeting exists but a student has no attendance record, `status` is
written as `Null`. That padding is intentional — it distinguishes "not marked"
from "not enrolled". `--records-only` omits those rows.

## What it does

- Authenticates and reauthenticates when the token is expired or about to expire
- Reports the daily rate limit, requests remaining, and how many the run used
- Logs to console and file at error, info and debug levels
- For each course, fetches student memberships plus child course details when merged
- For each course, fetches every attendance meeting
- Fetches attendance records along whichever axis costs fewer requests
- Combines the data, writing `Null` where a meeting exists without a record

## Blackboard endpoints used

See the [Blackboard REST API reference](https://developer.blackboard.com/portal/displayApi).

```
POST /learn/api/public/v1/oauth2/token
GET  /learn/api/public/v3/courses/{courseId}
GET  /learn/api/public/v1/courses/{courseId}/users
GET  /learn/api/public/v1/courses/{courseId}/meetings
GET  /learn/api/public/v1/courses/{courseId}/meetings/{meetingId}/users
GET  /learn/api/public/v1/courses/{courseId}/meetings/users/{userId}
```

The script only issues GET requests after authenticating, so it never modifies
data.

## Required privileges

The integration user needs a system role permitting these privileges
(entitlements in brackets):

| Privilege | Entitlement |
|---|---|
| User management by Web Services | `system.useradmin.generic.VIEW` |
| Administrator Panel (Courses) > Courses | `system.course.VIEW` |
| Course/Organization Control Panel (Tools) > Attendance > View Attendance | `course.attendance.VIEW` |
| Course/Organization Control Panel (Customization) > Properties | `course.configure-properties.EXECUTE` |
| Administrator Panel (Courses) > Courses > Edit > Enrollments | `system.courseuserlist.VIEW` |

## Reference

[Install and configure video](https://drive.google.com/file/d/1KzZ8rLpDLcoAC6O3k3UGNrNDZTx7y4q6/view?usp=sharing)
— recorded against the older `properties.ini` configuration. The registration
and Blackboard-side steps are still accurate; for configuration, follow the
`.env` steps in [INSTALL.md](INSTALL.md) instead.

## License

See [LICENSE](LICENSE). Provided as-is, without warranty or support.
