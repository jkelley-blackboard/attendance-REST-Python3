# attendance-REST-Python3
This is a single python module which will generate an export of attendance data for a provided list of courses

Full setup walkthrough: **[INSTALL.md](INSTALL.md)** - registering the developer
portal application, the Blackboard system role and REST integration, the local
Python environment, and a troubleshooting table.

Install and Configure Video:  https://drive.google.com/file/d/1KzZ8rLpDLcoAC6O3k3UGNrNDZTx7y4q6/view?usp=sharing
(recorded against the older properties.ini configuration; the .env steps in
INSTALL.md supersede what the video shows for that part)

## Configuration

Credentials come from a `.env` file, not a properties ini.

    copy .env.example .env      # then fill in BB_HOST / BB_KEY / BB_SECRET

The script looks for `./.env`, then `./internal/.env`. Point it somewhere else
with `--env-file`. Real environment variables take precedence over the file, so
a scheduler can supply `BB_SECRET` without it ever touching disk.

| Variable | Required | Default | Notes |
|---|---|---|---|
| `BB_HOST` | yes | — | Bare hostname, e.g. `mysite.blackboard.com` |
| `BB_KEY` | yes | — | Application key from developer.blackboard.com |
| `BB_SECRET` | yes | — | Application secret, 32+ characters |
| `BB_RESULT_LIMIT` | no | `100` | REST page size, 1-100 |
| `BB_SESSION_BUFFER` | no | `30` | Seconds before token expiry to reauthenticate |

## Usage

    python batch_attendance3.py list_of_courses.csv
    python batch_attendance3.py list_of_courses.csv --env-file internal/.env

The outputs are a log file and a csv of attendance records with a timestamp.
The expected data fields are:

header = [
    'courseId', 'courseName', 'courseExtKey', 'course_pk1',
    'meeting_id', 'meeting_start', 'meeting_end', 'status',
    'user_pk1', 'username', 'external_user_key', 'student_id', 'firstname', 'lastname',
    'childCourseId', 'childCourseName', 'childExtKey','child_pk1'
]

The code uses the following Blackboard endpoints:
See https://developer.blackboard.com/portal/displayApi 
- POST /learn/api/public/v1/oauth2/token
- GET /learn/api/public/v3/courses/{courseId}
- GET /learn/api/public/v1/courses/{courseId}/users
- GET /learn/api/public/v1/courses/{courseId}/meetings
- GET /learn/api/public/v1/courses/{courseId}/meetings/{meetingId]/users

The integration user needs a system role with the following permitted privliges [entitlments]:
	
- User management by Web Services [system.useradmin.generic.VIEW]
- Administrator Panel (Courses) > Courses [system.course.VIEW]
- Course/Organization Control Panel (Tools) > Attendance > View Attendance [course.attendance.VIEW]
- Course/Organization Control Panel (Customization) > Properties [course.configure-properties.EXECUTE]
- Administrator Panel (Courses) > Courses > Edit > Enrollments [system.courseuserlist.VIEW]

The code includes classes and methods to

- authenticate and reauthenticate when the session is expired or is about to timeout
- lookup rate limit, remaining requests and how many were used by the module
- log to console and file with error, info and debug levels
- for a course, get the student memberships and child course info if merged
- for a course, get all the attendance meetings
- get the attendance record for each student/meeting pair
- combine the data with attendance status 'Null' where a meeting exists but the student doesn't have record

The code uses the following non-standard Python Modules.
Everything else it imports is in the Python 3.11 standard library.
I have included a requirements.txt file for easy installation.

- requests
- python-dotenv

Setup is standard Python tooling, no wrapper scripts:

    python -m venv venv_batch_attendance
    venv_batch_attendance\Scripts\activate          # Windows
    source venv_batch_attendance/bin/activate      # macOS / Linux
    pip install -r attendance_requirements.txt

