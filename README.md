# attendance-REST-Python3
This is a single python module which will generate an export of attendance data for a provided list of courses

usage = batch_attendance3.py properties_file.ini list_of_courses.csv

The outputs are a log file and a csv of attendance records with a timestamp.
The expected data fields are:

header = [
    'courseId', 'courseName', 'courseExtKey', 'course_pk1',
    'meeting_id', 'meeting_start', 'meeting_end', 'status',
    'user_pk1', 'username', 'external_user_key', 'student_id', 'firstname', 'lastname',
    'childCourseId', 'childCourseName', 'childExtKey','child_pk1'
]

The code uses the following non-standard Python Modules
I have included a Setup.cmd file which installs them on windows using PIP
- datetime
- argparse
- configparser
- logging
- requests
- typing

The code uses the following Blackboard endpoints:
See https://developer.anthology.com/portal/displayApi 
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
