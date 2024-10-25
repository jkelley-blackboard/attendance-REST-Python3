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
- GET /learn/api/public/v1/oauth2/token
- GET /learn/api/public/v1/users/_1_1 **only to check rate values
- GET /learn/api/public/v3/courses/{courseId}  ***not yet
- GET /learn/api/public/v1/courses/{courseId}/users
- GET /learn/api/public/v1/courses/{courseId}/meetings
- GET /learn/api/public/v1/courses/{courseId}/meetings/{meetingId]/users

The integration user needs a system role with the following privliges:

- Administrator Panel (Users) > Users > Edit > View Course Enrollments- 
- Course/Organization Control Panel (Tools) > Attendance > View Attendce
- Administrator Panel (Users) > Users
  (Dev documentation missing note for membership endpoint. Need this to get user.externalId)

The code includes classes and methods to

- authenticate and reauthenticate when the session is expired or is about to timeout
- lookup rate limit, remaining requests and how many were used by the module
- log to console and file with error, info and debug levels
