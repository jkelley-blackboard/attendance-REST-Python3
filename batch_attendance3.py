"""
py 3.11
generate delimted file of attendance records from a list of course_ids
usage: batch_attendance3.py list_of_courses.csv [--env-file PATH]
by Jeff.Kelley@blackboard.com   Updated October 2024

BLACKBOARD MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY OF THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT. BLACKBOARD SHALL NOT BE LIABLE FOR ANY
DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.

MAIN LOGIC:
Authenticate to get token
Itterate through the list of cousres
 - Create a list of all the students
 - Create a list of all the meetings
 - Itterate through meetings
    - record the status if attendance record exists
    - record Null if there is a meeting, but no attendance record for a student

TODO:
 - handle a course with dates and no attendance records at all

"""

import os
import datetime
import time
import sys
import csv
import argparse
import logging
import requests
import re
from typing import List
from functools import wraps

try:
    from dotenv import load_dotenv
except ImportError:
    logging.error('Missing module python-dotenv. '
                  'Run: pip install -r attendance_requirements.txt')
    sys.exit(1)


#########################
## CONFIGURATION ##

# Searched in order when --env-file is not supplied. internal/ is gitignored,
# which is where real credentials belong.
ENV_FILE_LOCATIONS = ['.env', os.path.join('internal', '.env')]


def find_env_file(explicitPath):
    """Returns the .env path to load, or exits if none can be found."""
    if explicitPath:
        if not os.path.isfile(explicitPath):
            logging.error(f'No .env file at {explicitPath}')
            sys.exit(1)
        return explicitPath

    for candidate in ENV_FILE_LOCATIONS:
        if os.path.isfile(candidate):
            return candidate

    logging.error(f'No .env file found. Looked for: {", ".join(ENV_FILE_LOCATIONS)}. '
                  f'Copy .env.example to .env and fill it in, or pass --env-file.')
    sys.exit(1)


def env_int(name, default):
    """Reads an integer setting, naming the variable if it isn't a number."""
    raw = os.environ.get(name, '').strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f'{name} must be a whole number, got {raw!r}')


def parse_arguments_and_config():
    """Validates and sets the input arguments and .env config values."""
    parser = argparse.ArgumentParser(description='Batch attendance export from Blackboard Learn')
    parser.add_argument("INPUT_FILE", help="List of Learn Course IDs")
    parser.add_argument("--env-file", dest="ENV_FILE", default=None,
                        help="Path to the .env file (default: ./.env then ./internal/.env)")

    args = parser.parse_args()

    # Load the .env file into the process environment. Real environment
    # variables win, so a scheduler can override without editing the file.
    envFile = find_env_file(args.ENV_FILE)
    load_dotenv(envFile, override=False)

    # Setting and validating variables from the environment
    try:
        KEY = os.environ.get('BB_KEY', '').strip()
        SECRET = os.environ.get('BB_SECRET', '').strip()
        HOST = os.environ.get('BB_HOST', '').strip()
        RESULTLIMIT = env_int('BB_RESULT_LIMIT', 100)
        SESSIONBUFFER = env_int('BB_SESSION_BUFFER', 30)

        missing = [n for n, v in (('BB_KEY', KEY), ('BB_SECRET', SECRET), ('BB_HOST', HOST)) if not v]
        if missing:
            raise ValueError(f'Missing required value(s): {", ".join(missing)}')

        # HOST is a bare hostname in the file; tolerate a pasted scheme or trailing slash
        HOST = re.sub(r'^https?://', '', HOST).rstrip('/')

        for name, value in (('BB_KEY', KEY), ('BB_SECRET', SECRET), ('BB_HOST', HOST)):
            if re.search(r'\s', value):
                raise ValueError(f'{name} contains whitespace')

        if len(SECRET) < 32:
            raise ValueError(f'BB_SECRET is {len(SECRET)} characters, expected at least 32')
        if RESULTLIMIT < 1 or RESULTLIMIT > 100:
            raise ValueError(f'BB_RESULT_LIMIT must be 1-100, got {RESULTLIMIT}')
        if SESSIONBUFFER < 1:
            raise ValueError(f'BB_SESSION_BUFFER must be positive, got {SESSIONBUFFER}')

        HOST = 'https://' + HOST

    except ValueError as e:
        logging.error(f'Configuration validation failed. Check {envFile}: {e}')
        sys.exit(1)

    return {
        'envFile': envFile,
        'inFile': args.INPUT_FILE,
        'KEY': KEY,
        'SECRET': SECRET,
        'HOST': HOST,
        'RESULTLIMIT': RESULTLIMIT,
        'SESSIONBUFFER': SESSIONBUFFER
    }


#########################
LOG_FORMATTER = logging.Formatter('[%(asctime)s]|%(levelname)s|%(message)s',
                                  datefmt='%Y-%m-%d %H:%M:%S')


def setup_console_logging():
    """Console logging only. Called before the config is read so that a bad
    invocation reports in the normal format without creating a batch folder."""
    logger = logging.getLogger()  # Get the root logger
    logger.setLevel(logging.INFO)  # Set log level to INFO

    # Create a console handler for logging to stdout
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(LOG_FORMATTER)

    if not logger.handlers:
        logger.addHandler(console_handler)


def setup_logging(batchId):
    """Adds the batch log file alongside the console handler."""
    logger = logging.getLogger()

    # Create a file handler for logging to a file
    logfile = os.path.join(batchId, f'attendance_logfile_{batchId}.log')
    file_handler = logging.FileHandler(logfile, 'a')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(LOG_FORMATTER)

    logger.addHandler(file_handler)


#########################
class Authenticator:
    """Handles authentication and checks if the auth token is about to expire."""
    AUTH_URL = '/learn/api/public/v1/oauth2/token'

    def __init__(self, host, key, secret):
        self.host = host
        self.key = key
        self.secret = secret
        self.token = None
        self.expiresAt = None
        self.authStr = None
        self.authenticate()

    def authenticate(self):
        """Perform the authentication and retrieve the token."""
        auth_data = {'grant_type': 'client_credentials'}
        auth_url = self.host + self.AUTH_URL

        try:
            response = requests.post(auth_url, data=auth_data, auth=(self.key, self.secret))
            response.raise_for_status()  # Raise an HTTPError for bad responses
            self.parse_response(response.json())

        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to authenticate: {e}")
            sys.exit(1)  # Exit on failure

    def parse_response(self, response_json):
        """Parse the authentication response."""
        self.token = response_json.get('access_token')
        expires_in = response_json.get('expires_in')

        if not self.token or not expires_in:
            logging.error(f'Missing access token or expiration time in the response.')
            sys.exit(1)

        m, s = divmod(expires_in, 60)  # Convert to minutes and seconds
        self.expiresAt = datetime.datetime.now() + datetime.timedelta(seconds=s, minutes=m)
        self.authStr = f'Bearer {self.token}'
        logging.info(f"Auth token expires in {m} minutes and {s} seconds. (Expires at: {self.expiresAt})")

    def is_token_expired(self):
        """Check if the token is expired."""
        return datetime.datetime.now() >= self.expiresAt

    def is_token_nearly_expired(self, buffer_seconds):
        """Returns true if the auth token is about to expire."""
        time_left = (self.expiresAt - datetime.datetime.now()).total_seconds()
        if time_left < buffer_seconds:
            logging.info(f'PLEASE WAIT: Token almost expired, retrieving new token in {buffer_seconds} seconds.')
            time.sleep(buffer_seconds + 1)
            return True
        return False


############################
# Decorator to count GET requests
def count_get_requests(func):
    """wraps around the get method to count each time it is called"""
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        self.get_request_count += 1
        return func(self, *args, **kwargs)
    return wrapper


############################
class LearnClient:
    """Owns the HTTP session, the auth header, paging and the request count.

    One Session for the whole batch. Without it every GET renegotiates TLS,
    which measured ~730ms per request against Learn versus ~40ms reusing the
    connection. The Authenticator is held rather than its token string so a
    mid-batch reauthentication is picked up automatically.
    """

    def __init__(self, host: str, auth: Authenticator, result_limit: int):
        self.host = host
        self.auth = auth
        self.result_limit = result_limit
        self.session = requests.Session()
        self.get_request_count = 0

    @count_get_requests
    def _get(self, url, context):
        """Single GET. Returns the response, or None after logging the failure."""
        try:
            response = self.session.get(self.host + url,
                                        headers={'Authorization': self.auth.authStr})
            response.raise_for_status()  # Raise exception for bad status codes
            return response
        except requests.exceptions.HTTPError as http_err:
            # Log any HTTP errors
            logging.error(f'{context} | {http_err}')
            return http_err.response
        except requests.exceptions.RequestException as err:
            # Log any request errors
            logging.error(f'{context} | {err}')
        return None

    def get_json(self, url, context):
        """Returns the parsed body of a single object request, or None."""
        response = self._get(url, context)
        if response is None or not response.ok:
            return None
        logging.debug(f'Retrieved {url}')
        return response.json()

    def get_paged(self, url, context):
        """Follows paging.nextPage and returns every result across all pages."""
        results: List[dict] = []
        while url:
            logging.debug(f'Fetching from URL: {self.host + url}')
            data = self.get_json(url, context)
            if not data:
                break  # Exit if there's an issue with the API response

            results.extend(data.get('results', []))

            # Check if there's a next page, otherwise set the URL to empty
            url = data.get('paging', {}).get('nextPage', '')
        return results

    def fetch_rates(self):
        """Returns the daily total and currently availble number of requests."""
        # no privliges required
        response = self._get('/learn/api/public/v3/courses/_1_1', 'rate check')
        if response is None:
            logging.error("Failed to fetch rate limit information.")
            return None, None
        # The rate headers come back even on a 404, so don't require response.ok
        logging.debug(f'Response Headers: {response.headers}')
        return (response.headers.get('X-Rate-Limit-Limit'),
                response.headers.get('X-Rate-Limit-Remaining'))

    def display_rates(self):
        """Logs the rate values and returns them."""
        rate_limit, remaining_requests = self.fetch_rates()
        if rate_limit and remaining_requests:
            logging.info(f"Rate Limit: {rate_limit}. Remaining Requests: {remaining_requests}")
        else:
            logging.error("Failed to fetch rate limit information.")
        return rate_limit, remaining_requests


############################
## RESOURCE FETCHERS ##

# to get externalId, privlige Course/Organization Control Panel (Customization) > Properties [course.configure-properties.EXECUTE]
COURSE_FIELDS = 'id,uuid,externalId,courseId,name'

# Likely allowed by having both privliges:
#  User management by Web Services [system.useradmin.generic.VIEW]
#  Administrator Panel (Courses) > Courses [system.course.VIEW]
MEMBER_FIELDS = 'childCourseId,user.id,user.externalId,user.userName,user.studentId,user.name.given,user.name.family'


def course_ident(course_ident_raw: str) -> str:
    """A pk1 (_xxxxxx_1) is used as-is, anything else is a batch UID."""
    if re.match(r'^_\d+_1$', course_ident_raw):
        return course_ident_raw
    return f'courseId:{course_ident_raw}'


def fetch_course(client: LearnClient, course_ident_raw: str):
    """Gets extended attributes for select courseId or id."""
    ident = course_ident(course_ident_raw)
    return client.get_json(f'/learn/api/public/v3/courses/{ident}?fields={COURSE_FIELDS}', ident)


def fetch_meetings(client: LearnClient, courseId: str):
    """Returns every attendance meeting for a select course."""
    #privlige Course/Organization Control Panel (Tools) > Attendance > View Attendance [course.attendance.VIEW]
    url = (f'/learn/api/public/v1/courses/courseId:{courseId}'
           f'/meetings?limit={client.result_limit}')
    return client.get_paged(url, courseId)


def fetch_records(client: LearnClient, course_pk1: str, meeting_id: str):
    """Returns list of attendance records for a select course/meeting."""
    #privlige Course/Organization Control Panel (Tools) > Attendance > View Attendance [course.attendance.VIEW]
    url = (f'/learn/api/public/v1/courses/{course_pk1}'
           f'/meetings/{meeting_id}/users?limit={client.result_limit}')
    return client.get_paged(url, course_pk1)


def fetch_members(client: LearnClient, courseId: str):
    """Returns students enrolled in a course, with child course info for merges."""
    url = (f'/learn/api/public/v1/courses/courseId:{courseId}'
           f'/users?role=Student&expand=user&fields={MEMBER_FIELDS}&limit={client.result_limit}')
    members = client.get_paged(url, courseId)

    # Look up each distinct child course once, then attach it to its members.
    children = {}
    for member in members:
        childId = member.get('childCourseId')
        if not childId:
            continue
        if childId not in children:
            newChild = fetch_course(client, childId)
            logging.debug(f'Adding {newChild} to list for {courseId}')
            children[childId] = newChild
        if children[childId]:
            member['childCourse'] = children[childId]
            logging.debug(f'Added child course record to member:{member}')
    return members


############################
## ROW ASSEMBLY ##

#Sets the keys for attendanceRow below  - determines file order too
HEADER = [
    'courseId', 'courseName', 'courseExtKey', 'course_pk1',
    'meeting_id', 'meeting_start', 'meeting_end', 'status',
    'user_pk1', 'username', 'external_user_key', 'student_id', 'firstname', 'lastname',
    'childCourseId', 'childCourseName', 'childExtKey','child_pk1'
]


def build_rows(thisId, thisCourse, meetings_list, members_list, allRecords):
    """Yields one row per meeting/student pair, 'Null' where there is no record."""
    # Index the records by (meeting, user) so the pairing below is a dict hit
    # rather than a scan of allRecords for every student/meeting combination.
    recordIndex = {
        (str(rec['meetingId']), str(rec['userId'])): rec
        for rec in allRecords
    }

    for meeting in meetings_list:
        meeting_id = str(meeting['id'])

        for member in members_list:
            user = member['user']
            user_id = str(user['id'])
            logging.debug(f' meeting = {meeting_id} and user = {user_id}')

            # Find the attendance record for this meeting/student pair
            attendance_record = recordIndex.get((meeting_id, user_id))

            # Log the result
            if attendance_record:
                logging.debug(f"Match found: {attendance_record}")
                status = attendance_record['status']
            else:
                logging.debug("No match found")
                status = 'Null'

            # Declare the attendanceRow match to HEADER keys above
            yield {
                'courseId': thisId,
                'courseName': thisCourse['name'],
                'courseExtKey': thisCourse['externalId'],
                'course_pk1': thisCourse['id'],
                'meeting_id': meeting_id,
                'meeting_start': meeting['start'],
                'meeting_end': meeting['end'],
                'status': status,
                'user_pk1': user['id'],
                'username': user['userName'],
                'external_user_key': user['externalId'],
                'student_id': user.get('studentId', ''),
                'firstname': user['name']['given'],
                'lastname': user['name']['family'],
                'childCourseId': member.get('childCourse', {}).get('courseId', ''),
                'childCourseName': member.get('childCourse', {}).get('name', ''),
                'childExtKey': member.get('childCourse', {}).get('externalId', ''),
                'child_pk1': member.get('childCourseId', '')
            }


def process_course(client, thisId, sessionBuffer):
    """Fetches everything for one course. Returns (course, meetings, members, records)
    or None when the course should be skipped."""
    if client.auth.is_token_nearly_expired(sessionBuffer):
        client.auth.authenticate()

    logging.debug(f'')
    logging.debug(f'---------------------------------')
    logging.debug(f'{thisId} > Start this course')

    # Look up course or skip if not found.
    thisCourse = fetch_course(client, thisId)
    if not thisCourse:
        logging.info(f'{thisId} > No course found.')
        return None

    # Fetch a list of meetings or skip if none
    meetings_list = fetch_meetings(client, thisId)
    meetingCount = len(meetings_list)
    if meetingCount == 0:
        logging.info(f'{thisId} | No meetings.')
        return None

    # Fetch a list of members (students) or skip if none
    members_list = fetch_members(client, thisId)
    memberCount = len(members_list)
    if memberCount == 0:
        logging.info(f'{thisId} | No members.')
        return None

    # Fetch attendance records for all meetings
    allRecords = []
    for meeting in meetings_list:
        """Itterate over each meeting in the course."""
        #We use the course id value in the _12345_1 format here. See note in fetch_records
        allRecords.extend(fetch_records(client, meeting['courseId'], str(meeting['id'])))

    recordCount = len(allRecords)
    if recordCount == 0:
        logging.info(f'{thisId} | No attendance records.')
    else:
        logging.debug(f'allRecords:{allRecords}')
        logging.info(f'{thisId} | {memberCount} students, {meetingCount} meetings, and {recordCount} attendance records.')

    return thisCourse, meetings_list, members_list, allRecords


#################################
def main():
    # let's go!
    batchStart = datetime.datetime.now()
    batchId = str(batchStart.strftime("%Y%m%d-%H%M%S"))
    setup_console_logging()

    # Get config file data and populate variables before anything is written to
    # disk, so a bad invocation doesn't leave an empty batch folder behind.
    config_data = parse_arguments_and_config()

    inFile = config_data['inFile']
    KEY = config_data['KEY']
    SECRET = config_data['SECRET']
    HOST = config_data['HOST']
    RESULTLIMIT = config_data['RESULTLIMIT']
    SESSIONBUFFER = config_data['SESSIONBUFFER']

    os.makedirs(batchId)
    setup_logging(batchId)
    logging.info(f'Starting Batch Attendance ID = ' + batchId)

    # Authenticate
    thisAuth = Authenticator(HOST, KEY, SECRET)
    client = LearnClient(HOST, thisAuth, RESULTLIMIT)

    #Check Rate Limits
    rate_limit, start_remaining_requests = client.display_rates()

    outFile = os.path.join(batchId, f'attendance_output_{batchId}.csv')
    rowCounter = 0

    # start processing courses from the list
    with open(inFile) as inputFile, open(outFile, 'w', newline='') as outputFile:
        outputWriter = csv.DictWriter(outputFile, delimiter='|', fieldnames=HEADER)
        outputWriter.writeheader()

        for line in inputFile:
            """itterate over the courseIds in the input file"""
            thisId = line.rstrip()
            if not thisId:
                continue

            result = process_course(client, thisId, SESSIONBUFFER)
            if not result:
                continue
            thisCourse, meetings_list, members_list, allRecords = result

            # Combine data and write to outFile
            for attendanceRow in build_rows(thisId, thisCourse, meetings_list,
                                            members_list, allRecords):
                outputWriter.writerow(attendanceRow)
                rowCounter += 1

    #Calculate requests made
    rate_limit, end_remaining_requests = client.fetch_rates()
    if start_remaining_requests and end_remaining_requests:
        req_diff = int(start_remaining_requests) - int(end_remaining_requests)
        logging.info(f'There are {end_remaining_requests} remaining today. That is a difference of {req_diff}.')
    logging.info(f'Total GET requests made: {client.get_request_count}')

    # lets close up shop
    logging.info(f'Closing batch ' + batchId + ' with ' + str(rowCounter) + ' records.')


if __name__ == '__main__':
    main()
