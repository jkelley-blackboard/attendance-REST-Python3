"""
py 3.11
generate delimted file of attendance records from a list of course_ids
by Jeff.Kelley@anthology.com   Updated October 2024

ANTHOLOGY MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY OF THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT. ANTHOLOGY SHALL NOT BE LIABLE FOR ANY
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
import json
import datetime
import time
import sys
import csv
import argparse
import configparser
import logging
import requests
import re
from typing import List
from functools import wraps

#########################
def parse_arguments_and_config():
    """Validates and sets the input arguments and config property values."""
    parser = argparse.ArgumentParser(description='Properties, Input file and Output file')
    parser.add_argument("PROPERTIES_FILE", help="The properties file")
    parser.add_argument("INPUT_FILE", help="List of Learn Course IDs")

    args = parser.parse_args()

    # Load the properties file into the configparser
    propFile = args.PROPERTIES_FILE
    config = configparser.ConfigParser()
    config.read(propFile)

    # Setting and validating variables from properties file
    try:
        KEY = config.get('properties', 'KEY')
        SECRET = config.get('properties', 'SECRET')
        HOST = 'https://' + config.get('properties', 'HOST')
        RESULTLIMIT = int(config.get('properties', 'RESULTLIMIT'))
        SESSIONBUFFER = int(config.get('properties', 'SESSIONBUFFER'))

        if (' ' in [KEY, SECRET, HOST, RESULTLIMIT]) or (len(SECRET) < 32) \
                or (RESULTLIMIT < 1 or RESULTLIMIT > 100) or ('https' not in HOST):
            raise ValueError("Invalid property values.")
    except Exception as e:
        logging.error(f'Property value validation failed. Check {propFile}: {e}')
        sys.exit(1)

    return {
        'propFile': propFile,
        'inFile': args.INPUT_FILE,
        'KEY': KEY,
        'SECRET': SECRET,
        'HOST': HOST,
        'RESULTLIMIT': RESULTLIMIT,
        'SESSIONBUFFER':SESSIONBUFFER
    }

#########################
def setup_logging(batchId):
    """Establishes the logging infrastructure."""
    logger = logging.getLogger()  # Get the root logger
    logger.setLevel(logging.INFO)  # Set log level to INFO
    
    # Create a file handler for logging to a file
    logfile = os.path.join(batchId, f'attendance_logfile_{batchId}.log')
    file_handler = logging.FileHandler(logfile, 'a')
    file_handler.setLevel(logging.INFO)

    # Create a console handler for logging to stdout
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)

    # Create a formatter and set it for both handlers
    formatter = logging.Formatter('[%(asctime)s]|%(levelname)s|%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add the handlers to the logger if they don't already exist
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)


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
    """wraps around the requests.get function to count each time it is called"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        wrapper.get_request_count += 1
        return func(*args, **kwargs)
    wrapper.get_request_count = 0
    return wrapper

# Apply the decorator to the requests.get function
@count_get_requests
def requests_get(url, **kwargs):
    return requests.get(url, **kwargs)


############################
class CheckRates:
    """Logs and returns the daily total and currently availble number of requests."""
    def __init__(self, host: str, auth_token: str):
        self.host = host
        self.auth_token = auth_token
        
    def _build_url(self):
        # no privliges required
        return '/learn/api/public/v3/courses/_1_1'   
       
    def _get_response_header(self, url):
        try: 
            response = requests_get(self.host + url, headers={'Authorization': self.auth_token})
            response.raise_for_status()
            logging.debug(f'Response Headers: {response.headers}')
            return response.headers
        except requests.exceptions.RequestException as err:
            logging.error(f'Error occurred while checking rates: {err}')
        return None
        
    def fetch_rates(self):
        headers = self._get_response_header(self._build_url())
        if headers:
            rate_limit = headers.get('X-Rate-Limit-Limit')
            remaining_requests = headers.get('X-Rate-Limit-Remaining')
            retry_after = headers.get('Retry-After')
            return rate_limit, remaining_requests
        return None, None

    def display_rates(self):
        rate_limit, remaining_requests = self.fetch_rates()
        if rate_limit and remaining_requests:
            logging.info(f"Rate Limit: {rate_limit}. Remaining Requests: {remaining_requests}")
            return rate_limit, remaining_requests
        else:
            logging.error("Failed to fetch rate limit information.")
            return None, None


############################
class GetCourseData:
    """Gets extended attributes for select courseId or id"""
    def __init__(self, course_ident: str, host: str, auth_token: str):
        self.host = host  # API host URL
        self.auth_token = auth_token  # Authentication token
        # Regular expression to match the format _xxxxxx_1 where xxxxxx are all numbers
        pattern = r'^_\d+_1$'
        if re.match(pattern, course_ident):
            self.course_ident = course_ident
        else:
            self.course_ident = f'courseId:{course_ident}'
        self.course_data = None

    def _build_url(self):
        # Build the API URL for fetching course fields
        fields = 'id,uuid,externalId,courseId,name'
        # to get externalId, privlige Course/Organization Control Panel (Customization) > Properties [course.configure-properties.EXECUTE]
        return f'/learn/api/public/v3/courses/{self.course_ident}?fields={fields}'
     
    def _get_course_data(self, url):
        # Fetch course data from the API
        try:
            response = requests_get(self.host + url, headers={'Authorization': self.auth_token})
            response.raise_for_status()  # Raise exception for bad status codes
            logging.debug(f'Retrieved course details{response.json()}')
            return response.json()  # Return the JSON response as a dictionary
        except requests.exceptions.HTTPError as http_err:
            # Log any HTTP errors
            logging.error(f'{self.course_ident} | {http_err}')
        except requests.exceptions.RequestException as err:
            # Log any request errors
            logging.error(f'{self.course_ident} | {err}')
        return None
    
    def fetch_course(self):
        url = self._build_url()
        self.course_data = self._get_course_data(url)
        return self.course_data
    
    def get_course(self):
        # Return the select fields
        return self.course_data


############################
class GetMembers:
    """Returns a list of students enrolled in a course with user attributes and child course info for merges. """
    def __init__(self, courseId: str, host: str, auth_token: str, result_limit: int):
        self.courseId = courseId  # Store course ID
        self.host = host  # API host URL
        self.auth_token = auth_token  # Authentication token
        self.result_limit = result_limit  # Limit for API results
        self.members = []  # Initialize members list
    
    def _build_url(self):
        # Build the API URL for fetching course members with the role "Student"
        role = 'Student'
        fields = 'childCourseId,user.id,user.externalId,user.userName,user.studentId,user.name.given,user.name.family'
        # Likely allowed by having both privliges:
        #  User management by Web Services [system.useradmin.generic.VIEW]
        #  Administrator Panel (Courses) > Courses [system.course.VIEW]
        return f'/learn/api/public/v1/courses/courseId:{self.courseId}/users?role={role}&expand=user&fields={fields}&limit={self.result_limit}'
    
    def _get_members_data(self, url):
        # Fetch members data from the API endpoint
        try:
            response = requests_get(self.host + url, headers={'Authorization': self.auth_token})
            response.raise_for_status()  # Raise exception for bad status codes
            return response.json()  # Return the JSON response as a dictionary
        except requests.exceptions.HTTPError as http_err:
            # Log any HTTP errors
            logging.error(f'{self.courseId} | {http_err}')
        except requests.exceptions.RequestException as err:
            # Log any request errors
            logging.error(f'{self.courseId} | {err}')
        return None
    
    def fetch_members(self):
        # Main function to retrieve members for a given course
        url = self._build_url()  # Build the initial URL
        while url:  # Loop to handle paginated results
            logging.debug(f'Fetching members from URL: {self.host + url}')
            
            members_data = self._get_members_data(url)  # Get members data from API
            if not members_data:
                break  # Exit if there's an issue with the API response
            
            # Add the current page of results to the members list
            self.members.extend(members_data.get("results", []))
            
            # Check if there's a next page, otherwise set the URL to empty
            url = members_data.get('paging', {}).get('nextPage', '')
            
    def get_members_with_children(self):
        """If member has childCourseId add those details"""
        children = [] #initiate list of child courses
        for member in self.members:
            if 'childCourseId' in member:
                if not any(child.get('id') == member.get('childCourseId') for child in children):  #child not in list
                    ##look up and add to list
                    course_lookup = GetCourseData(member['childCourseId'], self.host, self.auth_token)
                    course_lookup.fetch_course()
                    newChild = course_lookup.get_course()
                    logging.debug(f'Adding {newChild} to list for {self.courseId}')
                    children.append(newChild)
            logging.debug(f'List of children{children}')
            for child in children:
                if child['id'] == member['childCourseId']:
                    member['childCourse'] = child
                    logging.debug(f'Added child course record to member:{member}')
        return self.members
            
    
    def get_members_list(self):
        # Return list of members - without child course details
        logging.debug(f'members:{self.members}')
        return self.members

######################
class GetMeetings:
    """Returns a list of meeetings for a given course."""
    def __init__(self, courseId: str, host: str, auth_token: str, result_limit: int):
        self.courseId = courseId
        self.host = host
        self.auth_token = auth_token
        self.result_limit = result_limit
        self.meetings = []  # Initialize an empty list for meetings
    
    def _build_url(self):
        root_course_url = f'/learn/api/public/v1/courses/courseId:{self.courseId}'
        #privlige Course/Organization Control Panel (Tools) > Attendance > View Attendance [course.attendance.VIEW]
        return f'{root_course_url}/meetings?limit={self.result_limit}'
    
    def _get_meetings(self, url):
        # Fetch meeting data from the API endpoint
        try:
            response = requests_get(self.host + url, headers={'Authorization': self.auth_token})
            response.raise_for_status()  # Raise exception for bad status codes
            return response.json()  # Return the JSON response as a dictionary
        except requests.exceptions.HTTPError as http_err:
            # Log any HTTP errors
            logging.error(f'{self.courseId} | {http_err}')
        except requests.exceptions.RequestException as err:
            # Log any request errors
            logging.error(f'{self.courseId} | {err}')
        return None

    def fetch_meetings(self):
        # Main function to retrieve meetings for a given course
        url = self._build_url()  # Build the initial URL
        while url:  # Loop to handle paginated results
            logging.debug(f'Fetching meeetings from URL: {self.host + url}')
            
            meeting_data = self._get_meetings(url)  # Get meetings from API
            if not meeting_data:
                break  # Exit if there's an issue with the API response
            
            # Add the current page of results to the list
            self.meetings.extend(meeting_data.get("results", []))
            
            # Check if there's a next page, otherwise set the URL to empty
            url = meeting_data.get('paging', {}).get('nextPage', '')

    def get_meetings_list(self):
        return self.meetings

#############################
class GetRecords:
    """Returns list of attendance records for a select course/meeting."""
    def __init__(self, meeting_id: str, course_id: str, host: str, auth_token: str, result_limit: int):     
        self.this_course = course_id
        self.this_meeting = meeting_id
        self.host = host
        self.auth_token = auth_token
        self.result_limit = result_limit
        self.records: List[dict] = []  # Initialize an empty list for records

    def _build_url(self):
        #privlige Course/Organization Control Panel (Tools) > Attendance > View Attendance [course.attendance.VIEW]
        return f'/learn/api/public/v1/courses/{self.this_course}/meetings/{self.this_meeting}/users?limit={self.result_limit}'
    
    def _get_records(self, url):
        # Fetch enrollment records from the API endpoint
        try:
            response = requests_get(self.host + url, headers={'Authorization': self.auth_token})
            response.raise_for_status()  # Raise exception for bad status codes
            return response.json()  # Return the JSON response as a dictionary
        except requests.exceptions.HTTPError as http_err:
            # Log any HTTP errors
            logging.error(f'{self.this_course} | {http_err}')
        except requests.exceptions.RequestException as err:
            # Log any request errors
            logging.error(f'{self.this_course} | {err}')
        return None    

    def fetch_records(self):
        # Main function to retrieve attendance records for course/meeting pair
        url = self._build_url()  # Build the initial URL
        while url:  # Loop to handle paginated results
            logging.debug(f'Fetching records from URL: {self.host + url}')
            
            records_data = self._get_records(url)
            if not records_data:
                break  # Exit if there's an issue with the API response
            
            # Add the current page of results to the list
            self.records.extend(records_data.get("results", []))
            
            # Check if there's a next page, otherwise set the URL to empty
            url = records_data.get('paging', {}).get('nextPage', '')

    def get_records_list(self):
        return self.records


#################################
## START THE SCRIPT ###

# let's go!
batchStart = datetime.datetime.now()
batchId = str(batchStart.strftime("%Y%m%d-%H%M%S"))
os.makedirs(batchId)

# Call the setup_logging function
setup_logging(batchId)
logging.info(f'Starting Batch Attendance ID = ' + batchId)

# Get config file data and populate variables
config_data = parse_arguments_and_config()

inFile = config_data['inFile']
KEY = config_data['KEY']
SECRET = config_data['SECRET']
HOST = config_data['HOST']
RESULTLIMIT = config_data['RESULTLIMIT']
SESSIONBUFFER = config_data['SESSIONBUFFER']

# Authenticate
thisAuth = Authenticator(HOST, KEY, SECRET)

#Check Rate Limits
rate_checker = CheckRates(HOST, thisAuth.authStr)
rate_checker.display_rates()  #logs values
rate_limit, start_remaining_requests = rate_checker.fetch_rates()

#file readiness
inputFile = open(inFile)

#Sets the keys for attendanceRow below  - determines file order too
header = [
    'courseId', 'courseName', 'courseExtKey', 'course_pk1',
    'meeting_id', 'meeting_start', 'meeting_end', 'status',
    'user_pk1', 'username', 'external_user_key', 'student_id', 'firstname', 'lastname',
    'childCourseId', 'childCourseName', 'childExtKey','child_pk1'
]
outFile = os.path.join(batchId, f'attendance_output_{batchId}.csv')
outputFile = open(outFile, 'w', newline='')
outputWriter = csv.DictWriter(outputFile, delimiter='|', fieldnames = header)
outputWriter.writeheader()

# initiate row count
rowCounter = 0


# start processing courses from the list 
for line in inputFile:
    """itterate over the courseIds in the input file"""
    
    if thisAuth.is_token_nearly_expired(SESSIONBUFFER):
        thisAuth.authenticate()
    
    thisId = line.rstrip()
    logging.debug(f'')
    logging.debug(f'---------------------------------')
    logging.debug(f'{thisId} > Start this course')
    
    # Look up course or skip if not found.
    lookup_this_course = GetCourseData(thisId, HOST, thisAuth.authStr)
    lookup_this_course.fetch_course()
    thisCourse = lookup_this_course.get_course()
    if not thisCourse:
        logging.info(f'{thisId} > No course found.')
        continue

    # Fetch a list of meetings or skip if none
    get_meetings = GetMeetings(thisId, HOST, thisAuth.authStr, RESULTLIMIT)
    get_meetings.fetch_meetings()
    meetings_list = get_meetings.get_meetings_list()
    meetingCount = len(meetings_list)
    if meetingCount == 0: 
        logging.info(f'{thisId} | No meetings.')
        continue

    # Fetch a list of members (students) or skip if none
    get_members = GetMembers(thisId, HOST, thisAuth.authStr, RESULTLIMIT)
    get_members.fetch_members()
    members_list = get_members.get_members_with_children()
    memberCount = len(members_list)
    if memberCount == 0: 
        logging.info(f'{thisId} | No members.')
        continue

    # Fetch attendance records for all meetings
    allRecords = []  # Initialize list
    for meeting in meetings_list:
        """Itterate over each meeting in the course."""
        attendance_fetcher = GetRecords(str(meeting['id']), meeting['courseId'], HOST, thisAuth.authStr, RESULTLIMIT)
        #We use the course id value in the _12345_1 format here. See note in GetRecords
        attendance_fetcher.fetch_records()
        records_list = attendance_fetcher.get_records_list()
        allRecords.extend(records_list)
    recordCount = len(allRecords)
    if recordCount == 0: 
        logging.info(f'{thisId} | No attendance records.')
    else:
        logging.debug(f'allRecords:{allRecords}')
        logging.info(f'{thisId} | {memberCount} students, {meetingCount} meetings, and {recordCount} attendance records.')

    # Combine data and write to outFile
    for meeting in meetings_list:
        meeting_id = str(meeting['id'])
        meeting_start = meeting['start']
        meeting_end = meeting['end']
        
        for member in members_list:
            user = member['user']
            user_id = str(user['id'])
            logging.debug(f' meeting = {meeting_id} and user = {user_id}')
            
            # Find the attendance record using a generator expression with next
            attendance_record = next(
                (rec for rec in allRecords if str(rec['userId']) == user_id and str(rec['meetingId']) == meeting_id),
                None
            )

            # Log the result
            if attendance_record:
                logging.debug(f"Match found: {attendance_record}")
                status = attendance_record['status']
            else:
                logging.debug("No match found")
                status = 'Null'

            # Declare the attendanceRow match to headers = keys above
            attendanceRow = {
                'courseId': thisId,
                'courseName':thisCourse['name'],
                'courseExtKey': thisCourse['externalId'],
                'course_pk1': thisCourse['id'],
                'meeting_id': str(meeting['id']),
                'meeting_start': meeting['start'],
                'meeting_end': meeting['end'],
                'status': status,
                'user_pk1': member['user']['id'],
                'username': member['user']['userName'],
                'external_user_key': member['user']['externalId'],
                'student_id': member['user'].get('studentId', ''),
                'firstname': member['user']['name']['given'],
                'lastname': member['user']['name']['family'],
                'childCourseId': member.get('childCourse', {}).get('courseId', ''),
                'childCourseName': member.get('childCourse', {}).get('name', ''),
                'childExtKey': member.get('childCourse', {}).get('externalId', ''),
                'child_pk1': member.get('childCourseId','')
            }

            # Write the row to the output file
            outputWriter.writerow(attendanceRow)
            rowCounter += 1


#Calculate requests made
rate_checker = CheckRates(HOST, thisAuth.authStr)
rate_limit, end_remaining_requests = rate_checker.fetch_rates()
req_diff = int(start_remaining_requests) - int(end_remaining_requests)
logging.info(f'There are {end_remaining_requests} remaining today. That is a difference of {req_diff}.')
logging.info(f'Total GET requests made: {requests_get.get_request_count}')

# lets close up shop
outputFile.close()
inputFile.close()
logging.info(f'Closing batch ' + batchId + ' with ' + str(rowCounter) + ' records.')
