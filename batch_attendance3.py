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
 - make other course attributes (external key) and user attributes (first, last) available
 - handle a course with dates and no attendance records at all

"""

import json
import datetime
import time
import sys
import csv
import argparse
import configparser
import logging
import requests
from typing import List

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
        'RESULTLIMIT': RESULTLIMIT
    }

#########################
def setup_logging(batchId):
    """Establishes the logging infrastructure."""
    logger = logging.getLogger()  # Get the root logger
    logger.setLevel(logging.INFO)  # Set log level to INFO
    
    # Create a file handler for logging to a file
    logfilename = f'attendance_logfile_{batchId}.log'
    file_handler = logging.FileHandler(logfilename, 'a')
    file_handler.setLevel(logging.INFO)

    # Create a console handler for logging to stdout
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)

    # Create a formatter and set it for both handlers
    formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add the handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)  


#########################
class doAuthenticate:
    """Authenticates and returns auth token value."""
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
        logging.info(f"|Auth token expires in {m} minutes and {s} seconds. (Expires at: {self.expiresAt})")

    def is_token_expired(self):
        """Check if the token is expired."""
        return datetime.datetime.now() >= self.expiresAt  
    

#########################
class nearlyExpired:
  """Returns true if the auth token is about to expire."""
  def __init__(self,sessionExpireTime):
      bufferSeconds = 30  # Configurable buffer.
      self.expired = False
      self.time_left = (sessionExpireTime - datetime.datetime.now()).total_seconds()
      #self.time_left = 29  # use for testing
      if self.time_left < bufferSeconds:
            logging.info(f'|PLEASE WAIT  Token almost expired retrieving new token in ' + str(bufferSeconds) + 'seconds.')
            time.sleep(bufferSeconds + 1)
            self.expired = True

############################
class CheckRates:
    """Logs and returns the daily total and currently availble number of requests."""
    def __init__(self, host: str, auth_token: str):
        self.host = host
        self.auth_token = auth_token
        
    def _build_url(self):
        return '/learn/api/public/v1/users/_1_1'
       
    def _get_response_header(self, url):
        try: 
            response = requests.get(self.host + url, headers={'Authorization': self.auth_token})
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
            logging.info(f"|Rate Limit: {rate_limit}. Remaining Requests: {remaining_requests}")
            return rate_limit, remaining_requests
        else:
            logging.error("Failed to fetch rate limit information.")
            return None, None


############################
class GetMembers:
    """Returns a list of students enrolled in a course. """
    def __init__(self, courseId: str, host: str, auth_token: str, result_limit: int):
        self.courseId = courseId  # Store course ID
        self.host = host  # API host URL
        self.auth_token = auth_token  # Authentication token
        self.result_limit = result_limit  # Limit for API results
        self.members = []  # Initialize members list
    
    def _build_url(self):
        # Build the API URL for fetching course members with the role "Student"
        return f'/learn/api/public/v1/courses/courseId:{self.courseId}/users?role=Student&expand=user&fields=user.id,user.externalId,user.userName,user.studentId&limit={self.result_limit}'
    
    def _get_members_data(self, url):
        # Fetch members data from the API endpoint
        try:
            response = requests.get(self.host + url, headers={'Authorization': self.auth_token})
            response.raise_for_status()  # Raise exception for bad status codes
            return response.json()  # Return the JSON response as a dictionary
        except requests.exceptions.HTTPError as http_err:
            # Log any HTTP errors
            logging.error(f'HTTP error occurred while getting members for course {self.courseId}: {http_err}')
        except requests.exceptions.RequestException as err:
            # Log any request errors
            logging.error(f'Request error occurred while getting members for course {self.courseId}: {err}')
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
    
    def get_members_list(self):
        # Return the final list of members
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

    def fetch_meetings(self):
        logging.debug(f'|Getting meeting information for {self.courseId}')
        
        root_course_url = f'/learn/api/public/v1/courses/courseId:{self.courseId}'
        get_meetings_url = f'{root_course_url}/meetings?limit={self.result_limit}'
        
        while len(get_meetings_url) > 0:  # Loop to handle paging
            logging.debug(get_meetings_url)
            
            # Send the request to the API
            response = requests.get(self.host + get_meetings_url, headers={'Authorization': self.auth_token})
            logging.debug(response)
            
            if response.status_code != 200:  # Log error if response is not successful
                logging.error(f'|{self.courseId}|Error getting meetings.')
                break
            
            # Parse the JSON response and append meetings
            meetings_data = json.loads(response.text)
            self.meetings += meetings_data.get("results", [])
            
            # Check if there are more pages to fetch
            get_meetings_url = meetings_data.get("paging", {}).get("nextPage", '')

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

    def fetch_records(self):
        ## There is a "bug" in GET /learn/api/public/v1/courses/{courseId}/meetings/{meetingId}/users
        ## only the primary course ID value is acceptable   eg  _2221_1
        logging.debug(f'|Getting attendance for meeting {self.this_meeting} course {self.this_course}')
        
        get_records_url = f'/learn/api/public/v1/courses/{self.this_course}/meetings/{self.this_meeting}/users?limit={self.result_limit}'
        
        while get_records_url:  # Loop to handle paging
            logging.debug(get_records_url)
            
            try:
                response = requests.get(self.host + get_records_url, headers={'Authorization': self.auth_token}, timeout=10)
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                logging.error(f'|{self.this_course}|Error getting records: {e}')
                break
            
            records_data = response.json()
            self.records += records_data.get("results", [])
            get_records_url = records_data.get("paging", {}).get("nextPage", '')

    def get_records_list(self) -> List[dict]:
        return self.records


#################################
## START THE SCRIPT ###

# let's go!
batchStart = datetime.datetime.now()
batchId = batchStart.strftime("%Y%m%d-%H%M")

# Call the setup_logging function
setup_logging(batchId)
logging.info(f'|Starting Batch Attendance ID = ' + batchId)

# Get config file data and populate variables
config_data = parse_arguments_and_config()

inFile = config_data['inFile']
KEY = config_data['KEY']
SECRET = config_data['SECRET']
HOST = config_data['HOST']
RESULTLIMIT = config_data['RESULTLIMIT']

# Authenticate
thisAuth = doAuthenticate(HOST, KEY, SECRET)

#Check Rate Limits
rate_checker = CheckRates(HOST, thisAuth.authStr)
rate_checker.display_rates()  #logs values
rate_limit, start_remaining_requests = rate_checker.fetch_rates()

#file readiness
inputFile = open(inFile)

outFileName = f'attendance_output_{batchId}.csv'
outputFile = open(outFileName, 'w', newline='')
header = ['courseId', 'course_pk1', 'meeting_id', 'meeting_start', 'meeting_end', 'status', 'user_pk1', 'username', 'external_user_key', 'student_id']
outputWriter = csv.DictWriter(outputFile, delimiter='|', fieldnames = header)
outputWriter.writeheader()

# initiate row count
rowCounter = 0


# start processing courses from the list 
for line in inputFile:
    """itterate over the courseIds in the input file"""
    if nearlyExpired(thisAuth.expiresAt).expired:
        thisAuth = doAuthenticate()
    thisId = line.rstrip()
    logging.debug(f'|'+ thisId + '|Start this course')

    # Fetch a list of meetings or skip if none
    get_meetings = GetMeetings(thisId, HOST, thisAuth.authStr, RESULTLIMIT)
    get_meetings.fetch_meetings()
    meetings_list = get_meetings.get_meetings_list()
    meetingCount = len(meetings_list)
    if meetingCount == 0: 
        logging.info(f'|'+ thisId + '|No meetings.')
        continue

    # Fetch a list of members (students) or skip if none
    get_members = GetMembers(thisId, HOST, thisAuth.authStr, RESULTLIMIT)
    get_members.fetch_members()
    members_list = get_members.get_members_list()
    memberCount = len(members_list)
    if memberCount == 0: 
        logging.info(f'|'+ thisId + '|No members.')
        continue

    allRecords = []  # Initialize list

    # Fetch all attendance records for all meetings
    for meeting in meetings_list:
        """Itterate over each meeting in the course."""
        get_records = GetRecords(str(meeting['id']), meeting['courseId'], HOST, thisAuth.authStr, RESULTLIMIT)
        ##We use the course id value in the _12345_1 format here. See note in GetRecords
        get_records.fetch_records()
        records_list = get_records.get_records_list()
        allRecords.extend(records_list)

    recordCount = len(allRecords)
    if recordCount == 0: 
        logging.info(f'|{thisId}|No attendance records.')
    else:
        logging.info(f'|{thisId}|{memberCount} students, {meetingCount} meetings, and {recordCount} attendance records.')

    # Combine data from lists and write to outFile
    for meeting in meetings_list:
        meeting_id = str(meeting['id'])
        course_id = meeting['courseId']
        meeting_start = meeting['start']
        meeting_end = meeting['end']

        # Iterate through all members and check if they have a record
        for member in members_list:
            user = member['user']
            user_id = user['id']

            # Check if the user has an attendance record for this meeting
            attendance_record = next((rec for rec in allRecords if rec['userId'] == user_id and rec['meetingId'] == meeting_id), None)

            # Set the status: "Null" if no record found
            status = attendance_record['status'] if attendance_record else 'Null'

            # Declare the attendanceRow based on the determined status
            attendanceRow = {
                'courseId': thisId,
                'course_pk1': course_id,
                'meeting_id': meeting_id,
                'meeting_start': meeting_start,
                'meeting_end': meeting_end,
                'status': status,
                'user_pk1': user_id,
                'username': user['userName'],
                'external_user_key': user['externalId'],
                'student_id': user.get('studentId', '')
            }

            # Write the row to the output file
            outputWriter.writerow(attendanceRow)
            rowCounter += 1


#Calculate requests made
rate_checker = CheckRates(HOST, thisAuth.authStr)
rate_limit, end_remaining_requests = rate_checker.fetch_rates()
used_requests = int(start_remaining_requests) - int(end_remaining_requests)
logging.info(f'|This batch made {used_requests} requests. There are {end_remaining_requests} remaining today.')

# lets close up shop
outputFile.close()
inputFile.close()
logging.info(f'|Closing batch ' + batchId + ' with ' + str(rowCounter) + ' records.')
