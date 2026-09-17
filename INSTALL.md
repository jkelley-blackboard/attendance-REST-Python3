# Installation and Usage Guide

**Batch Attendance Python3 module**

<https://github.com/jkelley-blackboard/attendance-REST-Python3>

> BLACKBOARD MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY OF THE
> SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
> WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR
> NON-INFRINGEMENT. BLACKBOARD SHALL NOT BE LIABLE FOR ANY DAMAGES SUFFERED BY
> LICENSEE AS A RESULT OF USING, MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS
> DERIVATIVES.

**Before you start:** while it is part of step 3, it might make sense to verify
that you are able to install Python 3 before you start. If you don't have local
PC permission, better to find out early.

---

## 1. Register Application

### Sign up and/or log in

<https://developer.blackboard.com/>

### Register the application

1. Click the (+) icon and select **Manual Registration**.
2. Fill out the form:
   - **Name and Description** — give it a meaningful name and useful
     description. The name will show in the Blackboard REST configuration
     interface.
   - **Domain** — the domain of the Blackboard system(s), e.g.
     `blackboard.com, myschool.edu`
   - **Do not enable the LTI 1.3 switch.** Leave it off.
3. When you submit the form it will return a list of details. Copy the following
   to a notepad:
   - Application ID
   - Key
   - Secret

> Note this will be the only time/place you can see the secret. If you lose it
> you will need to create another Key/Secret pair.

---

## 2. Prepare Blackboard

### Create a system role with the noted privileges

Name it something like **Attendance Integration** and give it a meaningful
description. If you share admin responsibilities, include your name.

"Permit" the following privileges:

- User management by Web Services
- Administrator Panel (Courses) > Courses
- Course/Organization Control Panel (Tools) > Attendance > View Attendance
- Course/Organization Control Panel (Customization) > Properties
- Administrator Panel (Courses) > Courses > Edit > Enrollments

See [Getting started with entitlements][ent] for displaying entitlements on the
privileges page in Blackboard.

[ent]: https://docs.blackboard.com/docs/blackboard/rest-apis/getting-started/getting-started-with-entitlements#mapping-entitlements-with-privileges

> Note that the code in this module only uses GET requests, so it will not make
> any changes to data.

### Create a user and assign the new role

If you don't already have a naming convention for integration accounts, you
might want to start one. Give the account meaningful values, indicate its
purpose, and assign the **Attendance Integration** system role.

### Create the integration in Blackboard

Create the REST integration from the Admin Page: **REST API Integrations >
Create Integration**.

1. Select the **Click Integration** link in the top left corner.
2. Enter the Application ID.
3. Enter the username for the user you just created.
4. Select **No** for both *End User Access* and *Authorized To Act As User*, then
   submit.
5. This will create an integration with the name from step 1.

> For extra security, set this integration to unavailable when not in use.

---

## 3. Set up the local environment

### Install Python 3

<https://www.python.org/downloads/>

I used 3.11.0 when I wrote this code. If you already have any 3.x installed, it
should work fine. If you want to install the latest 3.x version it should work
as well.

### Create a working folder

Your choice — give it a meaningful name.

### Download and prep files from GitHub

#### Create the .env file

Copy the supplied template and fill it in:

```
copy .env.example .env
```

Set these three values from step 1:

| Variable | Value |
|---|---|
| `BB_HOST` | Hostname of your test system, e.g. `mytest.blackboard.com`. No `https://`. |
| `BB_KEY` | Key from the developer portal |
| `BB_SECRET` | Secret from the developer portal |

Two optional values can be left at their defaults:

| Variable | Default | Notes |
|---|---|---|
| `BB_RESULT_LIMIT` | `100` | REST page size, 1-100. Lower it to exercise paging when your test courses have few records. |
| `BB_SESSION_BUFFER` | `30` | Seconds before token expiry to reauthenticate. Increase if you expect long delays between requests. |

The script looks for `.env` in the working folder, then `internal/.env`. To keep
the file somewhere else, pass `--env-file`:

```
python batch_attendance3.py list.csv --env-file C:\secure\attendance.env
```

Anything already set as a real environment variable wins over the file, so a
scheduled task can supply `BB_SECRET` without writing it to disk.

> **Keep the filled-in `.env` out of source control.** The supplied `.gitignore`
> already excludes it, along with the `internal/` folder and every run output
> folder.

#### Create or update the list.csv file

Each row of the file should be a course ID value as you would see in the GUI.
For testing I recommend at least one of each:

- Not a course
- A course without attendance records
- A course with full attendance records
- A course with partial attendance records
- A parent course (merge) with attendance records

### Establish and configure a virtual environment

A virtual environment keeps this tool's two dependencies out of your system
Python. Open a command prompt in your working folder and run three commands.

**Windows (CMD):**

```
python -m venv venv_batch_attendance
venv_batch_attendance\Scripts\activate
pip install -r attendance_requirements.txt
```

**Windows (PowerShell):** same, but the activate line is

```
venv_batch_attendance\Scripts\Activate.ps1
```

If PowerShell refuses with a script execution error, either use CMD instead or
allow signed scripts for your account:

```
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

**macOS / Linux:**

```
python3 -m venv venv_batch_attendance
source venv_batch_attendance/bin/activate
pip install -r attendance_requirements.txt
```

Once activated your prompt is prefixed with `(venv_batch_attendance)`. That
prefix is how you know the next command will use the virtual environment.

The `pip install` step reads `attendance_requirements.txt` and installs
`requests` and `python-dotenv`.

> To leave the virtual environment type `deactivate` or close the window. You
> need to activate it again each time you open a new command prompt — creating
> it is a one-time step, activating it is not.

---

## 4. Run the program

### Execute the script

```
python batch_attendance3.py list.csv
```

This will:

- start logging to the CMD console
- create a date-time folder
- write a log file and the `attendance_output_*.csv` file to that folder

The output file is pipe (`|`) delimited. A row is written for every
student/meeting pair; where a meeting exists but the student has no attendance
record, `status` is written as `Null`.

### Export modes

| Mode | Command | Columns | Rows |
|---|---|---|---|
| Full (default) | `batch_attendance3.py list.csv` | 18 | every student x meeting, `Null` where no record |
| Minimal | `batch_attendance3.py list.csv --minimal` | 8 | same rows, pk1 values only |
| Records only | `batch_attendance3.py list.csv --records-only` | 8 | only records that exist, no `Null` rows |

`--minimal` drops names, usernames and child course detail, keeping only pk1
identifiers. It skips the course lookup and the child course lookups, and asks
Learn for a much smaller membership payload.

`--records-only` additionally skips the membership request, so the export
contains only attendance that was actually taken. Use it when you are loading
into something that already knows the roster. It implies `--minimal`.

Request counts are dominated by the attendance fetch itself, so these modes
save roughly 1-5% of requests on a typical course - they mainly reduce payload
size and output width. The script automatically fetches records per student
instead of per meeting when that costs fewer requests, which matters most for
courses with many meetings and few students.

### Reading the console output

A healthy run looks like this:

```
[2026-09-17 13:37:24]|INFO|Starting Batch Attendance ID = 20260917-133724
[2026-09-17 13:37:25]|INFO|Auth token expires in 58 minutes and 51 seconds.
[2026-09-17 13:37:25]|INFO|Rate Limit: 10000. Remaining Requests: 9935
[2026-09-17 13:37:29]|INFO|jkelley_sandbox1 | No attendance records.
[2026-09-17 13:37:30]|INFO|NO_SUCH_COURSE_ZZZ99 > No course found.
[2026-09-17 13:37:31]|INFO|There are 9929 remaining today. That is a difference of 7.
[2026-09-17 13:37:31]|INFO|Total GET requests made: 8
[2026-09-17 13:37:31]|INFO|Closing batch 20260917-133724 with 3 records.
```

`No course found` and `No attendance records` are informational — the course is
skipped and the batch continues.

### Common problems

| Message | Cause |
|---|---|
| `No .env file found. Looked for: .env, internal\.env` | You haven't copied `.env.example` to `.env` yet, or you're running from the wrong folder. |
| `Missing required value(s): BB_KEY, BB_SECRET` | The `.env` file was found but those lines are still blank. |
| `BB_SECRET is 8 characters, expected at least 32` | The secret was truncated on paste. |
| `BB_KEY contains whitespace` | A stray space or line break was pasted in with the value. |
| `Failed to authenticate: 401` | Key/secret are valid characters but wrong, or the integration is set to unavailable in Blackboard. |
| `Failed to authenticate:` with a connection error | `BB_HOST` is wrong or unreachable. |
| `403` on course or meeting requests | The system role is missing one of the privileges in step 2. |
