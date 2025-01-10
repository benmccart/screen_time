# screen_time

A simple program accumulates the logged in time for configured users and forces a logoff if the user exceeds the logged in time for the day.

## Problem Solved
I have a simple Windows 10 machine set up for my kids for some of their school work.  It is trivial to schedule times at which they may log in, but nothing to limit their total logged in time.  For example, maybe they can log in anytime between 9:00 AM and 5:00 PM M-F, but I don't want them to exceed 45 minutes of screen time per day.  There is no straight-forward solution using standard Windows 10 Home or Professional editions if you are loging into accounts on the local machine, which is the way our children's accounts are set up.  I wrote this simple program to address the issue.

## Configuration
1. Edit config.json and add a line item for each user you want to monitor and restrict screen time for.  Times are in minutes.
2. Using an administrator account place the build screen_time.exe along with config.json in "C:\Program Files\screen_time\" 
3. Use the Windows Task Scheduler to create a new task with the following properties.
    1. Run the application under SYSTEM user account.
    2. Run whether user is logged on or not.
    3. Trigger the task at system startup.
    4. Allow the task to be run on demand.
    5. If the task fails restart the task every 1 minute.
    6. Attemp to restart up to 99 times.
    7. Set "Do not start a new instance" if the task is already running.

The screen_time.exe does not accumulate time when user is logged in but their screen is locked.

Of course make sure that any accounts that are listed in config.json don't have permission to write to "C:\Program Files\screen_time\" or to cancel or terminate the process.
