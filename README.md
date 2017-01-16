# wpscan-wrap
Basic python wrapper for wpscan (WordPress vulnerability scanner). 

The idea is to use this to automate the scnning of WordPress sites on a schedule using cron.
Sites are pulled from the settings.ini file and should be updated accordingly.

It is assumed that wpscan installed on the system and is in your path.
If it is not you should change the path used in the subrorcess section of the script. 
