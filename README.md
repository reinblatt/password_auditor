# password_auditor
This is a fun little project that uses the haveibeenpwned api to check for compromised passwords.

It is recommended that you use Python3.
Simply run the scripts and provide the path to the file containing passwords in plaintext.
The tool will then hash each of the passwords and then upload only a portion of the hash to haveibeenpwned via the API to identify if the password hash portion matches a password identified in a data breach.
