# csv2ldap
Updates LDAP users from CSV file

Dependencies:
- Python => 3.4 (smaller version, whant has been tested)
- ldap3 =>2.2


If you need to update your LDAP (Active Directory) users object from some system, what can provide data in CSV format,
csv2ldap can help you to automate this process.
You can form special CSV file (example can be found here), make changes in the config file and run csv2ldap.py executable file.
So, uses options in csv2ldap2.conf, it will process CSV file, connect to LDAP server and will try to update suitable users objects.
