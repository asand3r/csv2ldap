# csv2ldap
Utility can update LDAP user attributes to values from CSV file.

Dependencies:
- Python => 3.4 (smaller version, what has been tested)
- ldap3 => 2.2

## How it works
In our case we need to update our Active Directory users with data from CRM system. So, we exporting needed data to CSV file with specific format and feed it to csv2ldap.py as source. The utility loads file, check it with some rules, connecting to a LDAP (AD) server and compares every person it CSV with corresponding user. Therefore, the utility needs a key attribure to compare AD user with string in CSV data file and we decide to use 'employeeid' attribute.  

## CSV file header format
```csv
employeeid;sn;givenName;middleName;physicalDeliveryOfficeName;telephoneNumber;mobile;title;division;department;manager
```

Yeap, employeeid hardcoded as key now.  

## CSV file example
```csv
employeeid;sn;givenName;middleName;physicalDeliveryOfficeName;telephoneNumber;mobile;title;division;department;manager
0000000123;Ivanov;Ivan;Ivanovich;1068;645;+7 (916) 012-34-56;Engineer;Main division;Engineers department;0000000456
0000000987;Petrov;Petr;Petrovich;1068;646;;Engineer;Main division;Engineers department;0000000456
```

If you need to clear some user attribute or your CRM just hasn't it, leve it empty like exapmle above.

## Config file mandatory options
You must correct the config file before start. It has four mandatory options what you must feel anyway:
1. server - LDAP (AD) server name or IP address;  
2. username - username to connect to LDAP and correct it;  
3. password - password for the user;  
4. CsvPath - path to CSV data file.  

Other options has default values, so you may leave it as is, but I reccomend to check it anyway.

## Executable file parameters
csv2ldap2.py can get some addition parameters.

**-h|--help**  
Print HELP message.  
**-c|--config**  
Defines path to config file if it doesn't places next to csv2ldap.py.  
**-w|--wait**  
Set custom sleep interval between script running circles ('wait' option in config file).  
**-v|--version**  
Print utility version and exit.  
**-o|--onetime**  
Run script ones and exit.  
**--showcfg**  
Print config file and exit.  
**--debug**  
Enables DEBUG mode (not used yet).

## Running example
In the example below we updating one user. For demonstration we change 'physicalDeliveryOfficeName' attribute:  
![alt](https://pp.userapi.com/c824503/v824503986/155917/gknlDKnGV1s.jpg)
