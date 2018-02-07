import os
import csv
import re
import ldap3
import logging
import time
from hashlib import md5
from ast import literal_eval
from configparser import RawConfigParser
from logging.handlers import RotatingFileHandler
from ldap3.core.exceptions import LDAPSocketOpenError


def read_config(path):
    """
    The function reads csv2ldap.conf config file and returns RawConfigParser object.

    :param path:
    Path to config file
    :return:
    configparser.RawConfigParser object.
    """

    cfg = RawConfigParser()
    if os.path.exists(path):
        cfg.read(path)
        return cfg
    else:
        # Creating 'startup_error.log' if config file cannot be open
        with open('startup_error.log', 'w') as err_file:
            err_file.write('ERROR: Cannot find "csv2ldap.conf" fine in current directory.')
            raise SystemExit('Missing config file (csv2ldap.conf) in current directory')


def write_log(logger, err_level, message):
    """
    Writes string to log using logging module.

    :param logger:
    Logger object to use.
    :param err_level:
    Logging level - INFO, WARNING etc (also can be int - 20 for INFO, 30 for WARNING etc).
    :param message:
    String to write.
    :return:
    None
    """

    codes_to_int = {'DEBUG': 10, 'INFO': 20, 'WARNING': 30, 'ERROR': 40, 'CRITICAL': 50}
    if message is not None:
        logger.log(codes_to_int[err_level], message)
    else:
        logger.log(20, 'Logger has just got "None" for write to log. Going ahead...')


def get_logger(handler, formatter):
    """
    Getting logger object.

    :param handler:
    logging.Handler - set log handler (where you will write log string)
    :param formatter:
    logging.Formatter - set log string format.
    :return:
    Logger object
    """

    handler.setFormatter(formatter)
    logger = logging.getLogger()
    logger.addHandler(handler)
    return logger


def ldap_connect(ldap_server, ldap_user, ldap_password):
    """
    Establishing connection with LDAP server.

    :param ldap_server:
    str() LDAP server name or IP address.
    :param ldap_user:
    str() Username (sAMAccountName) using to connect with NTLM.
    :param ldap_password:
    str() User password.
    :return:
    ldap3.Connection object.
    """

    srv = ldap3.Server(ldap_server, get_info='ALL', mode='IP_V4_PREFERRED')
    try:
        conn = ldap3.Connection(srv, auto_bind=True, authentication='NTLM', user=ldap_user, password=ldap_password)
    except LDAPSocketOpenError as e:
        write_log(LOGGER, 'CRITICAL', "Cannot connect to LDAP server: {srv}".format(srv=ldap_server))
        raise SystemExit('ERROR: {message}'.format(message=e.__str__()))
    return conn


def update_user(conn, user_dn, updates):
    """
    Updates LDAP user's object by it's DistinguishedName. Also takes dict, what has info how to update values.
    Dict format describe in ldap3 project documentation and represents similar structure:
    {'attribute_name': [('MODIFY_REPLACE', [new_val.encode()])]}

    :param conn:
    ldap3.Connection object.
    :param user_dn:
    DistinguishedName of modified object.
    :param updates:
    Dict with attributes to update.
    :return:
    Two element tuple - (True/False, Description).
    """

    return conn.modify(user_dn, updates), conn.result['description']


def get_users(conn, searchfilter):
    """
    Function search users in LDAP catalog using search filter in config file.

    :param conn:
    ldap3.Connection object.
    :param searchfilter:
    LDAP search filter from config file.
    :return:
    dict with all found objects.
    """

    base_dn = conn.server.info.other['rootDomainNamingContext'][0]
    return conn.search(search_base=base_dn, search_filter=searchfilter, attributes=LDAP_GET_ATTRS)


def get_dn(conn, employeeid):
    """
    Function gets user DistinguishedName from LDAP catalog by attribute.

    :param conn:
    ldap3.Connection object.
    :param employeeid:
    LDAP attribute data.
    :return:
    List with LDAP user DN's.
    """

    # Making search filter (employeeID by default)
    filter_str = '(&(objectClass=user)(EmployeeID={}))'.format(employeeid)

    # Search in LDAP with our filter
    conn.search(conn.server.info.other['rootDomainNamingContext'], filter_str)
    dn_list = [entry.entry_dn for entry in conn.entries]
    return dn_list


def preprocessing(attr_value, method):
    """
    The function realize some preprocessing functionality for attributes.

    :param attr_value:
    <str>
    LDAP attribute to modify
    :param method:
    <str>
    What we want to do with attr. Can be 'capitalize', 'title', 'lower' and 'upper' for strings.
    :return:
    <str>
    Corrected attribute.
    """

    # Replacing
    if method.lower().startswith('replace'):
        # Making tuple with replacement data without the first 'replace' word.
        try:
            replace_expr = literal_eval(method[7:])
        except SyntaxError:
            raise SystemExit('ERROR: Cannot parse replacement expression {}. Check it.'.format(method[7:]))
        # If the first element of replace_tuple is <tuple>, so we have nested tuple. Walking through them.
        if type(replace_expr[0]) is tuple:
            for nested_tuple in replace_expr:
                regexp, repl_str = nested_tuple
                attr_value = re.sub(regexp, nested_tuple[1], attr_value)
            # When nested tuples is ended, write 'new_attr' value
            else:
                new_attr = attr_value
        # else we have just one tuple, so just make a replace
        else:
            regexp, repl_str = replace_expr
            new_attr = re.sub(regexp, repl_str, attr_value)

    # Operations with register
    elif method.lower() == 'capitalize':
        new_attr = attr_value.capitalize()
    elif method.lower() == 'title':
        new_attr = attr_value.title()
    elif method.lower() == 'lower':
        new_attr = attr_value.lower()
    elif method.lower() == 'upper':
        new_attr = attr_value.upper()
    else:
        new_attr = None
    return new_attr


def transform_mobile(phone_number):
    """
    The function transform phone number to one format.
    :param phone_number:
    str() String with phone number.
    :return:
    str() New phone number.
    """

    if re.match(r'^\d[-\s]?(\d{3}-){2}(\d{2}-?){2}', phone_number):
        old = phone_number.replace('-', '').replace(' ', '')
        new = "+7 ({0}) {1}-{2}-{3}".format(old[1:4], old[4:7], old[7:9], old[9:11])
    else:
        # Default - set value as is
        new = phone_number
    return new


def load_csv(conn, data_file, delimiter=';'):
    """
    The function prepares CSV data to synchronize with LDAP. It's read the file, process it and return dict with
    data for update.

    :param conn:
    ldap3.Connection object.
    :param data_file:
    str() Path to CSV datafile.
    :param delimiter:
    str() Delimiter to separate CSV columns. Default is ';', can be set in config file.
    :return:
    dict()
    {'employeeID': {Dict with LDAP attrs properties}}
    {'0000001029': {'sn': 'Ivanov', 'givenName': 'Ivan'}}
    """

    all_employees = {}

    # Opening CSV file and read it as dict
    with open(data_file, 'r', encoding=CSV_ENCODING) as users_csv:
        csv_data = csv.DictReader(users_csv, delimiter=delimiter)
        line_num = 1
        for row in csv_data:
            empl_id = row['EmployeeID']
            # If in values has None, it means that data count bigger than headers and CSV is incorrect
            if None not in row.values():
                calc_attrs = ['initials', 'description', 'mobile', 'manager', 'displayname']
                update_attrs = list(set(LDAP_UPD_ATTRS) - set(calc_attrs))

                # If user in exception list, subtract it's attrs from all update attributes in config file
                if empl_id in EXCEPTION_DICT:
                    # If user in exception list and has * as attributes - skip it
                    if EXCEPTION_DICT[empl_id][0] == '*':
                        continue
                    update_attrs = list(set(update_attrs) - set(EXCEPTION_DICT[empl_id]))
                update_dict = {}

                for attr in update_attrs:
                    # PREPROCESSING
                    if attr in (key.lower() for key in PREP_DICT.keys()):
                        method = PREP_DICT[attr].lower()
                        original_attr = row[ATTR_MATCHING_DICT[attr]]
                        corrected_attr = preprocessing(original_attr, method)
                        update_dict[attr] = corrected_attr
                    else:
                        # Fill update dict by static attributes from CSV
                        update_dict[attr] = row[ATTR_MATCHING_DICT[attr]]

                # Calculate rest attributes
                sn = update_dict['sn']
                given_name = update_dict['givenname']
                middle_name = update_dict['middlename']
                if middle_name != '':
                    initials = "{}. {}.".format(given_name[0], middle_name[0])
                    description = '{sn} {gn} {mn}'.format(sn=sn, gn=given_name, mn=middle_name)
                else:
                    initials = "{}.".format(given_name[0])
                    description = '{sn} {gn}'.format(sn=sn, gn=given_name)
                update_dict['initials'] = initials
                update_dict['description'] = description
                update_dict['displayname'] = '{sn} {initials}'.format(sn=sn, initials=initials)

                # mobile
                update_dict['mobile'] = transform_mobile(row['MobilePhone'])
                # manager
                manager_dn = get_dn(conn, employeeid=row['ManagerEmployeeID'])
                if len(manager_dn) == 1:
                    manager_dn = manager_dn[0]
                else:
                    manager_dn = ""
                    write_log(LOGGER, 'WARNING', "Found '{}' users for '{}' employeeid".format(
                        len(manager_dn), row['ManagerEmployeeID']))
                update_dict['manager'] = manager_dn

                # Put update_dict to the global dict
                all_employees[empl_id] = update_dict
            else:
                write_log(LOGGER, 'WARNING', "Missed values in CSV, line '{}'.".format(line_num))
            # Incrementing line counter
            line_num += 1
    return all_employees


def run_update(conn):
    """
    The function runs update process.

    :param conn:
    Result of ldap_connect() function.
    :return:
    None
    """

    # Processing CSV file...
    csv_data = load_csv(conn, CSV_FILE, CSV_DELIM)
    # Getting all need users from LDAP
    ad_users = get_users(conn=conn, searchfilter=LDAP_SEARCHFILTER)

    for user in ad_users:
        if user.employeeID.value in csv_data:
            # Update dict for one-time update of many attributes
            update_dict = {}
            update_attrs = LDAP_UPD_ATTRS
            if user.employeeID.value in EXCEPTION_DICT:
                update_attrs = set(LDAP_UPD_ATTRS) - set(EXCEPTION_DICT[user.employeeID.value])
            # Compare current attribute value from LDAP and new from CSV
            for attr in update_attrs:
                curr_val = user[attr].value
                new_val = csv_data[user.employeeID.value][attr]
                if curr_val is None:
                    curr_val = ""
                if curr_val != new_val:
                    # MODIFY_REPLACE if new_value length not equal zero
                    if len(new_val) != 0:
                        update_dict[attr] = [('MODIFY_REPLACE', [new_val.encode()])]
                    # MODIFY_DELETE if new value length is zero
                    else:
                        update_dict[attr] = [('MODIFY_DELETE', [curr_val])]
                # DEBUG: write to log, if new value equal current value
                else:
                    log_data = {
                        'login': user.sAMAccountName.value,
                        'prop_name': attr
                    }
                    write_log(LOGGER, 'DEBUG',
                              "User '{login}' has '{prop_name}' property with same value : SKIP".format(**log_data))
            # Running update
            if len(update_dict) != 0:
                upd_result = update_user(conn, user.entry_dn, update_dict)
                log_data = {'login': user.sAMAccountName.value,
                            'props': list(update_dict.keys()),
                            'msg': upd_result[1]
                            }
                if upd_result[0] is True:
                    write_log(LOGGER, 'INFO', '{login} : {props} : {msg}'.format(**log_data))
                else:
                    write_log(LOGGER, 'ERROR', '{login} : {props} : {msg}'.format(**log_data))
        # DEBUG: Write to log, if user not found in CSV
        else:
            log_data = {
                'login': user.sAMAccountName.value,
                'employeeID': user.employeeID.value,
            }
            write_log(LOGGER, 'DEBUG',
                      "User '{login}' with ID '{employeeID}' : 'NOT FOUND IN 1C : SKIP'".format(**log_data))
    print('{}: Update task complete, waiting for new data'.format(time.strftime('%d.%m.%Y %X')))


if __name__ == '__main__':
    # Lading config from file
    config = read_config(path='csv2ldap.conf')

    # MAIN section
    if config.has_section('MAIN'):
        WAIT_SEC = config.getint('MAIN', 'waitseconds', fallback=30)
        DATE_FMT = config.get('MAIN', 'DateFormat', fallback='%d.%m.%Y %X')

    # LDAP section
    if config.has_section('LDAP'):
        LDAP_SERVER = config.get('LDAP', 'Server')
        LDAP_USER = config.get('LDAP', 'username')
        LDAP_PASSWORD = config.get('LDAP', 'password')
        LDAP_SEARCHFILTER = config.get('LDAP', 'searchfilter')
        attrs = list(map(lambda x: x.lower(), config.get('LDAP', 'updateldapattrs').split(',')))
        LDAP_GET_ATTRS = attrs + ['sAMAccountName', 'employeeID']
        LDAP_UPD_ATTRS = attrs
    else:
        raise SystemExit("ERROR: Config file missed 'LDAP' section. You must specify it before run.")

    # CSV section
    if config.has_section('CSV'):
        CSV_FILE = config.get('CSV', 'FilePath')
        CSV_DELIM = config.get('CSV', 'Delimiter')
        CSV_ENCODING = config.get('CSV', 'Encoding')

    # EXCEPTION section
    EXCEPTION_DICT = {}
    if config.has_section('EXCEPTIONS') and config.items('EXCEPTIONS'):
        for eid, attrs in config.items('EXCEPTIONS'):
            EXCEPTION_DICT[eid] = attrs.split(',')

    # ATTR MATCHING section
    ATTR_MATCHING_DICT = {}
    if config.has_section('ATTR MATCHING') and config.items('ATTR MATCHING'):
        ATTR_MATCHING_DICT = dict(config.items('ATTR MATCHING'))

    # PREPROCESSING section (EXPERIMENTAL)
    PREP_DICT = {}
    if config.has_section('PREPROCESSING') and config.items('PREPROCESSING'):
        PREP_DICT = dict(config.items('PREPROCESSING'))

    # LOGGING section
    LOG_LEVEL = config.get('LOGGING', 'level')
    LOG_PATH = config.get('LOGGING', 'filepath')
    LOG_SIZE = config.getint('LOGGING', 'filesize')
    LOG_COUNT = config.getint('LOGGING', 'rotation')

    # Logger parameter
    logging.basicConfig(level=LOG_LEVEL)
    log_formatter = logging.Formatter(fmt="%(levelname)-9s: '%(asctime)s' %(message)s", datefmt='%d.%m.%Y %X')
    log_handler = RotatingFileHandler(filename=LOG_PATH, maxBytes=LOG_SIZE, backupCount=LOG_COUNT, encoding='utf-8')

    # Creating logger
    LOGGER = get_logger(handler=log_handler, formatter=log_formatter)

    init_md5 = ''
    write_log(LOGGER, 'INFO', 'Starting csv2ldap at {}'.format(time.strftime('%d.%m.%Y %X')))
    print('\n{}: csv2ldap started.\nPress CTRL-C to stop it...'.format(time.strftime('%d.%m.%Y %X')))
    while True:
        try:
            if os.path.exists(CSV_FILE):
                try:
                    with open(CSV_FILE, 'rb') as csv_file:
                        current_md5 = md5(csv_file.read()).hexdigest()
                except (IOError, FileNotFoundError):
                    write_log(LOGGER, 'CRITICAL', 'Cannot read CSV file: {}'.format(CSV_FILE))
                    raise SystemExit('Cannot read CSV file: {}'.format(CSV_FILE))

                if init_md5 != current_md5:
                    print('{}: Update task started'.format(time.strftime('%d.%m.%Y %X')))
                    with ldap_connect(LDAP_SERVER, LDAP_USER, LDAP_PASSWORD) as ldap_conn:
                        run_update(ldap_conn)
                    time.sleep(WAIT_SEC)
                else:
                    time.sleep(WAIT_SEC)
                init_md5 = current_md5
            else:
                write_log(LOGGER, 'CRITICAL', "File '{file}' doesn't exist".format(file=CSV_FILE))
                raise SystemExit("CSV file doesn't exist")
        except KeyboardInterrupt:
            print('{}: csv2ldap stopped by the user'.format(time.strftime('%d.%m.%Y %X')))
            break
