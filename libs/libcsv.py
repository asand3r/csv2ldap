from libs.libsettings import write_log, FILE_LOGGER, LDAP_SETTINGS, EXCEPTION_DICT, ATTR_MATCHING_DICT, CSV_ENCODING, \
    PREP_DICT
from libs.libldap import get_user_dn
from csv import DictReader
from re import match, sub
from ast import literal_eval


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
            replace_tuple = literal_eval(method[7:])
        except SyntaxError:
            raise SystemExit('ERROR: Cannot parse replacement expression {}. Ckeck it.'.format(method[7:]))
        # If the first element of replace_tuple is <tuple>, so we have nested tuple. Walking through them.
        if type(replace_tuple[0]) is tuple:
            for nested_tuple in replace_tuple:
                # The first element of nested tuple must be regexp and the second one is replacement string.
                regexp, repl_str = nested_tuple
                # Let's make a replace
                attr_value = sub(regexp, nested_tuple[1], attr_value)
            # When nested tuples is ended, write 'new_attr' value
            else:
                new_attr = attr_value
        # else we have just one tuple, so just make a replace
        else:
            regexp, repl_str = replace_tuple
            new_attr = sub(regexp, repl_str, attr_value)

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


def get_csv_data(conn, data_file, delimiter=';'):
    """
    The function prepares CSV data to synchronize with LDAP. It's read the file, process it and return dict with
    data for update.

    :param conn:
    ldap3.Connection object.

    :param data_file:
    Path to CSV datafile.

    :param delimiter:
    Delimiter to separate CSV columns. Default is ';', can be set in config file.

    :return:
    dict
    {'employeeID': {Dict with LDAP attrs properties}}
    {'0000001029': {'sn': 'Ivanov', 'givenName': 'Ivan'}}
    """

    # Dict to store all employees with key as employeeID
    all_employees = {}

    # Opening CSV file and read it as dict
    with open(data_file, 'r', encoding=CSV_ENCODING) as users_csv:
        csv_data = DictReader(users_csv, delimiter=delimiter)
        # Making counter for writing line number to log file
        line_num = 1
        # Going through all data in csv
        for row in csv_data:
            empl_id = row['EmployeeID']
            # If in values has None, it means that data count bigger than headers and CSV is incorrect
            if None not in row.values():
                # Making attribute list for update
                # Calculated attributes cannot been get from CSV
                calc_attrs = ['initials', 'description', 'mobile', 'manager', 'displayname']
                update_attrs = list(set(LDAP_SETTINGS.LDAP_UPD_ATTRS) - set(calc_attrs))

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
                # initials and description
                if len(update_dict['middlename']) != 0:
                    initials = "{0}. {1}.".format(update_dict['givenname'][0], update_dict['middlename'][0])
                    description = '{sn} {gn} {mn}'.format(
                        sn=update_dict['sn'], gn=update_dict['givenname'], mn=update_dict['middlename'])
                else:
                    initials = "{}.".format(update_dict['givenname'][0])
                    description = '{sn} {gn}'.format(sn=update_dict['sn'], gn=update_dict['givenname'])
                update_dict['initials'] = initials
                update_dict['description'] = description
                update_dict['displayname'] = '{sn} {initials}'.format(sn=update_dict['sn'], initials=initials)

                # mobile
                # Trying to set it to one view for all
                if match(r'^\d[-\s]?(\d{3}-){2}(\d{2}-?){2}', row['MobilePhone']):
                    old = row['MobilePhone'].replace('-', '').replace(' ', '')
                    new = "+7 ({0}) {1}-{2}-{3}".format(old[1:4], old[4:7], old[7:9], old[9:11])
                else:
                    # Default - set CSV value as is
                    new = row['MobilePhone']
                update_dict['mobile'] = new

                # manager
                # Must be DistinguishedName of target user, so get it
                m_empl_id = row['ManagerEmployeeID']
                manager_dn = get_user_dn(conn, attr_data=m_empl_id)
                # If we've just one user - use it
                if len(manager_dn) == 1:
                    manager_dn = manager_dn[0]
                # If it's more than 1 - obviously it' mistake in LDAP
                elif len(manager_dn) > 1:
                    manager_dn = ""
                    write_log(FILE_LOGGER, 'INFO',
                              "Found many DN's for {0}, check your LDAP catalog".format(m_empl_id))
                # If found nothing - writing to log
                else:
                    manager_dn = ""
                    write_log(FILE_LOGGER, 'INFO',
                              "Cannot find DN for '{0}'".format(m_empl_id))
                update_dict['manager'] = manager_dn

                # Finally put the update_dict to the global dict
                all_employees[empl_id] = update_dict
            else:
                if empl_id is not None:
                    write_log(FILE_LOGGER, 'WARNING',
                              "CSV: missed one or more values in line {} (without header)".format(line_num)
                              )
            # Incrementing line counter
            line_num += 1
    return all_employees
