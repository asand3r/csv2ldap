from libs.libsettings import write_log, CSV_FILE, CSV_DELIM, FILE_LOGGER, WAIT_SEC, LDAP_SETTINGS, EXCEPTION_DICT
from libs.libldap import get_users, update_user, ldap_connect
from libs.libcsv import get_csv_data
from datetime import datetime
from time import sleep
from hashlib import md5
from os import path


def run_update(conn):
    """
    :param conn:
    Is result of ldap_connect() function from libldap.py - ldap3.Connection.
    :return:
    Nothing
    """

    # Processing CSV file...
    csv_1c_data = get_csv_data(conn, CSV_FILE, CSV_DELIM)
    # Getting all needing users from LDAP
    ad_users = get_users(conn)

    for user in ad_users:
        if user.employeeID.value in csv_1c_data:
            # Update dict for one-time update of many attributes
            update_dict = {}

            # !!! Сделать так, чтобы можно было брать актуальный список атрибутов из выгрузки, они там уже есть !!!
            # Пока оставим так, но это личшние вычисления
            update_attrs = LDAP_SETTINGS.LDAP_UPD_ATTRS
            if user.employeeID.value in EXCEPTION_DICT:
                update_attrs = set(LDAP_SETTINGS.LDAP_UPD_ATTRS) - set(EXCEPTION_DICT[user.employeeID.value])
            # Compare current attribute value from LDAP and new from CSV
            for attr in update_attrs:
                curr_val = user[attr].value
                new_val = csv_1c_data[user.employeeID.value][attr]
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
                    write_log(FILE_LOGGER, 'DEBUG',
                              "User '{login}' has '{prop_name}' property with same value : SKIP".format(**log_data))
            # Running update
            if len(update_dict) != 0:
                upd_result = update_user(conn, user.entry_dn, update_dict)
                log_data = {'login': user.sAMAccountName.value,
                            'props': list(update_dict.keys()),
                            'msg': upd_result[1]
                            }
                if upd_result[0] is True:
                    write_log(FILE_LOGGER, 'INFO', '{login} : {props} : {msg}'.format(**log_data))
                else:
                    write_log(FILE_LOGGER, 'ERROR', '{login} : {props} : {msg}'.format(**log_data))
        # DEBUG: Write to log, if user not found in CSV
        else:
            log_data = {
                'sep': ' : ',
                'login': user.sAMAccountName.value,
                'employeeID': user.employeeID.value,
            }
            write_log(FILE_LOGGER, 'DEBUG',
                      "User '{login}' with ID '{employeeID}'{sep}'NOT FOUND IN 1C{sep}SKIP'".format(**log_data))
    print('{0}: Update task complete, waiting for new data'.format(datetime.now().strftime('%d.%m.%Y %X')))


# Variable to store last CSV md5 sum
last_md5 = ''
write_log(FILE_LOGGER, 'INFO', 'Starting csv2ldap at {}'.format(datetime.now().strftime('%d.%m.%Y %X')))
print('\n{ts}: csv2ldap started.\nPress CTRL-C to stop...'.format(ts=datetime.now().strftime('%d.%m.%Y %X')))
while True:
    try:
        if path.exists(CSV_FILE) and path.isfile(CSV_FILE):
            try:
                with open(CSV_FILE, 'rb') as csv_file:
                    current_md5 = md5(csv_file.read()).hexdigest()
            except IOError:
                write_log(FILE_LOGGER, 'CRITICAL', 'cannot open CSV data file. Check your permissions.')
                raise SystemExit('Cannot open CSV data file.')

            if last_md5 != current_md5:
                print('{0}: Update task started'.format(datetime.now().strftime('%d.%m.%Y %X')))
                with ldap_connect(LDAP_SETTINGS.LDAP_SERVER, LDAP_SETTINGS.LDAP_USER, LDAP_SETTINGS.LDAP_PASSWORD) as \
                        ldap_conn:
                    run_update(ldap_conn)
                sleep(WAIT_SEC)
            else:
                sleep(WAIT_SEC)
            # Store new md5
            last_md5 = current_md5
        # Where is not CSV file
        else:
            write_log(FILE_LOGGER, 'CRITICAL', "File '{file}' doesn't exist".format(file=CSV_FILE))
            raise SystemExit("CSV file doesn't exist")
    except KeyboardInterrupt:
        print('{ts}: csv2ldap stopped by the user'.format(ts=datetime.now().strftime('%d.%m.%Y %X')))
        break
