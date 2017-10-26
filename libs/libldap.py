from ldap3 import Connection, Server
from ldap3.core.exceptions import LDAPSocketOpenError
from libs.libsettings import LDAP_SETTINGS, write_log, FILE_LOGGER


def ldap_connect(server_name, ldap_user, ldap_password):
    """
    Establishing connection with LDAP server.

    :param server_name:
     <str>
    Fully Qualified LDAP server name.
    :param ldap_user:
    Username (sAMAccountName) using to connect with NTLM.
    :param ldap_password:
    User password.
    :return:
    ldap3.Connection object.
    """
    ldap_srv = Server(server_name, get_info='ALL', mode='IP_V4_PREFERRED')
    try:
        ldap_conn = Connection(ldap_srv, auto_bind=True, authentication='NTLM', user=ldap_user, password=ldap_password)
    except LDAPSocketOpenError as e:
        write_log(FILE_LOGGER, 'CRITICAL', "Cannot connect to LDAP server: {srv}".format(srv=server_name))
        raise SystemExit('ERROR: {message}'.format(message=e.__str__()))
    return ldap_conn


def update_user(conn, user_dn, updates):
    """
    New version of update_user

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


def get_users(conn, searchfilter=LDAP_SETTINGS.LDAP_SEARCHFILTER):
    """
    Function search users in LDAP catalog using search filter in config file

    :param conn:
    ldap3.Connection object.
    :param searchfilter:
    LDAP search filter from config file.
    :return:
    dict with all found objects.
    """

    ldap_search_filter = searchfilter
    ldap_attrs = LDAP_SETTINGS.LDAP_GET_ATTRS
    ldap_base_dn = conn.server.info.other['rootDomainNamingContext'][0]
    conn.search(search_base=ldap_base_dn, search_filter=ldap_search_filter, attributes=ldap_attrs)
    ldap_users = conn.entries
    return ldap_users


def get_user_dn(conn, attr_data, attr_name='EmployeeID'):
    """
    Function gets user DistinguishedName from LDAP catalog by attribute.

    :param conn:
    ldap3.Connection object.
    :param attr_data:
    LDAP attribute data. For example, if attr_name is 'EmployeeID', attr_data may be '0000001029'.
    :param attr_name:
    LDAP attribute name. 'EmployeeID' by default.
    :return:
    List of <str> with LDAP user DN's.
    """

    # Making search filter (employeeID by default)
    filter_str = '(&(objectClass=user)({0}={1}))'.format(attr_name, attr_data)

    # Search in LDAP with our filter
    conn.search(conn.server.info.other['rootDomainNamingContext'], filter_str)
    dn_list = []
    for entry in conn.entries:
        dn_list.append(entry.entry_dn)
    return dn_list
