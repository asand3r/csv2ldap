from os import path
from logging import basicConfig, Formatter, getLogger
from logging.handlers import RotatingFileHandler
from collections import namedtuple
from configparser import RawConfigParser


def get_config(cfg_file):
    """
    :param cfg_file:
    Path to config file
    :return:
    configparser.RawConfigParser object.
    """

    cfg = RawConfigParser()
    if path.isfile(cfg_file):
        cfg.read(cfg_file)
    else:
        # Creating 'startup_error.log' if config file cannot be open
        with open('startup_error.log', 'w') as err_file:
            err_file.write('ERROR: Cannot find "csv2ldap.conf" fine in current directory.')
            raise SystemExit('Missing config file (csv2ldap.conf) in working directory')
    return cfg


def write_log(logger, msg_level, message):
    """
    Writes string to log with logging module.

    :param logger:
    Logger object to use.
    :param msg_level:
    Logging level - INFO, WARNING etc (also can be int - 20 for INFO, 30 for WARNING etc).
    :param message:
    String to write.
    :return:
    None
    """

    codes = [code for code in range(10, 60, 10)]
    codes_to_int = {'DEBUG': 10, 'INFO': 20, 'WARNING': 30, 'ERROR': 40, 'CRITICAL': 50}
    if message is not None:
        if type(msg_level) is str:
            logger.log(codes_to_int[msg_level], message)
        elif type(msg_level) is int and msg_level in codes:
            logger.log(msg_level, message)
    else:
        logger.log(20, 'Logger has just get "None" for write to log, so nothing to do. Going ahead...')


def get_logger(handler, formatter):
    """
    Getting logger object (logging.getLogger())

    :param handler:
    logging.Handler - set log handler (where you will write log string)
    :param formatter:
    logging.Formatter - set log string format.
    :return:
    Logger object
    """

    handler.setFormatter(formatter)
    file_logger = getLogger()
    file_logger.addHandler(handler)
    return file_logger


# Lading config from file
config = get_config('csv2ldap.conf')

# MAIN section
if config.has_option('MAIN', 'waitseconds'):
    WAIT_SEC = config.getint('MAIN', 'waitseconds')
else:
    WAIT_SEC = 30

# LDAP section
# Storing LDAP parameters with named tuple
confset = namedtuple('confset', [
    'LDAP_SERVER', 'LDAP_USER', 'LDAP_PASSWORD', 'LDAP_SEARCHFILTER', 'LDAP_GET_ATTRS', 'LDAP_UPD_ATTRS'])
LDAP_SETTINGS = confset(
    LDAP_SERVER=config.get('LDAP', 'Server'),
    LDAP_USER=config.get('LDAP', 'username'),
    LDAP_PASSWORD=config.get('LDAP', 'password'),
    LDAP_SEARCHFILTER=config.get('LDAP', 'searchfilter'),
    LDAP_GET_ATTRS=list(map(lambda x: x.lower(), config.get('LDAP', 'updateldapattrs').split(','))) +
    ['sAMAccountName', 'employeeID'],
    LDAP_UPD_ATTRS=list(map(lambda x: x.lower(), config.get('LDAP', 'updateldapattrs').split(',')))
)
# CSV section
if config.has_section('CSV'):
    CSV_FILE = config.get('CSV', 'DataPath')
    CSV_DELIM = config.get('CSV', 'Delimiter')
    CSV_ENCODING = config.get('CSV', 'Encoding')

# EXCEPTION section
EXCEPTION_DICT = {}
if config.has_section('EXCEPTIONS') and len(config.items('EXCEPTIONS')) != 0:
    for employeeid, attrs in config.items('EXCEPTIONS'):
        EXCEPTION_DICT[employeeid] = attrs.split(',')

# ATTR MATCHING section
ATTR_MATCHING_DICT = {}
if config.has_section('ATTR MATCHING') and len(config.items('ATTR MATCHING')) != 0:
    ATTR_MATCHING_DICT = dict(config.items('ATTR MATCHING'))

# PREPROCESSING section (EXPERIMENTAL)
PREP_DICT = {}
if config.has_section('PREPROCESSING') and len(config.items('PREPROCESSING')) != 0:
    PREP_DICT = dict(config.items('PREPROCESSING'))

# LOGGING section
LOG_LEVEL = config.get('LOGGING', 'level')
LOG_PATH = config.get('LOGGING', 'filepath')
LOG_SIZE = config.getint('LOGGING', 'filesize')
LOG_COUNT = config.getint('LOGGING', 'rotation')

# Logger parameter
basicConfig(level=LOG_LEVEL)
log_formatter = Formatter(fmt="%(levelname)-9s: '%(asctime)s' %(message)s", datefmt='%d.%m.%Y %X')
file_log_handler = RotatingFileHandler(filename=LOG_PATH, maxBytes=LOG_SIZE, backupCount=LOG_COUNT, encoding='utf-8')

# Creating logger
FILE_LOGGER = get_logger(handler=file_log_handler, formatter=log_formatter)
