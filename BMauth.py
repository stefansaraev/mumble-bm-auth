#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import Ice
import _thread
import logging
import configparser
import re

import requests
from requests.auth import HTTPBasicAuth

from threading  import Timer
from optparse   import OptionParser
from logging    import (debug,
                        info,
                        warning,
                        error,
                        critical,
                        exception,
                        getLogger)

def x2bool(s):
    """Helper function to convert strings from the config to bool"""
    if isinstance(s, bool):
        return s
    elif isinstance(s, str):
        return s.lower() in ['1', 'true']
    raise ValueError()

cfgfile = 'BMauth.ini'
default = {
            'bm':(
                   ('auth_url', str, 'https://auth.url'),
                   ('auth_user', str, ''),
                   ('auth_pass', str, '')
            ),

            'user':(('id_offset', int, 1000000000),
                    ('reject_on_error', x2bool, True),
                    ('reject_on_miss', x2bool, True)),

            'ice':(('host', str, '127.0.0.1'),
                   ('port', int, 6502),
                   ('slice', str, 'Murmur.ice'),
                   ('secret', str, ''),
                   ('watchdog', int, 30)),

            'iceraw':None,

            'murmur':(('servers', lambda x:list(map(int, x.split(','))), []),),

            'log':(('level', int, logging.DEBUG),
                   ('file', str, 'BMauth.log'))}

class config(object):
    def __init__(self, filename = None, default = None):
        if not filename or not default: return
        cfg = configparser.ConfigParser()
        cfg.optionxform = str
        cfg.read(filename)

        for h,v in default.items():
            if not v:
                try:
                    self.__dict__[h] = cfg.items(h)
                except configparser.NoSectionError:
                    self.__dict__[h] = []
            else:
                self.__dict__[h] = config()
                for name, conv, vdefault in v:
                    try:
                        self.__dict__[h].__dict__[name] = conv(cfg.get(h, name))
                    except (ValueError, configparser.NoSectionError, configparser.NoOptionError):
                        self.__dict__[h].__dict__[name] = vdefault


def do_main_program():
    slicedir = Ice.getSliceDir()
    if not slicedir:
        slicedir = ["-I/usr/share/Ice/slice", "-I/usr/share/slice"]
    else:
        slicedir = ['-I' + slicedir]
    Ice.loadSlice('', slicedir + [cfg.ice.slice])
    import Murmur

    class BMauthenticatorApp(Ice.Application):
        def run(self, args):
            self.shutdownOnInterrupt()

            if not self.initializeIceConnection():
                return 1

            if cfg.ice.watchdog > 0:
                self.failedWatch = True
                self.checkConnection()

            # Serve till we are stopped
            self.communicator().waitForShutdown()
            self.watchdog.cancel()

            if self.interrupted():
                warning('Caught interrupt, shutting down')

            return 0

        def initializeIceConnection(self):
            ice = self.communicator()

            if cfg.ice.secret:
                debug('Using shared ice secret')
                ice.getImplicitContext().put("secret", cfg.ice.secret)

            info('Connecting to Ice server (%s:%d)', cfg.ice.host, cfg.ice.port)
            base = ice.stringToProxy('Meta:tcp -h %s -p %d' % (cfg.ice.host, cfg.ice.port))
            self.meta = Murmur.MetaPrx.uncheckedCast(base)

            adapter = ice.createObjectAdapterWithEndpoints('Callback.Client', 'tcp -h %s' % cfg.ice.host)
            adapter.activate()

            metacbprx = adapter.addWithUUID(metaCallback(self))
            self.metacb = Murmur.MetaCallbackPrx.uncheckedCast(metacbprx)

            authprx = adapter.addWithUUID(BMauthenticator())
            self.auth = Murmur.ServerUpdatingAuthenticatorPrx.uncheckedCast(authprx)

            return self.attachCallbacks()

        def attachCallbacks(self, quiet = False):
            try:
                if not quiet: info('Attaching meta callback')

                self.meta.addCallback(self.metacb)

                for server in self.meta.getBootedServers():
                    if not cfg.murmur.servers or server.id() in cfg.murmur.servers:
                        if not quiet: info('Setting authenticator for virtual server %d', server.id())
                        server.setAuthenticator(self.auth)

            except (Murmur.InvalidSecretException, Ice.UnknownUserException, Ice.ConnectionRefusedException) as e:
                if isinstance(e, Ice.ConnectionRefusedException):
                    error('Server refused connection')
                elif isinstance(e, Murmur.InvalidSecretException) or \
                     isinstance(e, Ice.UnknownUserException) and (e.unknown == 'Murmur::InvalidSecretException'):
                    error('Invalid ice secret')
                else:
                    # We do not actually want to handle this one, re-raise it
                    raise e

                self.connected = False
                return False

            self.connected = True
            return True

        def checkConnection(self):
            try:
                if not self.attachCallbacks(quiet = not self.failedWatch):
                    self.failedWatch = True
                else:
                    self.failedWatch = False
            except Ice.Exception as e:
                error('Failed connection check, will retry in next watchdog run (%ds)', cfg.ice.watchdog)
                debug(str(e))
                self.failedWatch = True

            self.watchdog = Timer(cfg.ice.watchdog, self.checkConnection)
            self.watchdog.start()

    class metaCallback(Murmur.MetaCallback):
        def __init__(self, app):
            Murmur.MetaCallback.__init__(self)
            self.app = app

        def started(self, server, current = None):
            if not cfg.murmur.servers or server.id() in cfg.murmur.servers:
                info('Setting authenticator for virtual server %d', server.id())
                try:
                    server.setAuthenticator(app.auth)
                except (Murmur.InvalidSecretException, Ice.UnknownUserException) as e:
                    if hasattr(e, "unknown") and e.unknown != "Murmur::InvalidSecretException":
                        raise e

                    error('Invalid ice secret')
                    return
            else:
                debug('Virtual server %d got started', server.id())

        def stopped(self, server, current = None):
            if self.app.connected:
                try:
                    if not cfg.murmur.servers or server.id() in cfg.murmur.servers:
                        info('Authenticated virtual server %d got stopped', server.id())
                    else:
                        debug('Virtual server %d got stopped', server.id())
                    return
                except Ice.ConnectionRefusedException:
                    self.app.connected = False

            debug('Server shutdown stopped a virtual server')

    class BMauthenticator(Murmur.ServerUpdatingAuthenticator):
        def __init__(self):
            Murmur.ServerUpdatingAuthenticator.__init__(self)
            self.name_uid_cache = dict()

        def authenticate(self, name, pw, certlist, certhash, strong, current = None):
            # Search for the user in the database
            FALL_THROUGH = -2
            AUTH_REFUSED = -1

            # match bm CALLSIGN-ID
            search = re.search('(^[0-9]?[A-Za-z]{1,2}[0-9]{1,4}[A-Za-z]{1,4})[-]([2-7][0-9]{6}$)', name, flags=0)
            if search:
                callsign = search.groups()[0]
                id = search.groups()[1]

                if not pw:
                    warning("No password supplied for user " + name)
                    return (AUTH_REFUSED, None, None)

                headers = { "X-Id": id, "X-Callsign" : callsign.upper(), "X-Password": pw }
                response = requests.get(cfg.bm.auth_url, headers=headers, auth=(cfg.bm.auth_user, cfg.bm.auth_pass))
                if response.status_code == 200:
                    debug("Login accepted for " + name)
                    return (int(id) + cfg.user.id_offset, name, [])
                else:
                    debug("Login refused (invalid password) for " + name)
                    return (AUTH_REFUSED, None, None)
            else:
                return (FALL_THROUGH, None, None)


        def getInfo(self, id, current = None):
            return (False, None)

        def nameToId(self, name, current = None):
            if name in self.name_uid_cache:
                uid = self.name_uid_cache[name] + cfg.user.id_offset
                debug("nameToId %s (cache) -> %d", name, uid)
                return uid

            debug('nameToId %s -> ?', name)
            return -2

        def idToName(self, id, current = None):
            return ""

        def idToTexture(self, id, current = None):
            return ""

        def registerUser(self, name, current = None):
            return -2

        def unregisterUser(self, id, current = None):
            return -1

        def getRegisteredUsers(self, filter, current = None):
            return {}

        def setInfo(self, id, info, current = None):
            return -1

        def setTexture(self, id, texture, current = None):
            return -1

    class CustomLogger(Ice.Logger):
        def __init__(self):
            Ice.Logger.__init__(self)
            self._log = getLogger('Ice')

        def _print(self, message):
            self._log.info(message)

        def trace(self, category, message):
            self._log.debug('Trace %s: %s', category, message)

        def warning(self, message):
            self._log.warning(message)

        def error(self, message):
            self._log.error(message)

    info('Starting BM mumble authenticator')
    initdata = Ice.InitializationData()
    initdata.properties = Ice.createProperties([], initdata.properties)
    for prop, val in cfg.iceraw:
        initdata.properties.setProperty(prop, val)

    initdata.properties.setProperty('Ice.ImplicitContext', 'Shared')
    initdata.properties.setProperty('Ice.Default.EncodingVersion', '1.0')
    initdata.logger = CustomLogger()

    app = BMauthenticatorApp()
    state = app.main(sys.argv[:1], initData = initdata)
    info('Shutdown complete')

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-i', '--ini',
                      help = 'load configuration from INI', default = cfgfile)
    parser.add_option('-v', '--verbose', action='store_true', dest = 'verbose',
                      help = 'verbose output [default]', default = True)
    parser.add_option('-q', '--quiet', action='store_false', dest = 'verbose',
                      help = 'only error output')
    (option, args) = parser.parse_args()

    try:
        cfg = config(option.ini, default)
    except Exception as e:
        print('Fatal error, could not load config file from "%s"' % cfgfile, file=sys.stderr)
        sys.exit(1)

    if cfg.log.file:
        try:
            logfile = open(cfg.log.file, 'a')
        except IOError as e:
            print('Fatal error, could not open logfile "%s"' % cfg.log.file, file=sys.stderr)
            sys.exit(1)
    else:
        logfile = logging.sys.stderr

    if option.verbose:
        level = cfg.log.level
    else:
        level = logging.ERROR

    logging.basicConfig(level = level,
                        format='%(asctime)s %(levelname)s %(message)s',
                        stream = logfile)

    do_main_program()
