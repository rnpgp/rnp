from cli_common import (
    pswd_pipe
)

import logging
import copy

class Rnp(object):
    def __init__(self, homedir, rnp_path, rnpkey_path):
        self.__gpg = rnp_path
        self.__key_mgm_bin = rnpkey_path
        self.__common_params = ['--homedir', homedir]
        self.__password = None
        self.__userid = None
        self.__hash = None

    @property
    def key_mgm_bin(self):
        return self.__key_mgm_bin

    @property
    def rnp_bin(self):
        return self.__gpg

    @property
    def common_params(self):
        return copy.copy(self.__common_params)

    @property
    def password(self):
        return self.__password

    @password.setter
    def password(self, val):
        self.__password = val

    @property
    def userid(self):
        return self.__userid

    @userid.setter
    def userid(self, val):
        self.__userid = val

    @property
    def hash(self):
        return self.__hash

    @hash.setter
    def hash(self, val):
        self.__hash = val

    def copy(self):
        return copy.deepcopy(self)

    def _run(self, cmd, batch_input = None):
        import subprocess
        logging.debug((' '.join(cmd)).strip())
        process = subprocess.Popen(cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        output, errout = process.communicate(input = batch_input)
        retcode = process.poll()
        logging.debug(errout.strip())
        logging.debug(output.strip())
        return retcode == 0

    def generte_key_batch(self, batch_input):
        pipe = pswd_pipe(self.__password)
        params = self.common_params
        params += ['--generate-key', '--expert']
        params += ['--pass-fd', str(pipe)]
        params += ['--userid', self.userid]
        if self.hash:
            params += ['--hash', self.hash]
        try:
            ret = self._run([self.__key_mgm_bin] + params, batch_input)
        finally:
            import os
            os.close(pipe)
        return ret

    def export_key(self, output, secure = False):
        params = self.common_params
        params += ["--output", output]
        params += ["--userid", self.userid]
        params += ["--force"]
        params += ["--export-key", self.userid]
        return self._run([self.key_mgm_bin] + params)

    def import_key(self, filename):
        params = self.common_params
        params += ['--import-key', filename]
        return self._run([self.key_mgm_bin] + params)

    def sign(self, output, input):
        pipe = pswd_pipe(self.password)
        params = self.common_params
        params += ['--pass-fd', str(pipe)]
        params += ['--userid', self.userid]
        params += ['--sign', input]
        params += ['--output', output]
        if self.hash:
            params += ['--hash', self.hash]
        try:
            ret = self._run([self.rnp_bin] + params)
        finally:
            import os
            os.close(pipe)
        return ret

    def verify(self, input):
        params = self.common_params
        params += ['--verify', input]
        if self.hash:
            params += ['--hash', self.hash]
        return self._run([self.rnp_bin] + params)

    def encrypt(self, recipient, output, input):
        pipe = pswd_pipe(self.password)
        params = self.common_params
        params += ['--pass-fd', str(pipe)]
        params += ['--userid', recipient]
        params += ['--encrypt', input]
        params += ['--output', output]
        try:
            ret = self._run([self.rnp_bin] + params)
        finally:
            import os
            os.close(pipe)
        return ret

    def decrypt(self, output, input):
        pipe = pswd_pipe(self.password)
        params = self.common_params
        params += ['--pass-fd', str(pipe)]
        params += ['--userid', self.userid]
        params += ['--decrypt', input]
        params += ['--output', output]
        try:
            ret = self._run([self.rnp_bin] + params)
        finally:
            import os
            os.close(pipe)
        return ret
