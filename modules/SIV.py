import os
import grp
import pwd
import time
import hashlib
import pickle as pkl

class Log:
    TMP = "[{}] {}"

    @staticmethod
    def _base(msg_type: str, msg: str):
        data = Log.TMP.format(msg_type, msg)

        return data

    @staticmethod
    def warn(msg: str) -> str:
        return Log._base("W", msg)

class FileDescriptor:
    def __init__(
            self,
            full_path: str,
            size: int,
            owner: str,
            group: str,
            permission: str,
            last_modification: int,
            digest: str
    ):
        self.full_path: str = full_path
        self.size: int = size
        self.owner: str = owner
        self.group: str = group
        self.permission: str = permission
        self.last_modification: int = last_modification
        self.digest: str = digest


class SIV:
    INIT_MODE = 'init'
    VARIFICATION_MODE = 'verification'

    SUPPORTED_MODES = [
        INIT_MODE,
        VARIFICATION_MODE
    ]

    MD5 = 'md5'
    SHA1 = 'sha1'

    SUPPORTED_HASH = [
        MD5,
        SHA1
    ]

    def __init__(
            self,
            monitored_dir: str,
            verification_file: str,
            report_file: str,
            mode: str,
            hash_func: str = SHA1,
    ):
        self.monitored_dir: str = os.path.abspath(monitored_dir)
        self.verification_file: str = os.path.abspath(verification_file)
        self.report_file: str = os.path.abspath(report_file)
        self.hash_func: str = hash_func
        self.mode: str = mode
        if self.mode not in self.SUPPORTED_MODES:
            raise ValueError("supported modes: '{}".format(self.SUPPORTED_MODES))
        if self.hash_func not in self.SUPPORTED_HASH:
            raise ValueError("supported hash: '{}".format(self.SUPPORTED_HASH))

        # self.hash_function = eval('hashlib.{}'.format(self.hash_func))

        if self.mode == self.INIT_MODE:
            self.__init_mode()
        elif self.mode == self.VARIFICATION_MODE:
            self.__verification_mode()


    def __verification_mode(self):
        # verifying input files
        self.validation_input_verification_mode()

        # load the verification file
        verification = self.load_verification_file(self.verification_file)
        prev_file_descriptors = verification['file_descriptors']

        self.hash_func = verification['hash_func']
        self.hash_function = eval('hashlib.{}'.format(self.hash_func))
        timer = time.time()

        file_descriptors, n_dirs, n_files, n_warn, report_messages = dict(), 0, 0, 0, ''
        for (path, dirs, files) in os.walk(self.monitored_dir):
            for file in files:
                full_path = os.path.join(path, file)
                stat = os.stat(full_path)
                content = open(full_path, 'rb').read()

                fd = FileDescriptor(
                    full_path=full_path,
                    size=stat.st_size,
                    owner=pwd.getpwuid(stat.st_uid).pw_name,
                    group=grp.getgrgid(stat.st_gid).gr_name,
                    permission=oct(stat.st_mode)[-3:],
                    last_modification=stat.st_mtime,
                    digest=self.hash_function(content).hexdigest()
                )

                file_descriptors.update({fd.full_path: fd})
                n_files += 1

                picked: FileDescriptor = prev_file_descriptors.get(fd.full_path, None)
                if picked:
                    flag = self._compare(fd, picked)
                    if flag == 0:
                        continue

                    msg, n_warn = self.check_modification(picked, fd, n_warn)
                    report_messages += msg
                else:
                    report_messages += "{}\n".format(Log.warn("New '{}' added.".format(fd.full_path)))
                    n_warn += 1

            n_dirs += 1

        removed_files = prev_file_descriptors.keys() - file_descriptors.keys()
        for removed_file in removed_files:
            report_messages += "{}\n".format(Log.warn("File '{}' removed.".format(removed_file)))
            n_warn += 1

        self.save_report(
            self.monitored_dir,
            self.verification_file,
            n_dirs,
            n_files,
            time.time() - timer,
            n_warn,
            report_messages
        )

    @staticmethod
    def check_modification(previous: FileDescriptor, current: FileDescriptor, n_warn):

        message = ''
        CHANGE_TEMPLATE = "(Previous: {}, Current: {})"

        # Check size
        if current.size != previous.size:
            message += "{}\n".format(
                Log.warn("Size of file '{}' {}.".format(
                    current.full_path, CHANGE_TEMPLATE.format(
                        previous.size, current.size
                    )
                ))
            )
            n_warn += 1

        # Check owner
        if current.owner != previous.owner:
            message += "{}\n".format(
                Log.warn("Owner of file '{}' {}.".format(
                    current.full_path, CHANGE_TEMPLATE.format(
                        previous.owner, current.owner
                    )
                ))
            )
            n_warn += 1

        # Check group
        if current.group != previous.group:
            message += "{}\n".format(
                Log.warn("Group of file '{}' {}.".format(
                    current.full_path, CHANGE_TEMPLATE.format(
                        previous.group, current.group
                    )
                ))
            )
            n_warn += 1

        # Check permission
        if current.permission != previous.permission:
            message += "{}\n".format(
                Log.warn("Permission of file '{}' {}.".format(
                    current.full_path, CHANGE_TEMPLATE.format(
                        previous.permission, current.permission
                    )
                ))
            )
            n_warn += 1

        # Check last modification
        if current.last_modification != previous.last_modification:
            message += "{}\n".format(
                Log.warn("LastModification of file '{}' {}.".format(
                    current.full_path, CHANGE_TEMPLATE.format(
                        time.ctime(previous.last_modification),
                        time.ctime(current.last_modification),
                    )
                ))
            )
            n_warn += 1

        # Check hash
        if current.digest != previous.digest:
            message += "{}\n".format(
                Log.warn("HASH of file '{}' {}.".format(
                    current.full_path, CHANGE_TEMPLATE.format(
                        previous.digest, current.digest
                    )
                ))
            )
            n_warn += 1

        return message, n_warn

    @staticmethod
    def _compare(current, prev):
        flag = 0

        # Compare Size
        if not (current.size == prev.size):
            flag = 1

        # Compare owner
        if not (current.owner == prev.owner):
            flag = 1

        # Compare Group
        if not (current.group == prev.group):
            flag = 1

        # Compare Permission
        if not (current.permission == prev.permission):
            flag = 1

        # Compare Modification
        if not (current.last_modification == prev.last_modification):
            flag = 1

        # Compare Hashing
        if not (current.digest == prev.digest):
            flag = 1

        return flag

    @staticmethod
    def load_verification_file(verification_file):
        return pkl.load(open(verification_file, 'rb'))

    def validation_input_verification_mode(self):
        # Verify that the specified verification file exists
        # Verify that the specified verification file is outside the monitored directory
        assert os.path.exists(self.verification_file), 'verification file does not exist'
        assert self.monitored_dir not in self.verification_file, 'verification file should be outside of the ' \
                                                                 'monitored directory.'

        # Verify that the specified report file is outside the monitored directory, and it is a txt file
        self.verify_report_file(self.report_file)

    def __init_mode(self):
        self.hash_function = eval('hashlib.{}'.format(self.hash_func))
        self.validation_input_init_mode()
        timer = time.time()

        file_descriptor, num_dirs, num_file = dict(), 0, 0
        for (path, dirs, files) in os.walk(self.monitored_dir):
            for file in files:
                full_path = os.path.join(path, file)
                stat = os.stat(full_path)
                content = open(full_path, 'rb').read()

                fd = FileDescriptor(
                    full_path=full_path,
                    size=stat.st_size,
                    owner=pwd.getpwuid(stat.st_uid).pw_name,
                    group=grp.getgrgid(stat.st_gid).gr_name,
                    permission=oct(stat.st_mode)[-3:],
                    last_modification=stat.st_mtime,
                    digest=self.hash_function(content).hexdigest()
                )

                file_descriptor.update({fd.full_path: fd})
                num_file += 1

            num_dirs += 1

        exec_time = time.time() - timer

        self.save_verification(file_descriptor)
        self.save_report(
            self.monitored_dir,
            self.verification_file,
            num_dirs,
            num_file,
            exec_time,
            None,
            None
        )

    def validation_input_init_mode(self):
        # verify monitored directory
        assert os.path.isdir(self.monitored_dir), 'monitored directory is not directory'
        assert os.path.exists(self.monitored_dir), 'monitored directory does not exist'

        # verify verification file is outside the monitored directory
        assert self.monitored_dir not in self.verification_file, 'verification file should be outside of the ' \
                                                                 'monitored directory.'


        # verify report file is outside of the monitored directory and being txt file
        self.verify_report_file(self.report_file)

        # verify that the hash function entered is supported by this SIV
        assert self.hash_func in self.SUPPORTED_HASH, "invalid hash, supported hash: '{}'".format(self.SUPPORTED_HASH)

    def verify_report_file(self, report_file: str):
        assert self.monitored_dir not in report_file, 'report file should be outside of monitored directory'
        if report_file.split("/")[-1].split(".")[-1] != "txt":
            raise ValueError("Entered report file should be a text file")

    def verify_hash_func(self, hash_func: str):
        assert hash_func in self.SUPPORTED_HASH, "invalid hash, supported hash: '{}'".format(self.SUPPORTED_HASH)

    def save_report(self, *args):
        data = "Monitored path: '{}'\n" \
               "Verification file: '{}'\n" \
               "Number of parsed directories: '{}'\n" \
               "Number of parsed files: '{}'\n" \
               "Time to complete: '{}'\n" \
               "Number of warnings: '{}'\n" \
               "Messages: (W: warning)\n" \
               "{}" \
               "".format(*args)

        with open(self.report_file, 'w') as file:
            file.write(data)

    def save_verification(self, file_descriptors):
        tmp: dict = dict(
            hash_func=self.hash_func,
            file_descriptors=file_descriptors
        )

        pkl.dump(tmp, open(self.verification_file, 'wb'))
