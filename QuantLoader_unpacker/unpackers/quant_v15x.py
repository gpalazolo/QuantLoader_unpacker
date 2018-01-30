import logging
import os

import coloredlogs
from winappdbg import Debug, EventHandler, Process

level_styles = {'info': {'color': 'green'},
                'warning': {'color': 'yellow'},
                'debug': {'color': 'blue', 'bold': True},
                'critical': {'color': 'red', 'bold': True}}

logging.basicConfig(level=logging.INFO)
coloredlogs.install(level='DEBUG', fmt='  %(message)s', level_styles=level_styles)

QL_BUFFER = 4194304
QL_SIZE = 69632


class QHandler(EventHandler):
    apiHooks = {
        "kernel32.dll": [
            ("VirtualAlloc", 4),
            ("Sleep", 1)
        ],
    }

    def post_VirtualAlloc(self, event, retval):
        try:
            (ra, (lpAddress, dwSize, flAllocationType, flProtect)) = self.get_funcargs(event)
            logging.info("[*] <%d:%d> 0x%x: VirtualAlloc(0x%x,0x%x (%d),0x%x,0x%03x) = 0x%x" % (
                event.get_pid(), event.get_tid(), ra, lpAddress, dwSize, dwSize, flAllocationType, flProtect, retval))
        except Exception as e:
            logging.warning('There was an error: {}'.format(repr(e)))

    def pre_Sleep(self, event, ra, dwMilliseconds):
        process = Process(event.get_pid())
        self.extract_quant_payload(process)
        process.kill()

    def extract_quant_payload(self, process):
        logging.info('Trying to extract the payload')
        payload_path = os.path.join(os.environ['USERPROFILE'], 'Desktop', 'ql_15_payload.bin')

        with open(payload_path, "wb") as f:
            f.write(process.read(QL_BUFFER, QL_SIZE))
            logging.critical('##### PAYLOAD EXTRACTED >> "{}" ##### '.format(payload_path))

        if not os.path.isfile(payload_path):
            logging.info('We had a problem saving the file')
            return False

    @staticmethod
    def get_funcargs(event):
        return event.get_thread().get_pc(), event.hook.get_params(event.get_tid())


def extract_payload(file_path):
    """
    Function that'll handle winappdbg debug
    :param file_path: path of QuantLoader
    :return: bool
    """
    debug = Debug(QHandler())
    try:
        debug.execv([file_path])
        debug.loop()
    finally:
        debug.stop()
