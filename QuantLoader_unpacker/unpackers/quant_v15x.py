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


class QHandler(EventHandler):
    apiHooks = {
        "kernel32.dll": [
            ("VirtualAlloc", 4),
            ("Sleep", 1)
        ],
    }

    @staticmethod
    def get_funcargs(event):
        h = event.hook
        t = event.get_thread()
        tid = event.get_tid()

        return t.get_pc(), h.get_params(tid)

    def post_VirtualAlloc(self, event, retval):
        try:
            (ra, (lpAddress, dwSize, flAllocationType, flProtect)) = self.get_funcargs(event)
            pid = event.get_pid()
            tid = event.get_tid()

            logging.info("[*] <%d:%d> 0x%x: VirtualAlloc(0x%x,0x%x (%d),0x%x,0x%03x) = 0x%x" % (
                pid, tid, ra, lpAddress, dwSize, dwSize, flAllocationType, flProtect, retval))
        except Exception as e:
            logging.warning('There was an error: {}'.format(repr(e)))

    def pre_Sleep(self, event, ra, dwMilliseconds):
        process = Process(event.get_pid())
        self.extract_quant_payload(process)
        process.kill()

    def extract_quant_payload(self, process):

        logging.info('Trying to extract the payload')
        payload_path = os.path.join(os.environ['USERPROFILE'], 'Desktop', 'ql_15_payload.bin')
        for mbi in process.get_memory_map():

            # Address and size of memory block.
            ba = mbi.BaseAddress
            rs = mbi.RegionSize

            if ba == 4194304 and rs == 69632:
                with open(payload_path, "wb") as f:
                    f.write(process.read(ba, rs))
                    logging.critical('##### PAYLOAD EXTRACTED >> "{}" ##### '.format(payload_path))
                return True

        logging.info('We did not found the payload')
        return False


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
