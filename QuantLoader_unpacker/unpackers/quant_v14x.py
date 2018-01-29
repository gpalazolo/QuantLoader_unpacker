import logging
import os
import struct

import coloredlogs
from winappdbg import Debug, EventHandler, Process

level_styles = {'info': {'color': 'green'},
                'warning': {'color': 'yellow'},
                'debug': {'color': 'blue', 'bold': True},
                'critical': {'color': 'red', 'bold': True}}

logging.basicConfig(level=logging.INFO)
coloredlogs.install(level='DEBUG', fmt='  %(message)s', level_styles=level_styles)


def number(value):
    value = str(value)
    if len(value) % 3:
        value = ' ' * (3 - (len(value) % 3)) + value
    value = ','.join([value[i:i + 3] for i in range(0, len(value), 3)])
    return value


class QHandler(EventHandler):
    apiHooks = {
        "kernel32.dll": [
            ("VirtualAllocEx", 5),
            ("WriteProcessMemory", 5),
            ("CreateProcessA", 10)
        ],
    }

    def post_CreateProcessA(self, event, retval):
        self.post_CreateProcess(event, retval, False)

    def post_CreateProcess(self, event, retval, fUnicode):

        (ra, (
            lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
            lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)) = self.get_funcargs(event)

        p = event.get_process()
        t = event.get_thread()

        pid = event.get_pid()
        tid = event.get_tid()

        szApplicationName = p.peek_string(lpApplicationName, fUnicode)
        szCommandLine = p.peek_string(lpCommandLine, fUnicode)

        d = event.debug
        ProcessInformation = self.guarded_read(d, t, lpProcessInformation, 16)

        # Extract the various fields from the ProcessInformation structure

        hProcess = struct.unpack("<L", ProcessInformation[0:4])[0]
        hThread = struct.unpack("<L", ProcessInformation[4:8])[0]
        dwProcessId = struct.unpack("<L", ProcessInformation[8:12])[0]
        dwThreadId = struct.unpack("<L", ProcessInformation[12:16])[0]

        global proc_id
        proc_id = dwProcessId

        logging.info("[*] <%d:%d> 0x%x: CreateProcess(\"%s\",\"%s\",0x%x): %d (0x%x, 0x%x, <%d:%d>)" % (
            pid, tid, ra, szApplicationName, szCommandLine, dwCreationFlags, retval, hProcess, hThread, dwProcessId,
            dwThreadId))

    def post_VirtualAllocEx(self, event, retval):
        try:

            (ra, (hProcess, lpAddress, dwSize, flAllocationType, flProtect)) = self.get_funcargs(event)
            d = event.debug
            pid = event.get_pid()
            tid = event.get_tid()

            logging.info("[*] <%d:%d> 0x%x: VirtualAllocEx(0x%x,0x%x (%d),0x%x,0x%03x) = 0x%x" % (
                pid, tid, ra, lpAddress, dwSize, dwSize, flAllocationType, flProtect, retval))

            pass
        except Exception as e:
            logging.warning('There was an error: {}'.format(repr(e)))

    def post_WriteProcessMemory(self, event, retval):

        (ra, (hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)) = self.get_funcargs(event)

        pid = event.get_pid()
        tid = event.get_tid()

        logging.info("[*] <%d:%d> 0x%x: WriteProcessMemory(0x%x,0x%x,0x%x,0x%x,0x%x): %d" % (
            pid, tid, ra, hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten, retval))

        self.extract_quant_payload(event.get_process(), lpBuffer)

    def guarded_read(self, d, t, addr, size):
        data = None
        if size > 0:
            p = t.get_process()
            data = p.read(addr, size)
        return data

    def extract_quant_payload(self, process, memory_buffer):
        payload_path = os.path.join(os.environ['USERPROFILE'], 'Desktop', 'ql_14_payload.bin')
        try:
            payload = process.read(memory_buffer - 180, 28672)
            if payload:
                with open(payload_path, "wb") as f:
                    f.write(payload)
                    logging.critical('##### PAYLOAD EXTRACTED >> "{}" ##### '.format(payload_path))
        except Exception as e:
            logging.info('We did not found the payload: {}'.format(repr(e)))
        self.kill_processes(process)

    @staticmethod
    def get_funcargs(event):
        h = event.hook
        t = event.get_thread()
        tid = event.get_tid()
        return t.get_pc(), h.get_params(tid)

    @staticmethod
    def kill_processes(current_process):
        sp = Process(proc_id)
        sp.kill(0)
        current_process.kill(0)


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
