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

        current_process = event.get_process()
        szApplicationName = current_process.peek_string(lpApplicationName, fUnicode)
        szCommandLine = current_process.peek_string(lpCommandLine, fUnicode)
        ProcessInformation = self.guarded_read(event.get_thread(), lpProcessInformation, 16)

        hProcess = struct.unpack("<L", ProcessInformation[0:4])[0]
        hThread = struct.unpack("<L", ProcessInformation[4:8])[0]
        dwProcessId = struct.unpack("<L", ProcessInformation[8:12])[0]
        dwThreadId = struct.unpack("<L", ProcessInformation[12:16])[0]

        global proc_id
        proc_id = dwProcessId

        logging.info("[*] <%d:%d> 0x%x: CreateProcess(\"%s\",\"%s\",0x%x): %d (0x%x, 0x%x, <%d:%d>)" % (
            event.get_pid(), event.get_tid(), ra, szApplicationName, szCommandLine, dwCreationFlags, retval,
            hProcess, hThread, dwProcessId, dwThreadId))

    def post_VirtualAllocEx(self, event, retval):
        try:
            (ra, (hProcess, lpAddress, dwSize, flAllocationType, flProtect)) = self.get_funcargs(event)

            logging.info("[*] <%d:%d> 0x%x: VirtualAllocEx(0x%x,0x%x (%d),0x%x,0x%03x) = 0x%x" % (
                event.get_pid(), event.get_tid(), ra, lpAddress, dwSize, dwSize, flAllocationType, flProtect, retval))

        except Exception as e:
            logging.warning('There was an error: {}'.format(repr(e)))

    def post_WriteProcessMemory(self, event, retval):

        (ra, (hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)) = self.get_funcargs(event)

        logging.info("[*] <%d:%d> 0x%x: WriteProcessMemory(0x%x,0x%x,0x%x,0x%x,0x%x): %d" % (
            event.get_pid(), event.get_tid(), ra, hProcess, lpBaseAddress, lpBuffer, nSize,
            lpNumberOfBytesWritten, retval))

        self.extract_quant_payload(event.get_process(), lpBuffer)

    def guarded_read(self, thread, address, size):
        data = None
        if size > 0:
            p = thread.get_process()
            data = p.read(address, size)
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
        return event.get_thread().get_pc(), event.hook.get_params(event.get_tid())

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
