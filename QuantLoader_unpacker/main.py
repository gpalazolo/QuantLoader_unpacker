import logging
import os
import sys
from argparse import ArgumentParser
from QuantLoader_unpacker.unpackers.ql_signature import SIG

import coloredlogs

level_styles = {'info': {'color': 'green'},
                'warning': {'color': 'yellow'},
                'debug': {'color': 'blue', 'bold': True},
                'critical': {'color': 'red', 'bold': True}}

logging.basicConfig(level=logging.INFO)
coloredlogs.install(level='DEBUG', fmt='  %(message)s', level_styles=level_styles)


def print_logo():
    logging.debug("________                       __  .____                     .___             ")
    logging.debug("\_____  \  __ _______    _____/  |_|    |    _________     __| _/___________  ")
    logging.debug(" /  / \  \|  |  \__  \  /    \   __\    |   /  _ \__  \   / __ |/ __ \_  __ \ ")
    logging.debug("/   \_/.  \  |  // __ \|   |  \  | |    |__(  <_> ) __ \_/ /_/ \  ___/|  | \/ ")
    logging.debug("\_____\ \_/____/(____  /___|  /__| |_______ \____(____  /\____ |\___  >__|    ")
    logging.debug("       \__>          \/     \/             \/         \/      \/    \/        ")
    logging.debug(" ~~~~~~~~~~ Unpacker by: Palazolo                                                                           ")
    logging.debug("\n")
    logging.debug(" This code is not safe to run on your machine. Are you on a virtual machine? (y/n)                          ")


def run(file_path):
    """
    Main function for the Unpacker
    :param file_path: Path of QuantLoader sample
    :return: bool
    """
    with open(file_path, 'rb') as f:
        qf = __get_version(f.read())
        if not qf:
            return False

        logging.info('Let\'s get the payload')
        try:
            if qf == '14':
                from QuantLoader_unpacker.unpackers.quant_v14x import extract_payload
            else:
                from QuantLoader_unpacker.unpackers.quant_v15x import extract_payload
            return extract_payload(file_path)
        except ImportError:
            logging.warning('An error occurred with this script, please, let the author know :|')
            return False


def __get_version(fb):
    for ql_v in SIG:
        mi = 0
        for s in SIG[ql_v]:
            mi = mi + 1 if s in fb else mi
            if (ql_v == '15' and mi > 2) or (ql_v == '14' and mi > 1):
                logging.critical('Found version: {}'.format(ql_v))
                return ql_v
    return None

if __name__ == '__main__':

    parser = ArgumentParser(description='QuantLoader Unpacker', epilog='Example: \n QL_Unpacker.exe -f "quant.exe"')
    parser.add_argument('-f', '--file', help='Quant Loader Sample Path', type=str, required=False, default=False)
    parser.add_argument('-v', '--version', help='Show version', action='store_true', required=False, default=False)
    args = parser.parse_args()
    if args.version:
        from QuantLoader_unpacker.__version__ import __version__

        logging.info('QuantLoader Unpacker version: {}'.format(__version__))
        sys.exit()

    elif args.file:
        print_logo()
        opt = raw_input()
        if opt != 'y':
            logging.debug('Exiting ...')
            sys.exit(0)

        logging.warning('I warned you (~_~)')
        run(args.file)
        logging.warning('Bye ;)')
        os.system('pause')
        sys.exit(0)
