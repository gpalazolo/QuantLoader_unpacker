import logging
import os
import sys
from argparse import ArgumentParser

import coloredlogs
import yara

level_styles = {'info': {'color': 'green'},
                'warning': {'color': 'yellow'},
                'debug': {'color': 'blue', 'bold': True},
                'critical': {'color': 'red', 'bold': True}}

logging.basicConfig(level=logging.INFO)
coloredlogs.install(level='DEBUG', fmt='  %(message)s', level_styles=level_styles)


def print_logo():
    logging.debug("                                                                                                            ")
    logging.debug(" $$$$$$\                                 $$\     $$\                                $$\                     ")
    logging.debug("$$  __$$\                                $$ |    $$ |                               $$ |                    ")
    logging.debug("$$ /  $$ |$$\   $$\  $$$$$$\  $$$$$$$\ $$$$$$\   $$ |      $$$$$$\   $$$$$$\   $$$$$$$ | $$$$$$\   $$$$$$\  ")
    logging.debug("$$ |  $$ |$$ |  $$ | \____$$\ $$  __$$\\_$$  _|  $$ |     $$  __$$\  \____$$\ $$  __$$ |$$  __$$\ $$  __$$\ ")
    logging.debug("$$ |  $$ |$$ |  $$ | $$$$$$$ |$$ |  $$ | $$ |    $$ |     $$ /  $$ | $$$$$$$ |$$ /  $$ |$$$$$$$$ |$$ |  \__|")
    logging.debug("$$ $$\$$ |$$ |  $$ |$$  __$$ |$$ |  $$ | $$ |$$\ $$ |     $$ |  $$ |$$  __$$ |$$ |  $$ |$$   ____|$$ |      ")
    logging.debug("\$$$$$$ / \$$$$$$  |\$$$$$$$ |$$ |  $$ | \$$$$  |$$$$$$$$\\$$$$$$  |\$$$$$$$ |\$$$$$$$ |\$$$$$$$\ $$ |      ")
    logging.debug(" \___$$$\  \______/  \_______|\__|  \__|  \____/ \________|\______/  \_______| \_______| \_______|\__|      ")
    logging.debug("     \___|                                                                                                  ")
    logging.debug(" ~~~~~~~~~~ Unpacker by: Palazolo                                                                           ")
    logging.debug("\n")
    logging.debug(" This code is not safe to run on your machine. Are you on a virtual machine? (y/n)                          ")


def run(file_path: str):
    """
    Main function for the Unpacker
    :param file_path: Path of QuantLoader sample
    :return: bool
    """
    yf = os.path.join(os.path.dirname(__file__), 'unpackers', 'quant_loader.yar')
    ym = []
    compiler = yara.compile(yf)

    with open(file_path, 'rb') as f:
        try:
            yara_matches = compiler.match(data=f.read())
        except yara.Error as e:
            logging.critical('Yara error: {} - File: {}'.format(repr(e), yf))
        for match in yara_matches:
            ym.append(match)
            logging.info('Found a match: {}'.format(match))
    return True


if __name__ == '__main__':

    parser = ArgumentParser(description='QuantLoader Unpacker', epilog='Example: \n QL_Unpacker.exe -f "aaa.exe"')
    parser.add_argument('-f', '--file', help='File path', type=str, required=False, default=False)
    parser.add_argument('-v', '--version', help='Show version', action='store_true', required=False, default=False)
    args = parser.parse_args()
    if args.version:
        from QuantLoader_unpacker.__version__ import __version__

        logging.info('QuantLoader Unpacker version: {}'.format(__version__))
        sys.exit()

    elif args.file:
        print_logo()
        opt = input()
        if opt != 'y':
            logging.info('Exiting ...')
            sys.exit(0)

        logging.info('I warned you (~_~)')
        msg = 'Payload extracted! Bye ;)' if run(args.file) else 'Didn\'t found the payload :('
        logging.warning(msg)
        os.system('pause')
        sys.exit(0)
