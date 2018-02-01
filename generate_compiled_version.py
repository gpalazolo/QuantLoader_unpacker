import os
import shutil
from distutils.sysconfig import get_python_lib

# =========== Don't forget to install all packages of 'requirements.txt' on your virtualenv =========== #
compiled_name = 'QL_Unpacker'
python_file_name = 'main'

# Do not change anything
virtual_env_path = os.path.join(os.path.dirname(os.path.dirname(get_python_lib())), 'Scripts')
script_path = os.path.dirname(os.path.realpath(__file__))
reg_path = os.path.join(script_path, 'ql_unpacker.reg')
bat_path = os.path.join(script_path, 'ql_unpacker.cmd')
project_path = os.path.basename(script_path)

# Generates a compiled version of obfuscated code
os.system(r'{}\pyinstaller --onefile {}\{}.py'.format(virtual_env_path, project_path, python_file_name))
os.remove('{}.spec'.format(python_file_name))
shutil.rmtree('build', ignore_errors=True)
shutil.copy(os.path.join('dist', '{}.exe'.format(python_file_name)), '{}.exe'.format(compiled_name))
shutil.rmtree('dist', ignore_errors=True)

# Creates the entry to add the file on context menu (right click).
with open(reg_path, 'w') as f:
    f.write('Windows Registry Editor Version 5.00\n'
            '[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shell\Extract Payload from QuantLoader]\n'
            '[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shell\Extract Payload from QuantLoader\command]\n'
            '@="' + os.path.realpath(bat_path).replace('\\', '\\\\') + ' \\"%1\\""')

with open(bat_path, 'w') as f:
    f.write('cls\n"{}.exe" -f %1\npause'.format(compiled_name))
