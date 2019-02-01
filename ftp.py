import argparse
import subprocess
import atexit

# note dir is read only
# another fun expantsion is for multiple files.
# one arg for dir (--dir ___) and --file comma seperated list of files in dir
# too lazy to do this, but best to do --download (create a makedir file first) and then --upload
# class as an interface? with _ as _: and then on "exit" literally just break and run .__close__
parser = argparse.ArgumentParser(''' ftp over ssh with duck (default)''')
parser.add_argument(
    'path', type=str, help='full path on remote host is required')
parser.add_argument('--file', action='store_true',
                    help='include if opening a file')
parser.add_argument('--dir', action='store_true',
                    help='include if opening a dir')

args = parser.parse_args()


def runonexit():
    print('exiting')


def getpath(path, file=None, dir=None):
    # Add backslashs where appropriate
    # to conform to wierd $PATH/<file> and $PATH/<folder>/ conventions
    if(path[0] != '/'):
        path = '/' + path
    elif(type(path[0]) != str):
        raise Exception

    if dir:
        # if file omit /, if dir must not omit /
        if(path[-1] != '/'):
            path = path + '/'
            print(path)
        elif(type(path[-1]) != str):
            raise Exception
    elif file:
        if(path[-1] == '/'):
            path = path - '/'
            print(path)
        elif(type(path[-1]) != str):
            raise Exception
    full_path = ' sftp://jklaw@ieng6-ece-05.ucsd.edu%s' % path

    return full_path


args.file = True
full_path = getpath(args.path, file=args.file, dir=args.dir)

command = 'duck -p Sasha787 --parallel --application /Applications/Visual\ Studio\ Code.app/ --edit ' + full_path

subprocess.run(command, shell=True)

# example for cleanup. Probably want to upload at cleanup and upload regularly.
atexit.register(runonexit)
