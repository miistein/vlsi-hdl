import argparse
import subprocess

command = 'ssh -X jklaw@ieng6-ece-05.ucsd.edu'
subprocess.run(command, shell=True)
