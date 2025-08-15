#!/usr/bin/env python3

import time
import os
import subprocess
import requests

OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', default=None)

if OPENAI_API_KEY:
    print('[+] PROCESS RUNNING WITH OPENAI API KEY!')
else:
    print('[-] NO API KEY FOUND')

# subprocess.Popen(['bash', '-c', '"ls"'])
# time.sleep(5)
requests.get('https://google.com')
print('[+] PROCESS FINISHED')
