# utilizing the https://haveibeenpwned.com/API/V3
# This Password Auditor utilizes the haveibeenpwned api - you provide the path to a text file of passwords and it will check them against the haveibeenpwned database

import requests
import hashlib
import sys
import os.path
from os import path


def main(args):
    my_file = input('Please enter the path to the text file: ')
    if os.path.exists(my_file):
        with open(my_file) as f:
            args = f.readlines()
            args = [x.strip() for x in args]
            for password in args:
                count = get_pwned_api_check(password)
                if count:
                    print(f'{password} was found {count} times and you should change your password')
                else:
                    print(f'{password} was NOT found. Safe for now!')
            return 'Completed!'
    else:
        return 'Path provided can not be located'


def get_pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    print(response)
    return get_password_leaks_count(response, tail)


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


# GET https://api.pwnedpasswords.com/range/{first 5 hash characters}

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
