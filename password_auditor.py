import requests
import hashlib
import os

def main():
    while True:
        my_file = input('Please enter the path to the text file: ')
        if is_valid_file(my_file):
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
            print('Path provided is not a valid file path. Please try again.')

def is_valid_file(file_path):
    # Ensure the file path is within the desired directory
    desired_directory = "c:\\temp\\password.txt"  # Replace with the actual desired directory
    absolute_path = os.path.abspath(file_path)
    if not absolute_path.startswith(desired_directory):
        return False

    # Ensure the file exists
    if not os.path.isfile(absolute_path):
        return False

    return True

def get_pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again')
    return res

if __name__ == '__main__':
    main()
