import requests
import hashlib
import sys

def request_api(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error: {res.status_code}. Check API and try again.')
    return res

def get_leaks(hashes, tail_check):
    # 5. Response comes as: hashed password : count of leaks
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for hash, count in hashes:
        # 6. If tail matches respones, count has being printed
        if hash == tail_check:
            return count
    return 0

def pwned_check(password):
    # 2. Hashing password, and splitting. API accepts first five chars.
    shapass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    fiveChar, tail = shapass[:5], shapass[5:]
    # 3. API gives a list of matches as a response 
    response = request_api(fiveChar)
    # 4. Returning responses with a tail from user hashed password
    return get_leaks(response, tail)

def main(args):
    for password in args:
        # 1.Calling function to check password with pass provided by user as arg.
        count = pwned_check(password)
        if count:
            print(f'{password} was found {count} times. You should change your password.')
        else:
            print(f'No leaks.')
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
