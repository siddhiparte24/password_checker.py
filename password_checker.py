import hashlib
import requests

# Function to make a request to the "Have I Been Pwned" API
def request_api_data(query_char):
    # Construct the URL with the first 5 characters of the hashed password
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    # Send a GET request to the API
    res = requests.get(url)
    # Check if the response status code is not 200 (OK)
    if res.status_code != 200:
        # Raise an error if the response status code is not 200
        raise RuntimeError(f'Error fetchinggg : {res.status_code}, check api and try again. ')
    return res

# Function to check if the tail of the hashed password exists in the API response
def get_password_leakcount(hashes, hash_to_check):
    # Split the response into lines and split each line into hash and count
    hashes = (line.split(':') for line in hashes.text.splitlines())
    # Iterate over each hash and count
    for h, count in hashes:
        # Check if the hash matches the tail of the hashed password
        if h == hash_to_check:
            # If match found, return the count
            return count
    # If no match found, return 0
    return 0

# Function to check if the password has been pawned
def pwned_api_check(password):
    # Hash the password using SHA-1 algorithm and convert to uppercase
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # Split the hashed password into first 5 characters (query prefix) and the rest (tail)
    first5, tail = sha1password[:5], sha1password[5:]
    # Request data from the API using the first 5 characters
    response = request_api_data(first5)
    # Check if the tail exists in the response and return the count
    return get_password_leakcount(response, tail)

# Main function to interact with the user and check the password
def main():
    # Prompt the user to enter their password
    password = input("Enter your password: ")
    # Check if the password has been pawned
    counti = pwned_api_check(password)
    # If count is not zero, inform the user that their password has been pawned
    if counti:
        print(f'{password} was found {counti} times. You should change your password.')
    # If count is zero, inform the user that their password is safe
    else:
        print(f'{password} was not found in any data breaches. Your password is safe.')

# Entry point of the script
if __name__ == '__main__':
    # Call the main function
    main()