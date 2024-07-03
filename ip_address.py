import ipaddress


        
# Initializing a mongodb connection 

while True:
    ip = input("Enter the IP address:\n")

    try:
        # validating input as ip address
        ipaddress.ip_address(ip)
        
        #

    except :
        print(f'{ip!r} does not appear to be an IPv4 or IPv6 address, Please enter the corrent ip format :)')
        
        
        
        
        
        
       