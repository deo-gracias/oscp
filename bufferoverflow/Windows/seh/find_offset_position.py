
#!/usr/bin/python
from pwn import *

def main():

    address = raw_input("[+] Enter address from debugger: ").strip()

    hex_address = "0x" + address

    unpacked = p32(int(hex_address, 16))

    print "[+] Offset is: " + str(cyclic_find(unpacked))

if __name__ == "__main__":
    main()
