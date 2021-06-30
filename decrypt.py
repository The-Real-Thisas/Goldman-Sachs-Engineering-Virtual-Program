import os
hashes = []
with open("passwd_dump.txt") as fp:
    Lines = fp.readlines()
    for line in Lines:
        hashRead = line.split(":", 1)
        hashes.append(hashRead[1])
    hashes = map(lambda s: s.strip(), hashes)
for eachHash in hashes:
    command = f"hashcat '{eachHash}' rockyou.txt --q && hashcat '{eachHash}' rockyou.txt --show >> passwords.txt"
    os.system(command)
