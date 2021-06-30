# Analysis on Password Dump

---

## Cracking Process:

### Identification of Algorithm

Through the use of a python-based tool `hashID` It was possible to identify the hashes as the result of MD5 hashing. This was later confirmed when after testing with `hashcat`.

```bash
$ hashid "1f5c5683982d7c3814d4d9e6d749b21e"
Analyzing '1f5c5683982d7c3814d4d9e6d749b21e'
[+] MD5
```

### Cracking

After identifying the hashing algorithm the first step was to try cracking one password. Due to the underlying algorithm used for hashing, it is not possible to reverse the hash to plaintext instead the approach possible is to brute-force what plaintext is used to generate the hash. 

For brute-forcing the plaintext a `wordlist` is required, the wordlist called `rockyou.txt` provided by kali linux is used.

The cracking itself is done by a tool known as `hashcat` wherein we provide the operational parameters and it performs the 'cracking' process automatically. 

```bash
┌──(kali㉿kali)-[~]
└─$ hashcat "e10adc3949ba59abbe56e057f20f883e" /usr/share/wordlists/rockyou.txt   
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-5350U CPU @ 1.80GHz, 1405/1469 MB (512 MB allocatable), 1MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

Host memory required for this attack: 64 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 13 secs

e10adc3949ba59abbe56e057f20f883e:123456          
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: MD5
Hash.Target......: e10adc3949ba59abbe56e057f20f883e
Time.Started.....: Wed Jun 30 14:06:46 2021 (0 secs)
Time.Estimated...: Wed Jun 30 14:06:46 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    12778 H/s (0.30ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 1024/14344385 (0.01%)
Rejected.........: 0/1024 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: 123456 -> bethany

Started: Wed Jun 30 14:06:26 2021
Stopped: Wed Jun 30 14:06:52 2021
```

This is the key information:

```bash
* Runtime...: 13 secs
Status...........: Cracked
Hash.Name........: MD5
Hash.Target......: e10adc3949ba59abbe56e057f20f883e
Candidates.#1....: 123456 -> bethany
```

`hashcat` was able to crack the hash in a mere 12 seconds and obtained the password as '123456'. Which if hashed via MD5 gives the exact hash.

$$Md5(123456) = e10adc3949ba59abbe56e057f20f883e$$

### Automation

While it is possible to crack individually is it better to automate the process. To achieve this a python script has been developed to open the file, collect each password into an array and pipe the hashes into `hashcat` . `hashcat` will then crack the hash and pipe it to a file (passwords.txt).

```python
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
```

### Results

Through the use of `hashcat` and the custom python script I was able to obtain the following passwords for each hash.

```
e10adc3949ba59abbe56e057f20f883e:123456
25f9e794323b453885f5181f1b624d0b:123456789
d8578edf8458ce06fbc5bb76a58c5ca4:qwerty
5f4dcc3b5aa765d61d8327deb882cf99:password
96e79218965eb72c92a549dd5a330112:111111
25d55ad283aa400af464c76d713c07ad:12345678
e99a18c428cb38d5f260853678922e03:abc123
fcea920f7412b5da7be0cf42b8c93759:1234567
7c6a180b36896a0a8c02787eeafb0e4c:password1
6c569aabbf7775ef8fc570e228c16b98:password!
3f230640b78d7e71ac5514e57935eb69:qazxsw
917eb5e9d6d6bca820922a0c6f7cc28b:Pa$$word1
f6a0cb102c62879d397b12b62c092c06:bluered
```

## Current Security Status

The current system is capable of hashing passwords using MD5 hashing which means if the password given by the client follows a strong password policy. It is in theory capable of protecting the passwords against brute-force attacks due to the nature of MD5 hashing. However, in practice, users use common passwords as seen in the passwords recovery conducted. This means attacks can use publicly available wordlists or buy wordlists from the dark web to then crack the hashes within a matter of time. Through testing of the password, dump provided the tool was able to crack most passwords in under 10 seconds. In conclusion, while in theory, the current system is capable of protecting the passwords, due to a poor password policy it is susceptible to brute force attacks with minimal effort. 

## Password Policy

It is clear that the only requirement is a minimum of six digits.

---

## Frontend Suggestions (Password Policy)

The current password policy is highly discouraged as it encourages users to adopt 'easy' passwords such as 'password' leading to hashes being susceptible to simple brute-force attacks by using publicly available wordlists. This results in a situation wherein no matter how powerful the hashing if the password policy is weak the password can always be guessed. 

While different organisations adopt different password policies it is recommended to use the NIST (National Institute for Standards and Technology) guidelines. 

1. **Password length:** Minimum password length (for user-selected passwords) is 8 characters with up to 64 (or more) allowed.
2. **Password complexity (e.g. requiring at least one upper- and lowercase, numeric, and special character):** NIST recommends password complexity not be imposed.
3. **Character sets:** The recommendation is all printing ASCII and UNICODE characters be allowed.
4. **Password “hints”/authentication questions (e.g. what was your first car?):** Password hints/authentication questions shouldn’t be used.
5. **Check for “known bad” passwords:** New and changed passwords are to be checked against a list of common or previously compromised passwords (e.g. from dictionaries, previous [breaches](https://linfordco.com/blog/out-of-the-box-into-a-data-breach/), keyboard patterns, and contextual words [e.g. the user’s username]).
6. **Throttling:** Implement throttling to limit failed authentication attempts.
7. **Password expiration:** Organizations shouldn’t require users to change their password at defined intervals (e.g. 45, 60, or 90 days).
8. **Using SMS for MFA:** NIST “discourages” the use of SMS as an out-of-band authenticator and is considering removing its use in future versions of the SP 800-63 series.

## Backend Suggestions

While updating the password policy is a significant improvement it is also possible to make changes on the backend in order to make the hashing more secure in the case of a data breach. This is to apply the concept of salt in the form of MD5 Salt. 

There are two ways to do this: 

### Static Salt (Not Recommended)

The first is using a static salt, here during hashing a salt or extra string is added to the plaintext password. 

$$'123456' + 'secret' = '123456secret'$$

Here, the 'secret' string is the salt that is used, this string should be kept secret and only used in hashing and decryption. 

$$'123456'+'cDEFs8XdM'='123456cDEFs8XdM'$$

The has for which is: 

$$Md5(123456cDEFs8XdM) = 764d5a40514056152b58411008b5b609$$

This will be stored in the database, the hacker which dumps the database will not have access to the salt as it is part of the hashing system which is isolated from the database itself. 

```bash
┌──(kali㉿kali)-[~]
└─$ hashcat "764d5a40514056152b58411008b5b609" rockyou.txt
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 (Jun  8 2020 17:36:15)) - Platform #1 [Apple]
====================================================================
* Device #1: Intel(R) Core(TM) i5-5350U CPU @ 1.80GHz, skipped
* Device #2: Intel(R) Iris(TM) Graphics 6100, 1472/1536 MB (384 MB allocatable), 48MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

Host memory required for this attack: 169 MB

Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Approaching final keyspace - workload adjusted.

Session..........: hashcat
Status...........: Exhausted
Hash.Name........: MD5
Hash.Target......: 764d5a40514056152b58411008b5b609
Time.Started.....: Wed Jun 30 16:49:16 2021 (7 secs)
Time.Estimated...: Wed Jun 30 16:49:23 2021 (0 secs)
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#2.........:  2002.0 kH/s (12.61ms) @ Accel:256 Loops:1 Thr:8 Vec:1
Recovered........: 0/1 (0.00%) Digests
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#2....: $HEX[30313030363636] -> $HEX[042a0337c2a156616d6f732103]

Started: Wed Jun 30 16:49:15 2021
Stopped: Wed Jun 30 16:49:24 2021
```

As seen above, the same attack used before is unable to crack the password from the wordlist used before. 

The reason why it's not recommended is that it is possible that the hashing system itself gets reverse engineered and the static salt that is used for all the hashes get leaked which means all the extra protection from the salt is useless as the attacker can then use the salt along with a wordlist to crack the hashes like before. 

An example is listed in the project files in the `hash_pass` file.

### Dynamic Salt (Recommended)

The process is similar to static salt the difference is in the salt used. Unlike with static salt where the salt is, as the name implies, static, whereas in dynamic salt the salt is dynamically generated using the data linked to the password. 

A common way this is implemented is by using the time data the account is created which is then used to dynamically generate the salt. This means if the data needs to be decrypted the system can generate the salt by using the date the account was created. By having a data point that is  unique to each account it is possible to have a unique salt for each account. This provides an added layer of security as unlike a static salt where the leak of the salt can compromise the entire database, the hacker will have a much harder time finding the salt and then cracking the password. 

While this is a significant improvement to the original system it is important to state that this too can be reverse-engineered with enough time and resources. This is not a substitute for a strong password policy.

### Hashing Algorithm

It is important to know that the hashing algorithm used (MD5) was not designed for password hashing instead was designed for fast hashing which is contradictory to the goal of keeping information private as the same speed of hashing means its faster for attackers to crack the password as more passwords can be hashed faster. It is better to use a purpose-built algorithm like bycrypt, scrypt or PBKDF2 as it provides better security. 

## Conclusion

The current system is susceptible to simple brute-force attacks, this is demonstrated with the use of `hashcat` and the `rockyou.txt` wordlist. While the system is theoretically capable of protecting against hackers by using MD5 for hashing where the pain-text is needed to decrypt the hash, the pain-text password can be easily guessed using a wordlist such as `rockyou.txt` as the poor password policy used encouraged users to adopt poor passwords. Thus a strong password policy such as the one provided by NIST is suggested. Further password salting in the backend hashing system is suggested as even if the passwords provided by the client is weak salting the password provides an added layer of protection. Moreover, while MD5 provides some level of protection it is not purpose-built for hashing sensitive information and has many cryptographic weaknesses and has been superseded by a variety of other hash functions and its better to adopt a purpose-built algorithm like bycrypt, scrypt or PBKDF2 as it provides better security.

## Project Files

[Goldman-Sachs-Engineering-Virtual-Program](https://github.com/The-Real-Thisas/Goldman-Sachs-Engineering-Virtual-Program)

- passwd_dump.txt - Password Dump
- rockyou.txt - Wordlist
- passwords.txt - Cracked Passwords
- decrypt.py - Python Script (For Decryption)
- hash_pass - Cracking with Salt

## Tools / Referances Used:

- HashID : [https://psypanda.github.io/hashID/](https://psypanda.github.io/hashID/)
- RockYou.txt : [https://gitlab.com/kalilinux/packages/wordlists/blob/kali/master/rockyou.txt.gz](https://gitlab.com/kalilinux/packages/wordlists/blob/kali/master/rockyou.txt.gz)
- NIST Guidelines : [https://linfordco.com/blog/nist-password-policy-guidelines/](https://linfordco.com/blog/nist-password-policy-guidelines/)