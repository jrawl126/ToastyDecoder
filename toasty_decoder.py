#!/usr/bin/env python3

header = """
 _____               _                   
|_   _|__   __ _ ___| |_ _   _           ▓▓▓▓▓▓    ▓▓▓▓▓▓ 
  | |/ _ \ / _` / __| __| | | |        ▓▓░░░░░░▓▓▓▓░░░░░░▓▓
  | | (_) | (_| \__ \ |_| |_| |      ▓▓░░░░░░░░░░░░░░░░░░░░▓▓      
  |_|\___/ \__,_|___/\__|\__, |      ▓▓░░░░██  ░░░░██  ░░░░▓▓
    SunBurst DGA Decoder |___/       ▓▓░░░░████░░░░████░░░░▓▓   
            _   ___                    ▓▓░░░░░░░░░░░░░░░░▓▓
   __   __ / | / _ \                   ▓▓░░░░░░░░░░░░░░░░▓▓
   \ \ / / | || | | |                  ▓▓░░░░░░░░░░░░░░░░▓▓
    \ V /  | || |_| |                  ▓▓░░░░░░░░░░░░░░░░▓▓
     \_/   |_(_)___/                   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ 

Cyber Toaster: Incident Response Track 2021
Authors: Simon Bruklich, Charles Glass, Charlie Harper, Zach Leggett, John Rawley
Usage: ./toasty_decoder.py -i file1 file2 file3 ... -o out.csv   
"""                                                                                                                                                                                         

import base64, datetime, csv, sys, argparse
#base_32_decode written by "QiAnXin_RedDrip"
def base_32_decode(string):
    text = "ph2eifo3n5utg1j8d94qrvbmk0sal76c"
    restring = ""
    datalen = (len(string) * 5) // 8
    num = 0
    ib = 0
    if len(string) < 3:
        restring = chr(text.find(string[1]) | text.find(string[1]) << 5 & 255)
        return restring
    k = text.find(string[0]) | (text.find(string[1]) << 5)
    j = 10
    index = 2
    for i in range(int(datalen)):
        restring += chr(k & 255)
        k = k >> 8
        j -= 8
        while( j < 8 and index < len(string)):
            k |= (text.find(string[index]) << j)
            index += 1
            j += 5
    return restring

class SubstitutionCipher:
    def __init__(self, pt, ct):
        self.encode_trans = str.maketrans(pt, ct)
        self.decode_trans = str.maketrans(ct, pt)

    def encode(self, s):
        return s.translate(self.encode_trans)
    
    def decode(self, s):
        return s.translate(self.decode_trans)

#If a character in the EscapeAlphabet is in the plaintext, the DgaEscapeCipher 
#is used to decode the ciphertext. This is indicated in the ciphertext by a 0.
EscapeAlphabet = "0-_."

DgaSubstitutionCipher = SubstitutionCipher(
    "rq3gsalt6u1iyfzop572d49bnx8cvmkewhj",
    "salt6u1iyfzop572d49bnx8cvmkewhjrq3g",
)
DgaEscapeCipher = SubstitutionCipher(
    "0-_.0-_.0-_.0-_.0-_.0-_.0-_.0-_.0-_",
    "salt6u1iyfzop572d49bnx8cvmkewhjrq3g",
)

#Decodes data with the substitution cipher
def dga_subst_decode(text):
    ct = ""
    escape = 0
    for c in text:
        if escape == 1:
            escape = 0
            ct += DgaEscapeCipher.decode(c)
        elif c in EscapeAlphabet:
            escape = 1
        else:
            ct += DgaSubstitutionCipher.decode(c)
    return ct

def check_service(bit, shift):
    running = "running" if bit & 0b00000010 << shift else "not running"
    stopped = "stopped" if bit & 0b00000001 << shift else "not stopped"
    return [running, stopped]

#Gets running and stopped status for select services
def decode_message(b):
    services = {"Windows Live OneCare / Windows Defender":'n/a', "Windows Defender Advanced Threat Protection": 'n/a', "Microsoft Defender for Identity": 'n/a', "Carbon Black": 'n/a', "CrowdStrike": 'n/a', "FireEye": 'n/a', "ESET": 'n/a', "F-Secure":'n/a'}
    if b == None:
        return services
    LSB = b[1]
    MSB = b[0]
    running = 0
    stopped = 0
    if int(LSB, 16) & 0b00000011:
        service="Windows Live OneCare / Windows Defender"
        services[service]=check_service(int(LSB, 16),0)
    if int(LSB, 16) & 0b00001100:
        service="Windows Defender Advanced Threat Protection"
        services[service]=check_service(int(LSB, 16),2)
    if int(LSB, 16) & 0b00110000:
        service="Microsoft Defender for Identity"
        services[service]=check_service(int(LSB, 16),4)  
    if int(LSB, 16) & 0b11000000:
        service="Carbon Black"
        services[service]=check_service(int(LSB, 16),6)  
    if int(MSB, 16) & 0b00000011:
        service="CrowdStrike"
        services[service]=check_service(int(MSB, 16),0)
    if int(MSB, 16) & 0b00001100:
        service="FireEye"
        services[service]=check_service(int(MSB, 16),2)  
    if int(MSB, 16) & 0b00110000:
        service="ESET"
        services[service]=check_service(int(MSB, 16),4)     
    if int(MSB, 16) & 0b11000000:
        service="F-Secure"
        services[service]=check_service(int(MSB, 16),6)   
    return services

#Converts hex timestamp to datetime class, where hex_timestamp is the number of 
#15 minute chunks since 01/01/2010.
def get_timestamp(hex_timestamp):
    dec = int(hex_timestamp, 16)
    date_and_time = datetime.datetime(2010, 1, 1, 0, 0, 0)
    time_change = datetime.timedelta(minutes=(dec * 15))
    new_time = date_and_time + time_change
    return new_time

#Outputs results to out.csv file
def write_results(results, output):
    fields = ['Filename', 'Line no.', 'Line', 'GUID', 'Domain', 'sequence', 'Ping', 'Timestamp', "Windows Live OneCare / Windows Defender", "Windows Defender Advanced Threat Protection", "Microsoft Defender for Identity", "Carbon Black", "CrowdStrike", "FireEye", "ESET", "F-Secure"]
    with open(output, 'w', newline='', encoding="utf-8") as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(fields)
        for row in results:
            csvwriter.writerow(row)

#Checks the array found to see if an ID has been recorded. Returns True if ID
#is not found
def is_new_userid(id, found):
    for item in found:
        if item[0] == id:
            return False
    return True

#Returns the index of a specified ID in the found array. If not found returns -1
def get_index(id, found):
    i = 0
    for item in found:
        if item[0] == id:
            return i
        i +=1
    return -1       

#Checks end of a passed in domain for matches to known used domains specified in 
#URLS. Returns True if submain is more then 16 character and ends with known 
#domain
def get_sequence_number(domain):
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    dotparts = domain.split('.')
    enc_seq_num = dotparts[0][15:16]
    seq_num = ord(dotparts[0][0]) % len(alphabet) - alphabet.find(enc_seq_num)
    return seq_num

#For multi-part messages, returns the sequence number of that message, with 0 
#being the first part of the message, and 1 being the second. Negative sequence 
#numbers are indicative of other encoded data (i.e. not a domain). 
def is_valid_url(domain):
    URLS = ["appsync-api.us-west-2.avsvmcloud.com", "appsync-api.us-east-2.avsvmcloud.com", "appsync-api.us-east-1.avsvmcloud.com", "appsync-api.eu-west-1.avsvmcloud.com"]
    domain.strip()
    dotparts = domain.split('.')
    if len(dotparts[0]) < 16:
        return False
    if not any(domain.endswith(url) for url in URLS):
        return False
    if any(domain.replace(url,'',1).endswith(url) for url in URLS):
        return False
    return True

def main():
    parser = argparse.ArgumentParser(description=header, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "-i",
        "--input",
        type=str,
        default=None,
        required=True,
        help="input files to be decoded",
        nargs='*',
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        required=True,
        help="output csv file with decoded data",
    )
    args = parser.parse_args()

    lineno = 0
    results = []
    history = [] #first entry is user id, second is msg 0, third is msg 1 
    for f in args.input:
        for line in open(f):
            lineno += 1
            line = line.strip()
            dotparts = line.split(".")
            decoded = ''

            if not is_valid_url(line):
                line_results = [str(f), str(lineno), 'UNKNOWN DOMAIN PATTERN: '+str(line)] + ['n/a']*13
                results.append(line_results)
                continue   

            domain = dotparts[0][16:]
            ping = False
            svcs = decode_message(None)
            GUID = ''
            timestamp = 'n/a'

            NUM = get_sequence_number(line)
            if NUM == 1 or NUM == 0:
            #Decode the first 16 bytes of data
                ENC_GUID = base_32_decode(dotparts[0][:15]).encode('raw_unicode_escape') # 9 Byte Array
                KEY = ENC_GUID[0]
                ENC_GUID = ENC_GUID[1:]
                for i in range(len(ENC_GUID)):
                    GUID += str(hex(int(ENC_GUID[i]) ^ int(KEY))).replace('0x', '').ljust(2, '0')

                if is_new_userid(GUID, history):
                    if NUM == 0:
                        history.append([GUID,domain,0])
                    elif NUM == 1:
                        history.append([GUID,0,domain])
                else:
                    index = get_index(GUID, history)
                    history[index][1+NUM] = domain

            else: # GetNextStringEx
                decoded = base_32_decode(dotparts[0]).encode('raw_unicode_escape')
                if len(decoded) >= 12:
                    KEY = decoded[0] # first key
                    decoded = decoded[1:]
                    DECODE_one = []
                    for j in range(len(decoded)):
                        DECODE_one.append(hex(int(decoded[j]) ^ int(KEY)))

                    KEY = DECODE_one[9:11] #second key
                    for j in range(0, 8):
                        GUID += str(hex(int(DECODE_one[j], 16) ^ int(KEY[(j+1) % len(KEY)], 16))).replace('0x', '').ljust(2, '0')

                    code_len = int(DECODE_one[8], 16) // 0x10 #0x25 // 0x10 -> 2
                    
                    if code_len == 1 or code_len == 0:
                        ping = True
                    elif code_len == 2:
                        svcs = decode_message(DECODE_one[-2:])
                    else:
                        svc = decode_message(DECODE_one[-2:])
                    
                    timestamp = "0x" + DECODE_one[8][-1] + DECODE_one[9][2:].ljust(2, '0') + DECODE_one[10][2:].ljust(2, '0')
                    timestamp = get_timestamp(timestamp)

                else:
                    line_results = [str(f), str(lineno), 'PAYLOAD LESS THAN 12 BYTES: '+str(line)] + ['n/a']*13
                    results.append(line_results)
                    continue

            if NUM == 1:
                index = get_index(GUID, history)
                if history[index][1] != 0:
                        domain = history[index][1] + domain
            if NUM == 0:
                index = get_index(GUID, history)
                if history[index][2] != 0:
                        domain = domain + history[index][2]
            line_results = []
            if domain[0:2] == '00':
                decoded = base_32_decode(domain[2:])
            else:
                decoded = dga_subst_decode(domain)

            line_results = [str(f), str(lineno), str(line), GUID, str(decoded), str(NUM), ping,'{}'.format(timestamp)]
            for key, val in svcs.items():
                line_results.append(str(val))
            results.append(line_results) 

    results.sort(key=lambda x: x[7])
    results.sort(key=lambda x: x[3])
    write_results(results, args.output)
    print(header)
    print("Successfully Removed the Crust from SunBurst")
    
if __name__ == "__main__":
    main()