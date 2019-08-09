#! /usr/bin/env python3
if True: # imports    
    import io ##
    import os
    import sys
    from netmiko import Netmiko, ConnectHandler
    import datetime
    from datetime import date
    from dateutil import parser
    import time
    import json
if True: # set json variables
    with open('cert-renew_xe_test.json') as f:
        js = json.load(f)
        device_ip           = js['DEVICE_IP']
        device_username     = js['DEVICE_UN']
        device_password     = js['DEVICE_PWD']
if True: # set local variables
    now = datetime.datetime.now()
    month = '{:02d}'.format(now.month)
    day = '{:02d}'.format(now.day)
    date_format = f'{now.year}{month}{day}'
    todays_date = now
if True: # define device dictionary
    device = {
        'host': device_ip,
        'username': device_username,
        'password': device_password,
        'device_type': 'cisco_xe'
    }
if True: # define date normalize function
    def norm_date(n):
        normalized_date = parser.parse(n)
        yr = int(normalized_date.strftime("%Y"))
        mo = int(normalized_date.strftime("%m"))
        d = int(normalized_date.strftime("%d"))
        normalized_date = date(yr, mo, d)
        return normalized_date
if True: # define get cert 'valid to' date function
    def cert_valid_to(tp):
        with ConnectHandler(**device) as channel:
            cmd = f'show crypto pki certificates {tp}'
            output = channel.send_command(cmd)
            output_lines = output.splitlines()            
        
            for idx, val in enumerate(output_lines):
                if f"Name: {hostname}" in val:
                    start_index = output_lines.index(val)
                    idx = idx
                elif "CA Certificate" in val:
                    end_index = output_lines.index(val)

            cert = output_lines[start_index:end_index]
            valid_to = []

            for i in cert:
                if "end" in i and "date" in i:
                    valid_to.append(i)
            
            # handle trustpoint with multiple host certs created
            while len(valid_to) > 1:
                valid_to.pop()

            v_str = str(valid_to).strip('[]').strip("'")
            v_str = v_str.replace(":", "")
            v_list = v_str.split()
            valid_to_date = []

            for idx, val in enumerate(v_list):
                if 'end' in val or 'date' in val or 'UTC' in val or len(val) > 4:
                    pass
                else:
                    valid_to_date.append(val)

            valid_to_date = str(valid_to_date).strip('[]').strip("'").strip(",")
            return valid_to_date
        
        channel.disconnect()
if True: # define get certificate serial number function
    def cert_sn(tp):
        with ConnectHandler(**device) as channel:
            cmd = f'show crypto pki certificates {tp}'
            output = channel.send_command(cmd)
            output_lines = output.splitlines()            
        
            for idx, val in enumerate(output_lines):
                if val == 'Certificate':
                    start_index = output_lines.index(val)
                    idx = idx
                elif f"Name: {hostname}" in val:
                    end_index = output_lines.index(val)
                    
            serial_sec = output_lines[start_index:end_index]
            sn = []

            for i in serial_sec:
                if "Certificate Serial Number" in i:
                    sn.append(i)
            
            sn_str = str(sn).strip('[]').strip("'")
            sn_list = sn_str.split()
            ser_num = []

            for val in sn_list:
                if len(val) > 15:
                    ser_num.append(val)

            def split(word):
                return [character for character in word]

            ser_num_str = str(ser_num).strip('[]').strip("'")
            ser_num_split = split(ser_num_str)
            ser_num_l4_list = []
            ser_num_l4_list.append(ser_num_split[-4:])
            ser_num_str = str(ser_num_l4_list).strip('[]').strip("'")
            ser_num_str = ser_num_str.replace(" ", "").replace(",", "").replace("'", "")

            return ser_num_str

        channel.disconnect()
if True: # get hostname and trustpoint, check existing cert expiry date, re-enroll cert
    with ConnectHandler(**device) as channel:
        print('Getting Hostname...')
        output = channel.find_prompt()
        chars = []
        blank_string = ""

        for c in output:
            chars.append(c)
        
        for idx, char in enumerate(chars):
            if '#' in char:
                chars.pop(idx)
        
        hostname = blank_string.join(chars)
        
        print('Getting TrustPoint...')
        cmd1 = '\n'
        cmd2 = 'show run | i trustpoint'
        channel.send_command(cmd1)
        output = channel.send_command(cmd2)
        output_lines = output.splitlines()
        elements = []

        for e in output_lines:
            if "crypto" in e and "self-signed" not in e:
                elements.append(e)
        
        e_str = str(elements).strip('[]').strip("'")
        e_list = e_str.split()
        trustpoint = []

        for e in e_list:
            if "crypto" not in e and "pki" not in e and "trustpoint" not in e:
                trustpoint.append(e)
        
        trustpoint = str(trustpoint).strip('[]')
        if "'" in trustpoint:
            trustpoint = trustpoint.replace("'", "")
        
        print("Getting certificate 'valid to' date...")        
        valid_until = cert_valid_to(trustpoint)
        valid_until = norm_date(valid_until)
        todays_date = str(todays_date)
        todays_date = norm_date(todays_date)
        delta = valid_until - todays_date
        days_rem = delta.days

        #if days_rem > 30:
        #    print(f"There are {days_rem} days remaining before certificate expiration.")
        #    print("Exiting script...")
        #    sys.exit()
        
        print(f"There are {days_rem} days remaining before expiration of existing certificate.")
        print("Re-enrolling certificate...")
        channel.send_command('\n')
        channel.send_command_timing('config t')
        cmd3 = f'crypto pki enroll {trustpoint}'
        output = channel.send_command_timing(cmd3, strip_command=False, strip_prompt=False)

        while '#' not in output:
            output = output

            if 'Do you want to continue with re-enrollment?' in output:        
                output += channel.send_command_timing('yes', strip_command=False, strip_prompt=False)
            if 'Password' in output:
                output += channel.send_command_timing('\n', strip_command=False, strip_prompt=False)
            if 'Re-enter' in output:
                output += channel.send_command_timing('\n', strip_command=False, strip_prompt=False)  
            if 'Request certificate from CA?' in output:
                output += channel.send_command_timing('yes', strip_command=False, strip_prompt=False)
            else:
                output += channel.send_command('\n')
        
        channel.send_command_timing('end')
        print("Saving configuration...")
        channel.save_config()
        channel.disconnect() 
if True: # confirm new certificate start and end dates
    print("Validating new confguration...")
    new_valid_until = cert_valid_to(trustpoint)
    new_valid_until = norm_date(new_valid_until)
    new_delta = new_valid_until - todays_date
    new_days_rem = new_delta.days

    serial_number = cert_sn(trustpoint)
    print(f"There are now {new_days_rem} days remaining before certificate expiration.")
    print(f"The new certificate serial number ends in '{serial_number}'.")
    print()
    print("Remember to revoke the OLD certificate on the CA!")
    sys.exit()