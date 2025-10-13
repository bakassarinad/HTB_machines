import sys
import struct
#Modify the SID hex value retrieved from query 
def prepare_sid(sid = '0x0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000'):
    hex_string = bytes.fromhex(sid[2:])
    mod_sid = sid_to_str(hex_string)
    domain_sid_data = mod_sid.split('-')[:7]
    domain_sid = '-'.join(domain_sid_data) + "-"

    print(domain_sid+"\n")
    return domain_sid

#Build out the SID string
def sid_to_str(sid = '0x0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000'):
    if sys.version_info.major < 3:
        revision = ord(sid[0])
    else:
        revision = sid[0]

    if sys.version_info.major < 3:
        number_of_sub_ids = ord(sid[1])
    else:
        number_of_sub_ids = sid[1]
    iav = struct.unpack('>Q', b'\x00\x00' + sid[2:8])[0]
    sub_ids = [struct.unpack('<I', sid[8 + 4 * i:12 + 4 * i])[0]
               for i in range(number_of_sub_ids)]

    return 'S-{0}-{1}-{2}'.format(revision, iav, '-'.join([str(sub_id) for sub_id in sub_ids]))

if __name__ == "__main__":
    print(sid_to_str())