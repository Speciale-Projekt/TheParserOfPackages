import pathlib

# MAGIC VARIABLES

child_addr = b"fe80:0:0:0:588a"
master_addr = b"fe80:0:0:0:243a"
multi_cast = b"ff02:0:0:0:0:0:"
child_determiner = b'\x43\x48\x49\x4C\x44'
master_determiner = b'\x4D\x41\x53\x54\x45\x52'


def read_file(file_name: pathlib.Path) -> str:
    """Open file as binary and return the data."""
    with open(file_name, "rb") as file:
        data = file.read()
    return data


def print_hex(data: bin) -> str:
    """Print a string as hexadecimal."""
    return " ".join(["{:02X}".format(x) for x in data])


def handle_messages(data: bin, determ: bin) -> list:
    """
    Parse the data and return a dictionary with the messages.
    :param data: binary data to parse
    :param determ: determinator to look for new messages
    :return: list of dictionary with the following: {count: int, destination: bin, message: bin}
    """
    messages = []
    for i in range(len(data)):
        if data[i:i + len(determ)] == determ:
            q = j = count = 0
            dest_addr = None

            for j in range(i + len(determ) + 1, len(data)):
                if data[j:j + 1] == b'\x3A':
                    count = int(data[i + len(determ) + 1:j])
                    break
            for q in range(j + 1, len(data)):
                if data[q:q + 1] == b'\x5B':
                    dest_addr = data[j + 1:q]
                    break

            for o in range(q + 1, len(data)):
                if data[o:o + 1] == b'\x5D':
                    messages.append({
                        "destination": dest_addr,
                        "count": count,
                        "message": data[q + 1:o]
                    })
                    break
    return messages


def assign_command_type(message: bin, res=None) -> list:
    """
    Assign the command type and the TLV names to the message.
    :param message:
    :return: command and tlvs
    """

    if res is None:
        res = []
    if message == b'':
        return res
    if message[0:1] == b'\xFF':
        command_type = message[1:2]
        next_message_index, tlvs = get_tlvs(message[2:])
        if next_message_index is not None:
            next_message_index += 2
    else:
        command_type = message[11:12]
        next_message_index, tlvs = get_tlvs(message[12:])
        if next_message_index is not None:
            next_message_index += 12
    if command_type == b'\x00':
        command = {"command_index": 0, "name": "Link Request"}
    elif command_type == b'\x01':
        command = {"command_index": 1, "name": "Link Accept"}
    elif command_type == b'\x02':
        command = {"command_index": 2, "name": "Link Accept and Request"}
    elif command_type == b'\x03':
        command = {"command_index": 3, "name": "Link Reject"}
    elif command_type == b'\x04':
        command = {"command_index": 4, "name": "Advertisement"}
    elif command_type == b'\x05':
        command = {"command_index": 5, "name": "Update"}
    elif command_type == b'\x06':
        command = {"command_index": 6, "name": "Update Request"}
    elif command_type == b'\x07':
        command = {"command_index": 7, "name": "Data Request"}
    elif command_type == b'\x08':
        command = {"command_index": 8, "name": "Data Response"}
    elif command_type == b'\x09':
        command = {"command_index": 9, "name": "Parent Request"}
    elif command_type == b'\x0A':
        command = {"command_index": 10, "name": "Parent Response"}
    elif command_type == b'\x0B':
        command = {"command_index": 11, "name": "Child ID Request"}
    elif command_type == b'\x0C':
        command = {"command_index": 12, "name": "Child ID Response"}
    elif command_type == b'\x0D':
        command = {"command_index": 13, "name": "Child Update Request"}
    elif command_type == b'\x0E':
        command = {"command_index": 14, "name": "Child Update Response"}
    elif command_type == b'\x0F':
        command = {"command_index": 15, "name": "Announce"}
    elif command_type == b'\x10':
        command = {"command_index": 16, "name": "Discovery Request"}
    elif command_type == b'\x11':
        command = {"command_index": 17, "name": "Discovery Response"}
    else:
        command = {"command_index": -1, "name": "Unknown command type"}
    res.append({**command, **{"tlvs": tlvs}, **{"total_message": print_hex(message[0:next_message_index])}})
    if next_message_index is not None:
        return assign_command_type(message[next_message_index:], res)
    else:
        return res


def get_tlvs(msg: bin, next_index=0, res=None) -> (int, list):
    """
    Parse the message and return a list of TLVs.
    :param next_index: the index of the next message
    :param msg: binary TLV data
    :param res: list of TLVs. Initialized to none
    :return: list of all TlVs in the message
    """
    # The message can have several TLV's and we'll return a list of all TLV's in the message.
    type_loc = 0
    length_loc = 1
    if res is None:
        res = []
    if msg == b'':
        return None, res
    if msg[0:1] == b'\xFF' or msg[0:2] == b'\x00\x15':
        return next_index, res
    if msg[type_loc] == 0:
        # Source Address TLV
        tlv_type = "Source Address TLV"
    elif msg[type_loc] == 1:
        # Mode TLV
        tlv_type = "Mode TLV"
    elif msg[type_loc] == 2:
        # Timeout TLV
        tlv_type = "Timeout TLV"
    elif msg[type_loc] == 3:
        # Challenge TLV
        tlv_type = "Challenge TLV"
    elif msg[type_loc] == 4:
        # Response TLV
        tlv_type = "Response TLV"
    elif msg[type_loc] == 5:
        # Link-layer Frame Counter TLV
        tlv_type = "Link-layer Frame Counter TLV"
    elif msg[type_loc] == 6:
        # Link Quality TLV
        tlv_type = "Link Quality TLV"
    elif msg[type_loc] == 7:
        # Network Parameter TLV
        tlv_type = "Network Parameter TLV"
    elif msg[type_loc] == 8:
        # MLE Frame Counter TLV
        tlv_type = "MLE Frame Counter TLV"
    elif msg[type_loc] == 9:
        # Route64 TLV
        tlv_type = "Route64 TLV"
    elif msg[type_loc] == 10:
        # Address16 TLV
        tlv_type = "Address16 TLV"
    elif msg[type_loc] == 11:
        # Leader Data TLV
        tlv_type = "Leader Data TLV"
    elif msg[type_loc] == 12:
        # Network Data TLV
        tlv_type = "Network Data TLV"
    elif msg[type_loc] == 13:
        # TLV Request TLV
        tlv_type = "TLV Request TLV"
    elif msg[type_loc] == 14:
        # Scan Mask TLV
        tlv_type = "Scan Mask TLV"
    elif msg[type_loc] == 15:
        # Connectivity TLV
        tlv_type = "Connectivity TLV"
    elif msg[type_loc] == 16:
        # Link Margin TLV
        tlv_type = "Link Margin TLV"
    elif msg[type_loc] == 17:
        # Status TLV
        tlv_type = "Status TLV"
    elif msg[type_loc] == 18:
        # Version TLV
        tlv_type = "Version TLV"
    elif msg[type_loc] == 19:
        # Address Registration TLV
        tlv_type = "Address Registration TLV"
    elif msg[type_loc] == 20:
        # Channel TLV
        tlv_type = "Channel TLV"
    elif msg[type_loc] == 21:
        # PAN ID TLV
        tlv_type = "PAN ID TLV"
    elif msg[type_loc] == 22:
        # Active Timestamp TLV
        tlv_type = "Active Timestamp TLV"
    elif msg[type_loc] == 23:
        # Pending Timestamp TLV
        tlv_type = "Pending Timestamp TLV"
    elif msg[type_loc] == 24:
        # Active Operational Dataset TLV
        tlv_type = "Active Operational Dataset TLV"
    elif msg[type_loc] == 25:
        # Pending Operational Dataset TLV
        tlv_type = "Pending Operational Dataset TLV"
    elif msg[type_loc] == 26:
        # Thread Discovery TLV
        tlv_type = "Thread Discovery TLV"
    else:
        tlv_type = "Unknown TLV"
    tlv_length = msg[length_loc]
    tlv_value = msg[length_loc + 1:2 + tlv_length]
    res.append({"type": tlv_type, "length": tlv_length, "value": tlv_value})

    next_index += tlv_length + 2

    return get_tlvs(msg[tlv_length + 2:], next_index, res)


def print_parsed_message(file: pathlib.Path, msg: dict) -> None:
    """Just a simple print utility."""
    print(f"{file.name[:-4].capitalize()}:")
    for _msg in msg:
        if _msg.get("destination") == child_addr:
            dest = "Child"
        elif _msg.get("destination") == master_addr:
            dest = "Master"
        elif _msg.get("destination") == multi_cast:
            dest = "Multicast"
        else:
            dest = _msg.get("destination")
        print("\t{}: {} - Send to {}".format(_msg.get("count"), _msg.get("command_type").get("name"), dest))
        for tlv in _msg.get("tlvs"):
            print("\t\t{}: {}".format(tlv.get("type"), print_hex(tlv.get("value"))))
        # Print the complete message, as binary
        print("\t" + print_hex(_msg.get("message")))


if __name__ == '__main__':
    bb_file = pathlib.Path("test.bin")
    bb_msg = assign_command_type(read_file(bb_file))
    for msg in bb_msg:
        print(msg["name"])
        print(msg["total_message"])
        print()
