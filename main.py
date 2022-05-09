def read_file(file_name):
    with open(file_name, "rb") as file:
        data = file.read()
    return data


def print_hex(data) -> str:
    return " ".join(["{:02X}".format(x) for x in data])


def handle_child(data):
    messages = []
    for i in range(len(data)):
        if data[i:i + 5] == b'\x43\x48\x49\x4C\x44':
            count = 0
            j = 0
            for j in range(i + 6, len(data)):
                if data[j:j + 1] == b'\x5B':
                    count = int(data[i + 6:j])
                    break

            for o in range(j + 1, len(data)):
                if data[o:o + 1] == b'\x5D':
                    messages.append({
                        "count": count,
                        "message": data[j + 1:o],
                    })
                    break
    return messages


def handle_master(data):
    messages = []
    for i in range(len(data)):
        if data[i:i + 6] == b'\x4D\x41\x53\x54\x45\x52':
            count = 0
            j = 0
            for j in range(i + 7, len(data)):
                if data[j:j + 1] == b'\x5B':
                    count = int(data[i + 7:j])
                    break

            for o in range(j + 1, len(data)):
                if data[o:o + 1] == b'\x5D':
                    messages.append({
                        "count": count,
                        "message": data[j + 1:o]
                    })
                    break
    return messages


def assign_command_type(messages):
    for message in messages:
        if message == {}:
            continue
        command_type = message.get("message")[11:12]
        if command_type == b'\x00':
            message["command_type"] = {"command_index": 0, "name": "Link Request"}
        elif command_type == b'\x01':
            message["command_type"] = {"command_index": 1, "name": "Link Accept"}
        elif command_type == b'\x02':
            message["command_type"] = {"command_index": 2, "name": "Link Accept and Request"}
        elif command_type == b'\x03':
            message["command_type"] = {"command_index": 3, "name": "Link Reject"}
        elif command_type == b'\x04':
            message["command_type"] = {"command_index": 4, "name": "Advertisement"}
        elif command_type == b'\x05':
            message["command_type"] = {"command_index": 5, "name": "Update"}
        elif command_type == b'\x06':
            message["command_type"] = {"command_index": 6, "name": "Update Request"}
        elif command_type == b'\x07':
            message["command_type"] = {"command_index": 7, "name": "Data Request"}
        elif command_type == b'\x08':
            message["command_type"] = {"command_index": 8, "name": "Data Response"}
        elif command_type == b'\x09':
            message["command_type"] = {"command_index": 9, "name": "Parent Request"}
        elif command_type == b'\x0A':
            message["command_type"] = {"command_index": 10, "name": "Parent Response"}
        elif command_type == b'\x0B':
            message["command_type"] = {"command_index": 11, "name": "Child ID Request"}
        elif command_type == b'\x0C':
            message["command_type"] = {"command_index": 12, "name": "Child ID Response"}
        elif command_type == b'\x0D':
            message["command_type"] = {"command_index": 13, "name": "Child Update Request"}
        elif command_type == b'\x0E':
            message["command_type"] = {"command_index": 14, "name": "Child Update Response"}
        elif command_type == b'\x0F':
            message["command_type"] = {"command_index": 15, "name": "Announce"}
        elif command_type == b'\x10':
            message["command_type"] = {"command_index": 16, "name": "Discovery Request"}
        elif command_type == b'\x11':
            message["command_type"] = {"command_index": 17, "name": "Discovery Response"}
        else:
            message["command_type"] = {"command_index": -1, "name": "Unknown command type"}
    return messages


def main():
    messages = handle_child(read_file("child.bin"))
    messages = assign_command_type(messages)
    print("Child:")
    for message in messages:
        print("{}: {}".format(message.get("count"), message.get("command_type")))
    messages = handle_master(read_file("master2.bin"))
    messages = assign_command_type(messages)

    print("Master:")
    for message in messages:
        print("{}: {}".format(message.get("count"), message.get("command_type")))


def extract_link_messages():
    child_messages = handle_child(read_file("child.bin"))
    master_messages = handle_master(read_file("master.bin"))

    child_messages = assign_command_type(child_messages)
    master_messages = assign_command_type(master_messages)

    link_messages = []
    for index, message in enumerate(master_messages):
        if message.get("command_type")["command_index"] in [0, 1, 2, 3]:
            link_messages.append(message)
        if child_messages[index].get("command_type")["command_index"] in [0, 1, 2, 3]:
            link_messages.append(child_messages[index])

    with open("link_messages.bin", "wb") as f:
        for m in link_messages:
            f.write(m.get("message"))


def parse_message(msg, res=None) -> list:
    # The message can have several TLV's and we'll return a list of all TLV's in the message.
    if res is None:
        res = []
    if msg == b'':
        return res
    type_loc = 0
    length_loc = 1
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
    return parse_message(msg[tlv_length + 2:], res)


if __name__ == '__main__':
    _msgs = handle_master(read_file("dd.bin"))
    _msgs = assign_command_type(_msgs)

    print("Master:")
    for _msg in _msgs:
        print("{}: {}".format(_msg.get("count"), _msg.get("command_type").get("name")))
        for tlv in parse_message(_msg.get("message")[12:]):
            pass
            print("\t{}: {}".format(tlv.get("type"), print_hex(tlv.get("value"))))
        # Print the complete message, as binary
        print("\t" + print_hex(_msg.get("message")))
