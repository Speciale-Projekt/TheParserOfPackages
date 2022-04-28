def read_file(file_name):
    with open(file_name, "rb") as file:
        data = file.read()
    return data


def handle_child(data):
    messages = []
    for i in range(len(data)):
        if data[i:i + 5] == b'\x43\x48\x49\x4C\x44':
            count = 0
            for j in range(i+6, len(data)):
                if data[j:j + 1] == b'\x5B':
                    count = int(data[i + 6:j])
                    break

            for o in range(j + 1, len(data)):
                if data[o:o + 1] == b'\x5D':
                    messages.append({
                        "count": count,
                        "message": data[j:o]
                    })
                    break
    return messages


def handle_master(data):
    messages = []
    for i in range(len(data)):
        if data[i:i + 6] == b'\x4D\x41\x53\x54\x45\x52':
            count = 0
            for j in range(i+7, len(data)):
                if data[j:j + 1] == b'\x5B':
                    count = int(data[i + 7:j])
                    break

            for o in range(j + 1, len(data)):
                if data[o:o + 1] == b'\x5D':
                    messages.append({
                        "count": count,
                        "message": data[j:o]
                    })
                    break
    return messages


def assign_command_type(messages):
    for message in messages:
        if message == {}:
            continue
        command_type = message.get("message")[12:13]
        if command_type == b'\x00':
            message["command_type"] = "Link Request"
        elif command_type == b'\x01':
            message["command_type"] = "Link Accept"
        elif command_type == b'\x02':
            message["command_type"] = "Link Accept and Request"
        elif command_type == b'\x03':
            message["command_type"] = "Link Reject"
        elif command_type == b'\x04':
            message["command_type"] = "Advertisement"
        elif command_type == b'\x05':
            message["command_type"] = "Update"
        elif command_type == b'\x06':
            message["command_type"] = "Update Request"
        elif command_type == b'\x07':
            message["command_type"] = "Data Request"
        elif command_type == b'\x08':
            message["command_type"] = "Data Response"
        elif command_type == b'\x09':
            message["command_type"] = "Parent Request"
        elif command_type == b'\x0A':
            message["command_type"] = "Parent Response"
        elif command_type == b'\x0B':
            message["command_type"] = "Child ID Request"
        elif command_type == b'\x0C':
            message["command_type"] = "Child ID Response"
        elif command_type == b'\x0D':
            message["command_type"] = "Child Update Request"
        elif command_type == b'\x0E':
            message["command_type"] = "Child Update Response"
        elif command_type == b'\x0F':
            message["command_type"] = "Announce"
        elif command_type == b'\x10':
            message["command_type"] = "Discovery Request"
        elif command_type == b'\x11':
            message["command_type"] = "Discovery Response"
        else:
            message["command_type"] = "Unknown command type"
    return messages


def main():
    messages = handle_child(read_file("child.bin"))
    messages = assign_command_type(messages)
    print("Child:")
    for message in messages:
        print("{}: {}".format(message.get("count"), message.get("command_type")))
    messages = handle_master(read_file("master.bin"))
    messages = assign_command_type(messages)

    print("Master:")
    for message in messages:
        print("{}: {}".format(message.get("count"), message.get("command_type")))


if __name__ == '__main__':
    main()
