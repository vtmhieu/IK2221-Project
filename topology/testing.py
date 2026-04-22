import topology


def ping(client, server, expected, count=1, wait=1):

    server_ip = server.IP() if not isinstance(server, str) else server
    
    # What if ping fails? How long does it take? Add a timeout to the command!
    cmd = f"ping {server_ip} -c {count} -W {wait}  >/dev/null 2>&1; echo $?"
    ret = client.cmd(cmd).strip()
    
    # Here you should compare the return value "ret" with the expected value
    # (consider both failures
    is_success = (ret == "0")

    if is_success != expected:
        print(f"Ping failed: expected {expected}, got {is_success}")
        return False

    return True


def curl(client, server, method="GET", payload="", port=80, expected=True):
        """
        run curl for HTTP request. Request method and payload should be specified
        Server can either be a host or a string
        return True in case of success, False if not
        """

        if (isinstance(server, str) == 0):
            server_ip = str(server.IP())
        else:
            # If it's a string it should be the IP address of the node (e.g., the load balancer)
            server_ip = server
        
        # Pass some payload (a.k.a. data). You may have to add some escaped quotes!
        data_flag = f"-d '{payload}'" if payload else ""
        
        # Specify HTTP method using -X. And change server into server_ip
        # The magic string at the end reditect everything to the black hole and just print the return code
        cmd = f"curl -X {method} {data_flag} --connect-timeout 3 --max-time 3 -s {server_ip}:{port} > /dev/null 2>&1; echo $?"
        
        # Convert the return value to an integer for comparison
        ret = client.cmd(cmd).strip()
        print(f"`{cmd}` on {client} returned {ret}")

        is_success = (ret == "0")
        return is_success == expected
