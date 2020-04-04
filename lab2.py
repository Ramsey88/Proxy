import sys
import os
import enum
import socket
import _thread

class HttpRequestInfo(object):
    """
    Represents a HTTP request information
    Since you'll need to standardize all requests you get
    as specified by the document, after you parse the
    request from the TCP packet put the information you
    get in this object.
    To send the request to the remote server, call to_http_string
    on this object, convert that string to bytes then send it in
    the socket.
    client_address_info: address of the client;
    the client of the proxy, which sent the HTTP request.
    requested_host: the requested website, the remote website
    we want to visit.
    requested_port: port of the webserver we want to visit.
    requested_path: path of the requested resource, without
    including the website name.
    NOTE: you need to implement to_http_string() for this class.
    """

    def __init__(self, client_info, method: str, requested_host: str,
                 requested_port: int,
                 requested_path: str,
                 headers: list):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host ## the requested website
        self.requested_port = requested_port ## port of the website
        self.requested_path = requested_path

        # Headers will be represented as a list of lists
        # for example ["Host", "www.google.com"]
        # if you get a header as:
        # "Host: www.google.com:80"
        # convert it to ["Host", "www.google.com"] note that the
        # port is removed (because it goes into the request_port variable)
        self.headers = headers
    def to_http_string(self):
        """
        Convert the HTTP request/response
        to a valid HTTP string.
        As the protocol specifies:
        [request_line]\r\n
        [header]\r\n
        [headers..]\r\n
        \r\n
        (just join the already existing fields by \r\n)
        You still need to convert this string
        to byte array before sending it to the socket,
        keeping it as a string in this stage is to ease
        debugging and testing.
        """
        String = self.method +" "+str(self.requested_path)+" "+ "HTTP/1.0"+"\r\n"
        for x in range (0,len(self.headers)):
            for y in range (0,len(self.headers[x])):
                head=str(self.headers[x][y])+":"+" "+str(self.headers[x][-1])+"\r\n"
                String += head
                break;
        String += "\r\n"
        print("*" * 50)
        print("[to_http_string] Implement me!")
        print("*" * 50)
        return String

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        print(f"Path:", self.requested_path)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """

    def __init__(self, code, message):
        self.code = code
        self.message = message
    def to_http_string(self):
        """ Same as above """
        string = self.message+" "+"("+str(self.code)+")"
        return string

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(self.to_http_string())


class HttpRequestState(enum.Enum):
    """
    The values here have nothing to do with
    response values i.e. 400, 502, ..etc.
    Leave this as is, feel free to add yours.
    """
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1


def entry_point(proxy_port_number):
    """
    Entry point, start your code here.
    Please don't delete this function,
    but feel free to modify the code
    inside it.
    """
    setup_sockets(proxy_port_number)
    print("*" * 50)
    print("[entry_point] Implement me!")
    print("*" * 50)
    return None


def setup_sockets(proxy_port_number):
    print("Starting HTTP proxy on port:", proxy_port_number)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # intializing a TPC socket
    s.bind(('127.0.0.1',proxy_port_number))
    hash_table = {}
    while 1:
        s.listen(4096)
        conn, addr = s.accept()
        _thread.start_new_thread(socket_logic,(conn, addr, hash_table),)
    print("*" * 50)
    print("[setup_sockets] Implement me!")
    print("*" * 50)



def socket_logic(conn,addr,hash_table):
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.
    Feel free to delete this function.
    """
    raw_data = ""
    count = 0
    while 1:
        data = conn.recv(1024).decode()
        if data == "\r\n":
            if count == 1:
                break
            count += 1
        else:
            count = 0
        raw_data += data
    request_info = http_request_pipeline(addr, raw_data)
    if type(request_info) == HttpErrorResponse:
        conn.send(request_info.to_byte_array(request_info.to_http_string()))
        conn.close()
    else:
        String = request_info.to_http_string()
        print(String)
        if String in hash_table:
            conn.send(hash_table.get(String))
            print("FASTEEEEEEEER")
            conn.close()
        else:
            recieve = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                recieve.connect((request_info.requested_host, int(request_info.requested_port)))
                recieve.send(request_info.to_byte_array(String))
                data = recieve.recv(4096)
                hash_table[String] = data
                conn.send(data)
                conn.close()
            except:
                conn.send(bytes("could not resolve "+request_info.requested_host+": Name or service not known", "UTF-8"))
                conn.close()


    pass



def http_request_pipeline(source_addr, http_raw_data):
    """
    HTTP request processing pipeline.
    - Validates the given HTTP request and returns
      an error if an invalid request was given.
    - Parses it
    - Returns a sanitized HttpRequestInfo
    returns:
     HttpRequestInfo if the request was parsed correctly.
     HttpErrorResponse if the request was invalid.
    Please don't remove this function, but feel
    free to change its content
    """
    validity = check_http_request_validity(http_raw_data)
    if validity == HttpRequestState.GOOD:
       httprequestinfo=parse_http_request(source_addr,http_raw_data)
       sanitize_http_request(httprequestinfo,http_raw_data)
       return httprequestinfo
    elif validity == HttpRequestState.INVALID_INPUT:
        return HttpErrorResponse(400,"Bad Request")
    elif validity == HttpRequestState.NOT_SUPPORTED:
        return HttpErrorResponse(501,"Not Implemented")

    # Return error if needed, then:
    # parse_http_request()
    # sanitize_http_request()
    # Validate, sanitize, return Http object.
    print("*" * 50)
    print("[http_request_pipeline] Implement me!")
    print("*" * 50)

def parse_http_request(source_addr, http_raw_data):
    """
    This function parses a "valid" HTTP request into an HttpRequestInfo
    object.
    """
    #make sure client_info is right
    data_list=http_raw_data.split("\r\n",1)
    first_line=data_list[0].split(" ")
    method=first_line[0]
    port_flag=0
    path_flag=0
    http_flag=0
    headers=list()
    requested_path = "/"
    requested_port=80
    if(first_line[1][0]=="/"):
        second_line = data_list[1]
        hosts=second_line.split("\r\n")
        while 1:
            if hosts[-1] == "":
                hosts.pop(-1)
                if len(hosts) == 0:
                    break
            else:
                break;
        requested_path = first_line[1]
        header = hosts[0].replace(" ", "").replace("http://","").split(":")
        if (len(header)>2):
            requested_port=header[2]
            header.pop(-1)
        headers.append(header)
        header_url = header[1].split(":")
        requested_host = header_url[0]
        if (len(hosts)>1.0):
            for x in range(0, int(len(hosts))):
                if x==0:
                    pass
                else:
                    header_url = hosts[x].replace(" ", "").split(":")
                    headers.append(header_url)
    else:
        http=first_line [1].split("://")
        if len(http)>1:
            http_flag=1
            http.pop(0)
            http = http[0]
        else:
            http = http[0]
        #www.google.com:8080/things
        port_flag=http.find(":")
        path_flag=http.find("/")
        print(port_flag,path_flag)
        if port_flag != -1 and path_flag == -1:
            requested_host = http.split(":")[0]
            requested_port = http.split(":")[1]
        elif port_flag == -1 and path_flag != -1:
            requested_host = http.split("/",1)[0]
            requested_path = "/"+http.split("/",1)[1]
        elif port_flag == -1 and path_flag == -1:
            requested_host = http
        elif port_flag != -1 and path_flag !=-1:
            requested_host = http.split(":")[0]
            requested_port = http.split(":")[1].split("/")[0]
            requested_path = "/"+http.split("/",1)[1]
        #if http_flag == 1:
         #   requested_host= "http://"+requested_host
    print("*" * 50)
    print("[parse_http_request] Implement me!")
    print("*" * 50)
    # Replace this line with the correct values.
    ret = HttpRequestInfo(source_addr, method, requested_host, requested_port, requested_path, headers)
    return ret


def check_http_request_validity(http_raw_data) -> HttpRequestState:
    """
    Checks if an HTTP request is valid
    returns:
    One of values in HttpRequestState
    """
    data_list = http_raw_data.split("\r\n",1)

   # print(data_list)
    first_line = data_list[0].split(" ")
    method = first_line[0]
    headers=list()
    if len(first_line) == 3:
        if first_line[1] == "/":
          second_line = data_list[1]
          find_host=second_line.find("Host")
          if second_line !="" and find_host != -1:
              if first_line[2] == "HTTP/1.0":
                  if (method == "GET"):
                    if first_line[2] == "HTTP/1.0":
                        hosts = second_line.split("\r\n")
                        for x in range(0, len(hosts)-1):
                            header = hosts[x].split(":",1)
                            if len(header) == 2:
                                headers.append(header)
                                return HttpRequestState.GOOD
                            else:

                                return HttpRequestState.INVALID_INPUT
                    else:

                        return HttpRequestState.INVALID_INPUT
                  elif (method == "HEAD" or method == "POST" or method == "PUT"):
                      return HttpRequestState.NOT_SUPPORTED
                  else:

                      return HttpRequestState.INVALID_INPUT
              else:

                  return HttpRequestState.INVALID_INPUT

          else:
              return HttpRequestState.INVALID_INPUT

        else:
            if first_line[0] != "" and first_line[1] != "" and first_line[2] != "":
                if first_line[2] == "HTTP/1.0":
                            second_line = data_list[1]
                            hosts = second_line.split("\r\n")
                            while 1:
                                if hosts[-1] == "":
                                    hosts.pop(-1)
                                    if len(hosts) ==0:
                                        break
                                else:
                                    break;
                            if(len(hosts)>=1):
                                for x in range(0, len(hosts)):
                                    header = hosts[x].split(":")
                                    if len(header) == 2:
                                        headers.append(header)
                                    else:
                                        return HttpRequestState.INVALID_INPUT
                            if (method == "GET"):
                                return HttpRequestState.GOOD
                            elif (method == "HEAD" or method == "POST" or method == "PUT"):
                                return HttpRequestState.NOT_SUPPORTED
                            else:

                                return HttpRequestState.INVALID_INPUT
                else:

                    return HttpRequestState.INVALID_INPUT

            else:

                return HttpRequestState.INVALID_INPUT

    else:
        return HttpRequestState.INVALID_INPUT
    print("*" * 50)
    print("[check_http_request_validity] Implement me!")
    print("*" * 50)


def sanitize_http_request(request_info: HttpRequestInfo,http_raw_data):
    """
    Puts an HTTP request on the sanitized (standard) form
    by modifying the input request_info object.
    for example, expand a full URL to relative path + Host header.
    returns:
    nothing, but modifies the input object
    """
    data_list = http_raw_data.split("\r\n", 1)
    first_line = data_list[0].split(" ")
    if first_line[1][0] != "/" :
        request_info.headers.append(["Host",request_info.requested_host])
        second_line = data_list[1]
        hosts = second_line.split("\r\n")
        while 1:
            if hosts[-1] == "":
                hosts.pop(-1)
                if len(hosts) == 0:
                    break
            else:
                break;
        if (int(len(hosts)) >= 1):
            for x in range(0, int(len(hosts))):
                header_url = hosts[x].replace(" ", "").split(":")
                request_info.headers.append(header_url)
    print("*" * 50)
    print("[sanitize_http_request] Implement me!")
    print("*" * 50)


#######################################
# Leave the code below as is.
#######################################


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.
        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def check_file_name():
    """
    Checks if this file has a valid name for *submission*
    leave this function and as and don't use it. it's just
    to notify you if you're submitting a file with a correct
    name.
    """
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_){,2}lab2\.py", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    else:
        print(f"[LOG] File name is correct.")


def main():
    """
    Please leave the code in this function as is.
    To add code that uses sockets, feel free to add functions
    above main and outside the classes.
    """
    print("\n\n")
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)

    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    entry_point(proxy_port_number)


if __name__ == "__main__":
    main()
