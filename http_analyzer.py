import socket
from urllib.parse import unquote, parse_qs, urlparse
import base64

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", 8080))
server.listen(1)

print("Listening on port 8080...")

client_socket, addr = server.accept()

print(f"Connection from {addr}")

request = client_socket.recv(4096)

print(request.decode())

client_socket.close()
server.close()

# parsing the request
lines = request.decode().splitlines()
request_line = lines[0]
print(request_line)
method, path, version = request_line.split()
print(method)
print(version)
print(path)

# create headers dict to get all headers
headers = {}
# turn headers strings into dictionary
for line in lines[1:]:
    if ":" in line:
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
print(headers)
# extract cookie header from headers
cookie_headers = headers.get("Set-Cookie")
print(cookie_headers)

# split different cookies
if cookie_headers:
    parts = [p.strip() for p in cookie_headers.split(";")]
    name, _, value = parts[0].partition("=")
    flags = parts[1:]
    #print different cookies
    print(name)
    print(value)
    print(flags)
    #lowercase all flags to compare
    flags_lower = [f.lower() for f in flags]
    #check if it has flags
    has_httponly = "httponly" in flags_lower
    has_secure = "secure" in flags_lower
    samesite = next((f for f in flags_lower if f.startswith("samesite=")), None)

 #print conclusions
    print(f"Cookie name: {name}")
    if "httponly" in flags_lower:
        print("HttpOnly: present. -> JS cannot read cookie")
    else:
        print("HttpOnly: absent ->  cookie theft via XSS possible")



url = path
#parse the url into parts
parsed = urlparse(url)
#print(parsed)
#get the query
print(parsed.query)
#turn string into value=pair dictionary
params = parse_qs(parsed.query)
print(params)

#list of suspicious params
suspicious = {
    "auth": ["token", "jwt", "session"],
    "redirect": ["next", "redirect"],
    "file": ["file", "path"],
    "debug": ["debug", "verbose"]
}

for key, values in params.items():

    for val in values:
        print(f"{key}: {unquote(val)}")

    for category, keywords in suspicious.items():

        if key.lower() in keywords:
            print(f"[!] {category.upper()} parameter detected: {key}")



#detecting b64
for key, values in params.items():
    for v in values:
        padded = v + "=" * (-len(v) % 4)
        print(f"testing value: {repr(v)}")
        try:
            decoded = base64.b64decode(padded)

            if len(decoded) == 0:
                print(f"{v[:20]:<20} → empty decode")
                continue

            printable = sum(32 <= b < 127 for b in decoded)
            ratio = printable / len(decoded)

            if ratio > 0.75:
                print(f"{v[:20]:<20} → DETECTED → {decoded.decode('utf-8', errors='replace')}")
            else:
                print(f"{v[:20]:<20} → binary/random Base64")
                print(repr(v))
        except Exception as e:
            print(f"{v[:20]:<20} → invalid Base64")
            
            print(e)
