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
print("================ HTTP REQUEST ================")
#print(request.decode())

client_socket.close()
server.close()

# parsing the request
lines = request.decode().splitlines()
request_line = lines[0]
print(request_line)
method, path, version = request_line.split()
print(f"{'Method':<10}: {method}")
print(f"{'Version':<10}: {version}")
print(f"{'Path':<10}: {path}")

# create headers dict to get all headers
headers = {}
# turn headers strings into dictionary
print("=" * 50)
print("HEADERS")
print("=" * 50)
for line in lines[1:]:
    if ":" in line:
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
print(headers)
# extract cookie header from headers
print("=" * 50)
print("COOKIES")
print("=" * 50)

cookie_headers = headers.get("Cookie")
#print(cookie_headers)

# split different cookies
if cookie_headers:

    cookies = [c.strip() for c in cookie_headers.split(";")]

    for cookie in cookies:

        name, _, value = cookie.partition("=")

        print(f"{'Cookie':<10}: {name}")
        print(f"{'Value':<10}: {value}")
        print()
    #lowercase all flags to compare
    '''flags_lower = [f.lower() for f in flags]
    #check if it has flags
    has_httponly = "httponly" in flags_lower
    has_secure = "secure" in flags_lower
    samesite = next((f for f in flags_lower if f.startswith("samesite=")), None)

 #print conclusions
    if "httponly" in flags_lower:
        print("HttpOnly: present. -> JS cannot read cookie")
    else:
        print("HttpOnly: absent ->  cookie theft via XSS possible")
'''
print("=" * 50)
print("QUERY PARAMETERS")
print("=" * 50)


url = path
#parse the url into parts
parsed = urlparse(url)
#print(parsed)
#get the query
print(parsed.query)
#turn string into value=pair dictionary
params = parse_qs(parsed.query)
#print(params)

#list of suspicious params
suspicious = {
    "auth": ["token", "jwt", "session"],
    "redirect": ["next", "redirect"],
    "file": ["file", "path"],
    "debug": ["debug", "verbose"]
}

for key, values in params.items():

    print(f"\n[+] {key}")

    for val in values:

        decoded_val = unquote(val)

        print(f"    Value: {decoded_val}")

        # detect suspicious parameter names
        for category, keywords in suspicious.items():

            if key.lower() in keywords:
                print(f"    [!] {category.upper()} parameter detected")

print("=" * 50)
print("Base64 detection and decoding")
print("=" * 50)


#detecting b64
for key, values in params.items():
    for v in values:
        padded = v + "=" * (-len(v) % 4)
        try:
            decoded = base64.b64decode(padded)

            if len(decoded) == 0:
                #print(f"{v[:20]:<20} → empty decode")
                continue

            printable = sum(32 <= b < 127 for b in decoded)
            ratio = printable / len(decoded)

            if ratio > 0.75:
                print(f"{v[:20]:<20} → DETECTED → {decoded.decode('utf-8', errors='replace')}")
            
        except Exception:
            #print(f"{v[:20]:<20} → invalid Base64")
            pass
