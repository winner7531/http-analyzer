# HTTP
A beginner-friendly HTTP analyzer built using Python sockets.

The project captures raw HTTP requests, parses headers and query parameters, and performs lightweight security analysis such as suspicious parameter detection and Base64 detection and decode.

## Features

- Capture raw HTTP requests using sockets
- Parse request method, path, and HTTP version
- Extract and analyze headers
- Parse query parameters
- Detect suspicious parameters
- Detect possible Base64-encoded values

## How It Works

The analyzer starts a socket server on port 8080 and listens for incoming HTTP requests.

Captured requests are:
1. Decoded from bytes to text
2. Split into request lines
3. Parsed into headers and request components
4. Analyzed for suspicious parameters and encoded data

## Usage

Run the analyzer:

```bash
python3 chat.py
```
Test with curl
curl "http://localhost:8080/test?token=c2hpa2hhcg=="


---

# Example Output

Example:

````markdown id="z8q4ny"
## Example Output

```text
[!] AUTH parameter detected: token
c2hpa2hhcg== → DETECTED → shikhar


---

```markdown id="y5p2wd"
# Future Improvements

- POST body parsing
- JWT detection
- HTTP response parsing
- Proxy support
```


