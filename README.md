# smuggles
smuggles is an HTTP request smuggling scanner designed to be able to scan thousands of hosts in a single scan.  It offers the following features:
- detection of CL.TE and TE.CL request smuggling using the time-based techniques described by James Kettle in his post [HTTP Desync Attacks: Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- scan state saving and resumption
- generation of PoC requests to reproduce timeouts
- generation of [Turbo Intruder](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack) scripts to exploit request smuggling issues
- random request ordering to allow for a large number of tests to be performed while keeping the traffic to each host low
- a large number of mutations of the `Transfer-Encoding` included in tests

## Installation
If you have go installed, you can run:
```bash
go install -v github.com/danielthatcher/smuggles@latest
```

## Usage
smuggles accepts a list of URLs as target, one per line, on stdin and can be run without any arguments:
```bash
cat targets.txt | smuggles
```
smuggles will send a regular HTTP request to each target to determine what a normal response time for the target is, and then test different mutation of the `Transfer-Encoding` header against each target to try and cause a timeout. CL.TE tests are performed before TE.CL tests to try and prevent accidental socket poisoning during the detection phase.

When run without any arguments, smuggles will try all mutations with each of the `GET`, `POST`, `PUT`, and `DELETE` HTTP methods. You can view the full list of mutations with `smuggles -l`, and view an individual mutation with `smuggles -m <mutation name>`. Note that this will output the raw bytes of the mutation, including control characters.

### Selecting mutations
Mutations can be disabled by specifying the `-d` flag one or more times, each time with a glob the of the mutation names to disable. For example, to disable all mutations which put bytes either side of the colon or which specify multiple values separated by a comma you would run
```bash
smuggles -d 'comma-*' -d 'colon-*'
```

You can instead enable just a subset of mutations with the `-e` flag, against used one or more times with a glob matching the mutations to enable as the argument. For example, to enable just the line prefix and the uppercase mutations, you would run
```bash
smuggles -e 'lineprefix-*' -e uppercase
```

### Selecting methods
Similarly, custom methods can be specified with the `-m` flag. For example, to only scan with `GET` and `POST` methods, you would run
```bash
smuggles -m GET -m POST
```

### Output
Smuggles will output results similar to the following:
```
GET https://example.com CL.TE lineprefix-space
```
This means that a CL.TE timeout can be triggered with a request to https://example.com using the `lineprefix-space` mutation of the `Transfer-Encoding` header.

### Generating timeout PoCs
Timeout proof-of-concepts can be generated by running smuggles with the `--poc` flag an supplying a line of smuggles' output. For example, you can generate a proof-of-concept for a CL.TE timeout to https://example.com using the `lineprefix-space` mutation as follows:
```bash
$ smuggles --poc GET https://example.com CL.TE lineprefix-space    
GET / HTTP/1.1
 Transfer-Encoding: chunked
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246
Connection: close
Content-Length: 4

1
Z
Q
```

### Generating TurboIntruder scripts
You can also generate TurboIntruder scripts for exploitation in a similar fashion by specifying a template script with the `--script` flag:
```bash
smuggles --script /path/to/script.py GET https://example.com CL.TE lineprefix-space
```
Sample template scripts can be found in the [resources](resources/) directory.
