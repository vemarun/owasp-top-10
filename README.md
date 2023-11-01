# owasp-top-10
#### OWASP Top 10 Notes

#### OWASP A3 - Sensitive Data Exposure 
```
- Mitigate Data exposure by encrypting data in transit and hashing passwords
- Data Masking for confidential information shown on screen like credit card information
- Protect sensitive data at rest using data encryption tools like bitlocker. 
- Bitlocker is inbuilt in windows pro versions 
```

#### A2 - Broken Authentication
```
- Aware of password length , strong password requirements, Password expiry ,Password reuse
- Enable multifactor auth like username + password + otp / smartcard
- Never stick with default authentication passwords. Always change default credentials
- Log failed attempts authentications. 
- Lock accounts if many failed attempts in small interval of time.
- Principle of least privilege - Grant only those those permission required to perform a task
- Use role base access control where roles have permissions assigned to them
- For keys based authentication, rotate keys regularly
- Idle timeout for app sessions
- In Multi factor auth - otp that change periodically can be used (totp / hotp). Virtual mfa app like google authenticator used to store and generate codes
- If user resetting password dont tell if username/email is wrong
```

#### A1 - Injection
```
- Escape special characters in input
- Use prepared queries
- Allow input list validation and input santization
```

#### A6 - Security Misconfiguration
```
- wifi open networks
- unused accounts left enabled should be removed/disabled
- Error messages disclosing too much information instead show custom error messages and custom web page
- http headers not being used at all e.g strict-transport-security, content-security-policy
- x-xss-protection header, x-frame-options:SAMEORIGIN, access-control-allow-origin:<domain>
- Apply OS/Software updates
- Introduce network and host firewalls
- Enable centralised logging and alerting
- Uptodate malware scanning tools
- Periodic web app vulnerability assessment and pen tests with fuzz testing 
- Harden server's file system access control
- Web server directory listing left enabled that shows all files on server should be disabled
- tls and web root not enabled
- Default enabled services / components unused modules that are not required
- Enable trusted signed images only
- Heartbleed bug - too much server information disclosure in http requests like web server name, openssl version etc 
- Disable sslv3 / tls 1.0 that have known vulnerabilties
```

#### A5- Broken Access control
```
- Principle of least privilege
- force authentication for each secure web page
- Security requirements are defined from starting of software dev phase i.e. from SDLC requiremts gathering and design phase
- Carefully configure public resource access
- deny everything by default, and allow as needed
- Configure firewalls
- log failed login attempts everywhere
- Use only trusted code libraries
- Use role based access control
- Ensure fail-secure access controls like if disk is full and no space for logging- app should stop on its own
- User is aouthorized to use app
- Support selective wipe (wiping of corporate data) for lost or stolen devices
```

### A4 - XML External Entities (XXE)
```
- Attacker can include malicious content in xml before it is parsed by xml parser
- then malicious can be executed by xml parser which can lead to remote code execution , dos attacks , sensitive data disclosure etc.
- To mitigate - update xml parser
- Use a web application firewalls
- Disable xml parser if not needed e.g. in php set in config libxml_disable_entity true
- validate xml inputs and sanitize it
- Review third party xml parser services / code libraries
```

#### A9 - Using Components with known vulnerabilties
```
- Beware of components that are no longer supported
- Regression testing for changed components
- Vulnerability Database - https://nvd.nist.gov/
- Openssl heartbleed vulnerabilty is known example
- Understand versions of components in use
- Ensure latest components are applied
- Use components from trusted entities
- Disable unused components
- Run periodic web app vulnerabilty test
```

#### A8 - Insecure Deserialisation
```
- Malicios code can be injected before object is deserialized
- Serialized data is a byte stream, malicious user can inject data into stream
- To mitigate - Input validation before deserialization
- Encrypt byte stream
- Digitally sign byte stream
```

#### A7 - XSS Cross site Scripting
```
- When malicious script is injected in website through wrong urls or web forms etc.
- It can be used for browser and session hijacking
- User redirection to malicious websites
- To prevent xss attacks - prevent malicious inputs and do periodic pentest
- Santize and validate user inputs, url inputs and web form fields
- Escaping functions on server side 
- Use WAF - web application firewalls
- XSS client side filters
- Server-side HTTP header like Content-security-policy
- User awareness and training
- Fuzzing testing is a type of testing in which unexpected data is sent to application to see its reaction.
- Fuzz testing should be done
- Zed attack proxy tool is one such tool that can be used to test
```

#### A10 - Insufficient logging and monitoring
```
- Logs must be reviewed
- Log alerts - someone must be notified in case of urgent issues
- Lack of auditing ? like app anf file access, token issues, failed login attempts
- Helps in auditing Suspicious host and network activity
- Helps in Reveiwing system performance, resource usage, loads etc.
- Make incident response plan (IRP)
- Log access control
- Centralised logging and monitoring
- Identify logging and monitoring deficiency by doing periodic pen tests
- Enable verbose logging for temporary to troublesheet
- Log file encryption as it may contain user data
- there should be log file integrity, log file backup, log alerts
- We can enable extra event log, custom views log in windows from event viewer
- Also log alert can be set in event viwer. Same type of logs has same Log ID
- Linux - sudo service rsys status - we can setup a central log server to which all servers sends logs
- sudo nano /etc/rsyslog.cong
- Windows has inbuilt performance monitoring
- Linux has top / htop
```


