# Burp Extender How-To Guide

Burp Extender is a framework that allows you to extend Burp Suite's functionality using custom extensions written in Java, Python (Jython), or Ruby (JRuby).

## Setting Up Burp with Python Extensions

1. **Install Jython**:
```bash
# Download from https://www.jython.org/download
wget https://repo1.maven.org/maven2/org/python/jython-installer/2.7.3/jython-installer-2.7.3.jar
java -jar jython-installer-2.7.3.jar
```

2. **Configure Burp to use Jython**:
- Go to Extender → Options → Python Environment
- Set the location of jython.jar

## Basic Burp Extension Structure (Python)

```python
from burp import IBurpExtender, IHttpListener, IScannerCheck
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # Keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # Obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # Set our extension name
        callbacks.setExtensionName("My Custom Extension")
        
        # Obtain our output stream
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        
        # Register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            # Process response
            response = messageInfo.getResponse()
            responseStr = self._helpers.bytesToString(response)
            
            # Look for interesting patterns
            if "password=" in responseStr and toolFlag == self._callbacks.TOOL_PROXY:
                self._stdout.println("Found password in response!")
                self._stdout.println(responseStr)
```

## Real-World Scenario 1: Custom Parameter Discovery

**Situation**: You want to automatically identify custom parameters in web applications that might not be caught by Burp's default parameter detection.

**Step-by-Step Process**:

1. **Create the parameter discovery extension**:
```python
from burp import IBurpExtender, IHttpListener
from java.io import PrintWriter
import re

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Custom Parameter Discovery")
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.registerHttpListener(self)
        
        # Patterns to look for
        self.patterns = [
            r'[\?&]([a-zA-Z_][a-zA-Z0-9_]*)=',  # URL parameters
            r'([a-zA-Z_][a-zA-Z0-9_]*)=([^&\s]*)',  # Form parameters
            r'"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:\s*"',  # JSON keys
        ]
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:  # Only process responses
            request = messageInfo.getRequest()
            requestStr = self._helpers.bytesToString(request)
            
            # Check for custom parameters
            for pattern in self.patterns:
                matches = re.findall(pattern, requestStr)
                for match in matches:
                    param_name = match[0] if isinstance(match, tuple) else match
                    # Filter out common parameters
                    if param_name not in ['username', 'password', 'email', 'submit', 'action']:
                        if len(param_name) > 3:  # Likely custom if >3 chars
                            self._stdout.println(f"Custom parameter found: {param_name}")
```

## Real-World Scenario 2: Automated Authentication Token Tracking

**Situation**: You want to track authentication tokens across requests to better understand the application's authentication flow.

**Step-by-Step Process**:

1. **Create the token tracking extension**:
```python
from burp import IBurpExtender, IHttpListener
from java.io import PrintWriter
import re

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Auth Token Tracker")
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.registerHttpListener(self)
        
        # Store tokens we find
        self.tokens = set()
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:  # Process requests
            request = messageInfo.getRequest()
            requestStr = self._helpers.bytesToString(request)
            
            # Look for authentication tokens in headers
            auth_header_match = re.search(r'Authorization:\s*(.*?)(?:\r\n|\n)', requestStr, re.IGNORECASE)
            if auth_header_match:
                token = auth_header_match.group(1)
                if token not in self.tokens:
                    self.tokens.add(token)
                    self._stdout.println(f"New auth token found: {token}")
            
            # Look for token in cookies
            cookie_match = re.search(r'Cookie:\s*(.*?)(?:\r\n|\n)', requestStr, re.IGNORECASE)
            if cookie_match:
                cookie_str = cookie_match.group(1)
                # Look for common session token names
                token_patterns = [
                    r'(sessionid|token|auth|access_token)=([a-zA-Z0-9\-\._]+)',
                    r'(PHPSESSID|JSESSIONID)=[a-zA-Z0-9\-\._]+'
                ]
                
                for pattern in token_patterns:
                    matches = re.findall(pattern, cookie_str, re.IGNORECASE)
                    for match in matches:
                        token = match[1] if isinstance(match, tuple) and len(match) > 1 else match
                        if token and token not in self.tokens:
                            self.tokens.add(token)
                            self._stdout.println(f"New session token found: {token}")
```

## Real-World Scenario 3: Custom Scanner Check for API Endpoints

**Situation**: You want to create a custom vulnerability scanner that specifically looks for vulnerable API endpoints.

**Step 1**: Create the custom scanner:
```python
from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.io import PrintWriter
import re

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("API Endpoint Scanner")
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.registerScannerCheck(self)
    
    def doPassiveScan(self, baseRequestResponse):
        issues = []
        
        # Get URL and response
        url = self._helpers.analyzeRequest(baseRequestResponse).getUrl().toString()
        response = baseRequestResponse.getResponse()
        responseStr = self._helpers.bytesToString(response)
        
        # Check for API-specific vulnerabilities
        if '/api/' in url or '/v1/' in url or '/v2/' in url or '/graphql' in url:
            # Check for information disclosure
            if '"password"' in responseStr.lower() or '"api_key"' in responseStr.lower():
                issues.append(
                    CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [baseRequestResponse],
                        "API Information Disclosure",
                        "Sensitive information like passwords or API keys found in API response",
                        "High"
                    )
                )
            
            # Check for common API vulnerabilities
            if 'traceback' in responseStr.lower() or 'exception' in responseStr.lower():
                issues.append(
                    CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [baseRequestResponse],
                        "API Error Disclosure",
                        "Detailed error information disclosed in API response",
                        "Medium"
                    )
                )
        
        return issues
    
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # Active scanning would go here if needed
        return None
    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getUrl() == newIssue.getUrl() and existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
```

## Advanced Burp Extension Techniques

**Adding Custom Tabs**:
```python
from burp import IBurpExtender, ITab
from javax.swing import JPanel, JButton, JTextArea
from java.awt import BorderLayout

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Custom UI Extension")
        
        # Create UI components
        self._txtInput = JTextArea()
        self._btnDoMagic = JButton("Do Magic!", actionPerformed=self.actionPerformed)
        
        # Main panel
        self._mainPanel = JPanel(BorderLayout())
        self._mainPanel.add(self._btnDoMagic, BorderLayout.NORTH)
        self._mainPanel.add(self._txtInput, BorderLayout.CENTER)
        
        # Add our custom tab to Burp's UI
        callbacks.addSuiteTab(self)
    
    def actionPerformed(self, event):
        # Handle button click
        input_text = self._txtInput.getText()
        # Process the input...
    
    def getTabCaption(self):
        return "Magic Tab"
    
    def getUiComponent(self):
        return self._mainPanel
```

## Common Burp Extension Interfaces

### IBurpExtender (Required)
- `registerExtenderCallbacks(callbacks)`: Entry point for the extension

### IHttpListener (Intercept HTTP messages)
- `processHttpMessage(toolFlag, messageIsRequest, messageInfo)`: Process HTTP messages

### IProxyListener (Intercept proxy messages)
- `processProxyMessage(messageIsRequest, message)`: Process proxy messages

### IScannerCheck (Custom scanner)
- `doPassiveScan(baseRequestResponse)`: Passive scanning
- `doActiveScan(baseRequestResponse, insertionPoint)`: Active scanning
- `consolidateDuplicateIssues(existingIssue, newIssue)`: Handle duplicate issues

### ITab (Custom UI tab)
- `getTabCaption()`: Return tab name
- `getUiComponent()`: Return component to show in tab

## Tips and Best Practices

1. **Use appropriate interfaces**: Select the right interface based on what you want to achieve
2. **Handle exceptions properly**: Wrap your code in try-catch blocks to prevent extension crashes
3. **Log appropriately**: Use callbacks.getStdout() to output useful information
4. **Follow Java conventions**: Even in Python, follow Java naming conventions for interface methods
5. **Test thoroughly**: Test your extensions in a safe environment before using in assessments
6. **Use helpers wisely**: Utilize the helpers object for common tasks like decoding, encoding, and HTTP analysis
7. **Be efficient**: Extensions run during normal Burp operation, so ensure they don't impact performance

## Troubleshooting Common Issues

- **"ImportError"**: Ensure Jython is correctly configured in Burp's options
- **Extension not loading**: Check for syntax errors and ensure required interfaces are properly implemented
- **No output**: Verify callbacks.getStdout() is used to output messages
- **Extension not responding**: Ensure Java.perform() isn't used inappropriately
- **Memory issues**: Remove unnecessary persistent storage of data in your extension
- **Performance degradation**: Optimize your code to minimize processing time per request/response