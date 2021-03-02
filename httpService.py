import http.server
import socketserver
from urllib.parse import urlparse
from urllib.parse import parse_qs
import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pages import header, footer, landingPageContent
from client import startTransaction

class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        global matrix,err,b,dim
        # Sending an '200 OK' response
        self.send_response(200)

        # Setting the header
        self.send_header("Content-type", "text/html")

        # Whenever using 'send_header', you also have to call 'end_headers'
        self.end_headers()
        print(self.path)
        
        parsed_url = urlparse(self.path)
        parsed_q = parse_qs(parsed_url.query)     
        html = header + landingPageContent + footer    
        if self.path == "/":
            print("got to landing")
            html = header + landingPageContent + footer    
        elif self.path =="/start":
            startTransaction()
            html = header + """
                            <h3>Your transaction is processing...</h3>
                            <div class="spinner-border" role="status">
                                <span class="sr-only">Loading...</span>
                            </div>
                            <div style="margin:20px"> <a class = "btn btn-primary" href = "/accounts">Go to accounts </a> </div>
                            """ + footer
        elif self.path == "/account":
            f = open('Data/accounts.txt', 'r')
            amounts = f.readline()
            amounts = amounts.split()
            html = header + "<h3> Client account: " + amounts[0] + "</h3>" +"<h3> Merchant account: " + amounts[1] + "</h3>" +footer


        # Writing the HTML contents with UTF-8
        self.wfile.write(bytes(html, "utf8"))

        return

# Create an object of the above class
handler_object = MyHttpRequestHandler

PORT = 8000
my_server = socketserver.TCPServer(("", PORT), handler_object)

# Star the server
my_server.serve_forever()