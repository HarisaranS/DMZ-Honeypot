import asyncio
import logging

logger = logging.getLogger("HoneyPy.HTTP")

class HTTPService:
    def __init__(self, honeypot_core, port=8080):
        self.honeypot = honeypot_core
        self.port = port
        self.html_content = (
            "<html><head><title>Employee Login</title>"
            "<style>"
            "body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f0f2f5; margin: 0; }"
            ".login-container { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 300px; }"
            "input { width: 100%; padding: 10px; margin: 5px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }"
            "button { width: 100%; padding: 10px; background-color: #1877f2; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }"
            "button:hover { background-color: #166fe5; }"
            "h2 { text-align: center; color: #333; margin-bottom: 20px; }"
            ".error { color: red; font-size: 0.9em; text-align: center; display: none; }"
            "</style>"
            "</head>"
            "<body>"
            "<div class='login-container'>"
            "<h2>Restricted Access</h2>"
            "<form method='POST' action='/login'>"
            "<input type='text' name='username' placeholder='Username' required><br>"
            "<input type='password' name='password' placeholder='Password' required><br>"
            "<button type='submit'>Log In</button>"
            "</form>"
            "</div>"
            "</body></html>"
        )


    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        
        try:
            # Read request
            try:
                # Read until we get header end or a reasonable amount
                data = await asyncio.wait_for(reader.read(4096), timeout=5)
            except asyncio.TimeoutError:
                return

            if not data:
                return
            
            request_text = data.decode('utf-8', errors='ignore')
            lines = request_text.split('\r\n')
            if not lines:
                return

            first_line = lines[0]
            # Log the request
            self.honeypot.log_attack("HTTP", addr[0], addr[1], first_line)

            # Check for POST data
            if "POST" in first_line:
                parts = request_text.split('\r\n\r\n', 1)
                if len(parts) > 1:
                    self.honeypot.log_attack("HTTP_CREDENTIALS", addr[0], addr[1], parts[1].strip())
            
            # Construct Response
            # IMPORTANT: Calculate exact byte length of the body
            body_bytes = self.html_content.encode('utf-8')
            content_length = len(body_bytes)

            response_headers = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                "Server: Apache/2.4.41 (Ubuntu)\r\n"
                f"Content-Length: {content_length}\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            
            writer.write(response_headers.encode('utf-8'))
            writer.write(body_bytes)
            await writer.drain()

        except Exception as e:
            logger.error(f"Error handling HTTP connection: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass

    async def start(self):
        server = await asyncio.start_server(
            self.handle_client, '0.0.0.0', self.port
        )
        logger.info(f"HTTP Service listening on port {self.port}")
        async with server:
            await server.serve_forever()
