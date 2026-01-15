import asyncio
import logging

logger = logging.getLogger("HoneyPy.FTP")

class FTPService:
    def __init__(self, honeypot_core, port=2121):
        self.honeypot = honeypot_core
        self.port = port

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        logger.info(f"New FTP connection from {addr}")

        try:
            # Send Banner (VsFTPd compliant-ish)
            writer.write(b"220 (vsFTPd 3.0.3)\r\n")
            await writer.drain()

            username = ""
            password = ""

            while True:
                # Read command
                line = await asyncio.wait_for(reader.readuntil(b'\n'), timeout=10)
                if not line:
                    break
                
                cmd_line = line.decode('utf-8', errors='ignore').strip()
                cmd = cmd_line.upper().split(' ')[0]
                arg = cmd_line[len(cmd):].strip()

                self.honeypot.log_attack("FTP_COMMAND", addr[0], addr[1], cmd_line)

                if cmd == "USER":
                    username = arg
                    writer.write(b"331 Please specify the password.\r\n")
                elif cmd == "PASS":
                    password = arg
                    self.honeypot.log_attack("FTP_CREDENTIALS", addr[0], addr[1], f"User: {username} | Pass: {password}")
                    writer.write(b"530 Login incorrect.\r\n")
                    # Usually we close or let them try again. Let's close to annoy them.
                    break
                elif cmd == "QUIT":
                    writer.write(b"221 Goodbye.\r\n")
                    break
                else:
                    writer.write(b"500 Unknown command.\r\n")
                
                await writer.drain()

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.error(f"Error handling FTP connection: {e}")
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
        logger.info(f"FTP Service listening on port {self.port}")
        async with server:
            await server.serve_forever()
