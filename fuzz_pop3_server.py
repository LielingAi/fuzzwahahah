import asyncio
import sys
import os
import traceback
import glob

# POP3 line terminator as defined by RFC 1939
POP3_LINE_TERM = b'\r\n'

class POP3FuzzServerProtocol(asyncio.Protocol):
    """
    A simple POP3 server protocol implementation for fuzzing purposes.
    It supports basic commands needed to retrieve email messages from a directory.
    It serves one email at a time, removing it from the directory after RETR.
    """
    def __init__(self, mail_dir_path, chunk_size=None, delay=None, delete_after_send=False):
        self.transport = None
        self.state = "AUTHORIZATION"  # As per RFC 1939
        self.mail_dir_path = mail_dir_path # Store the path to the directory of .eml files
        self.chunk_size = chunk_size
        self.delay = delay # Delay in seconds between chunks
        self.delete_after_send = delete_after_send # Whether to delete the file after sending
        self._current_mail_file_path = None # Path of the mail file currently being served

    def _get_next_mail_file(self):
        """
        Get the path of the next .eml file in the directory.
        Returns the full path of the first .eml file found (sorted alphabetically),
        or None if no .eml files are found.
        """
        if not os.path.isdir(self.mail_dir_path):
            print(f"[SERVER] Mail directory '{self.mail_dir_path}' does not exist or is not a directory.")
            return None
            
        # Use glob to find all .eml files
        eml_pattern = os.path.join(self.mail_dir_path, "*.eml")
        eml_files = glob.glob(eml_pattern)
        
        # Sort the files to have a predictable order
        eml_files.sort()
        
        if eml_files:
            # Return the first one
            return eml_files[0]
        else:
            return None

    def connection_made(self, transport):
        """Called when a client connects."""
        self.transport = transport
        peername = transport.get_extra_info('peername')
        print(f"[SERVER] Connection from {peername}")
        # Greeting as per RFC 1939
        self.transport.write(b"+OK POP3 Fuzz Server ready" + POP3_LINE_TERM)

    def data_received(self, data):
        """Called when data is received from the client."""
        try:
            # Decode command, handling potential partial receives
            message = data.decode('utf-8', errors='ignore').rstrip('\r\n')
            print(f"[SERVER] Received: {message}")
            parts = message.split(' ')
            command = parts[0].upper() if parts else ""

            if self.state == "AUTHORIZATION":
                if command == "USER":
                    # USER name: RFC 1939 Section 6
                    # We accept any user
                    self.transport.write(b"+OK User accepted" + POP3_LINE_TERM)
                elif command == "PASS":
                    # PASS string: RFC 1939 Section 6
                    # We accept any password
                    self.state = "TRANSACTION"
                    self.transport.write(b"+OK Password accepted" + POP3_LINE_TERM)
                elif command == "QUIT":
                    # QUIT: RFC 1939 Section 6
                    self.transport.write(b"+OK Bye" + POP3_LINE_TERM)
                    self.transport.close()
                elif command == "CAPA":
                    # Optional CAPA command for extended capabilities
                    # This is not in base RFC 1939 but widely supported
                    self.transport.write(b"+OK Capability list follows" + POP3_LINE_TERM)
                    # We don't advertise any specific capabilities for simplicity
                    self.transport.write(b"." + POP3_LINE_TERM)
                else:
                    # -ERR is used for all errors as per RFC 1939
                    self.transport.write(b"-ERR Unknown command in AUTHORIZATION state" + POP3_LINE_TERM)

            elif self.state == "TRANSACTION":
                # In this mode, we dynamically determine the number of messages
                # based on the files in the directory for each command.
                
                if command == "STAT":
                    # STAT: RFC 1939 Section 6
                    # "+OK nn mm" where nn is message count, mm is mailbox size
                    next_mail_file = self._get_next_mail_file()
                    if not next_mail_file:
                        # No messages
                        self.transport.write(b"+OK 0 0" + POP3_LINE_TERM)
                    else:
                        try:
                            with open(next_mail_file, 'rb') as f:
                                current_mail_data = f.read()
                            # Rough size estimate. RFC allows for approximation.
                            size = len(current_mail_data) 
                        except Exception:
                            size = 0 # Fallback
                        response = f"+OK 1 {size}"
                        self.transport.write(response.encode('utf-8') + POP3_LINE_TERM)
                    
                elif command == "LIST":
                    # LIST [msg]: RFC 1939 Section 6
                    next_mail_file = self._get_next_mail_file()
                    if not next_mail_file:
                        # No messages
                        if len(parts) == 1: # LIST
                            self.transport.write(b"+OK 0 messages" + POP3_LINE_TERM)
                            self.transport.write(b"." + POP3_LINE_TERM)
                        elif len(parts) == 2: # LIST msg
                            self.transport.write(b"-ERR no such message" + POP3_LINE_TERM)
                        else:
                             self.transport.write(b"-ERR invalid arguments" + POP3_LINE_TERM)
                        return

                    if len(parts) == 1: # LIST (no arguments)
                        # Multi-line response for 1 message
                        try:
                            with open(next_mail_file, 'rb') as f:
                                current_mail_data = f.read()
                            size = len(current_mail_data)
                        except Exception:
                            size = 0 # Fallback
                        self.transport.write(b"+OK 1 messages" + POP3_LINE_TERM)
                        # List messages, format: "msg# size"
                        self.transport.write(f"1 {size}".encode('utf-8') + POP3_LINE_TERM)
                        self.transport.write(b"." + POP3_LINE_TERM) # End of multi-line response
                        
                    elif len(parts) == 2: # LIST msg
                        try:
                            msg_num = int(parts[1])
                            if msg_num == 1:
                                try:
                                    with open(next_mail_file, 'rb') as f:
                                        current_mail_data = f.read()
                                    size = len(current_mail_data)
                                except Exception:
                                    size = 0 # Fallback
                                response = f"+OK {msg_num} {size}"
                                self.transport.write(response.encode('utf-8') + POP3_LINE_TERM)
                            else:
                                self.transport.write(b"-ERR no such message" + POP3_LINE_TERM)
                        except ValueError:
                            self.transport.write(b"-ERR invalid arguments" + POP3_LINE_TERM)
                    else:
                         self.transport.write(b"-ERR invalid arguments" + POP3_LINE_TERM)

                elif command == "RETR":
                    # RETR msg: RFC 1939 Section 6
                    # Retrieve entire message (including headers and body, with EOB stuffing)
                    if len(parts) != 2:
                        self.transport.write(b"-ERR invalid arguments" + POP3_LINE_TERM)
                        return
                    try:
                        msg_num = int(parts[1])
                        if msg_num != 1:
                            self.transport.write(b"-ERR no such message" + POP3_LINE_TERM)
                            return
                    except ValueError:
                        self.transport.write(b"-ERR invalid arguments" + POP3_LINE_TERM)
                        return

                    # --- THE CORE OF THE FUZZ SERVER ---
                    # Get the next mail file
                    next_mail_file = self._get_next_mail_file()
                    if not next_mail_file:
                        self.transport.write(b"-ERR no messages in directory" + POP3_LINE_TERM)
                        return
                        
                    # Store the path for potential deletion after send
                    self._current_mail_file_path = next_mail_file

                    # Read the mail file content
                    try:
                        with open(self._current_mail_file_path, 'rb') as f:
                            mail_data = f.read()
                        print(f"[SERVER] (RETR) Loaded mail from '{self._current_mail_file_path}', {len(mail_data)} bytes.")
                    except FileNotFoundError:
                        print(f"[SERVER] (RETR) Error: File '{self._current_mail_file_path}' not found.")
                        self.transport.write(b"-ERR Mail file not found on server" + POP3_LINE_TERM)
                        # Reset current file path as it's invalid
                        self._current_mail_file_path = None
                        return
                    except Exception as e:
                        print(f"[SERVER] (RETR) Error reading file '{self._current_mail_file_path}': {e}")
                        self.transport.write(b"-ERR Internal server error reading mail" + POP3_LINE_TERM)
                        self._current_mail_file_path = None
                        return
                    
                    # Send the email data asynchronously
                    asyncio.create_task(self.send_mail_data(mail_data))
                    
                elif command == "TOP":
                     # TOP msg n: RFC 1939 Section 8 (Optional)
                     # Get message headers + n lines of body
                     if len(parts) != 3:
                        self.transport.write(b"-ERR invalid arguments" + POP3_LINE_TERM)
                        return
                     try:
                        msg_num = int(parts[1])
                        lines = int(parts[2])
                        if msg_num != 1:
                            self.transport.write(b"-ERR no such message" + POP3_LINE_TERM)
                            return
                        if lines < 0:
                            self.transport.write(b"-ERR invalid line count" + POP3_LINE_TERM)
                            return
                     except ValueError:
                        self.transport.write(b"-ERR invalid arguments" + POP3_LINE_TERM)
                        return

                     # Get the next mail file
                     next_mail_file = self._get_next_mail_file()
                     if not next_mail_file:
                        self.transport.write(b"-ERR no messages in directory" + POP3_LINE_TERM)
                        return

                     # Read the mail file content
                     try:
                        with open(next_mail_file, 'rb') as f:
                            mail_data = f.read()
                        print(f"[SERVER] (TOP) Loaded mail from '{next_mail_file}', {len(mail_data)} bytes.")
                     except FileNotFoundError:
                        print(f"[SERVER] (TOP) Error: File '{next_mail_file}' not found.")
                        self.transport.write(b"-ERR Mail file not found on server" + POP3_LINE_TERM)
                        return
                     except Exception as e:
                        print(f"[SERVER] (TOP) Error reading file '{next_mail_file}': {e}")
                        self.transport.write(b"-ERR Internal server error reading mail" + POP3_LINE_TERM)
                        return
                    
                     asyncio.create_task(self.send_top_data(mail_data, lines))
                     
                elif command == "UIDL":
                    # UIDL [msg]: RFC 1939 Section 8 (Optional)
                    # Unique ID Listing
                    next_mail_file = self._get_next_mail_file()
                    if not next_mail_file:
                        if len(parts) == 1: # UIDL
                            self.transport.write(b"+OK 0 messages" + POP3_LINE_TERM)
                            self.transport.write(b"." + POP3_LINE_TERM)
                        elif len(parts) == 2: # UIDL msg
                            self.transport.write(b"-ERR no such message" + POP3_LINE_TERM)
                        else:
                             self.transport.write(b"-ERR invalid arguments" + POP3_LINE_TERM)
                        return

                    if len(parts) == 1: # UIDL (no arguments)
                        self.transport.write(b"+OK unique-id listing follows" + POP3_LINE_TERM)
                        # We use the filename (without extension) as a simple UID
                        filename = os.path.basename(next_mail_file)
                        uid = os.path.splitext(filename)[0]
                        self.transport.write(f"1 {uid}".encode('utf-8') + POP3_LINE_TERM)
                        self.transport.write(b"." + POP3_LINE_TERM)
                    elif len(parts) == 2: # UIDL msg
                        try:
                            msg_num = int(parts[1])
                            if msg_num == 1:
                                # Use filename as UID
                                filename = os.path.basename(next_mail_file)
                                uid = os.path.splitext(filename)[0]
                                self.transport.write(f"+OK {msg_num} {uid}".encode('utf-8') + POP3_LINE_TERM)
                            else:
                                self.transport.write(b"-ERR no such message" + POP3_LINE_TERM)
                        except ValueError:
                            self.transport.write(b"-ERR invalid arguments" + POP3_LINE_TERM)
                    else:
                         self.transport.write(b"-ERR invalid arguments" + POP3_LINE_TERM)
                         
                elif command == "QUIT":
                    # QUIT: RFC 1939 Section 6
                    self.state = "AUTHORIZATION" # Reset state for potential new connection
                    # Do not delete file on QUIT, only on successful RETR send
                    self._current_mail_file_path = None
                    self.transport.write(b"+OK Bye" + POP3_LINE_TERM)
                    self.transport.close()
                elif command == "CAPA":
                    # Optional CAPA command
                    self.transport.write(b"+OK Capability list follows" + POP3_LINE_TERM)
                    # Advertise TOP and UIDL as they are common
                    self.transport.write(b"TOP" + POP3_LINE_TERM)
                    self.transport.write(b"UIDL" + POP3_LINE_TERM)
                    self.transport.write(b"." + POP3_LINE_TERM)
                elif command == "NOOP":
                    # NOOP: RFC 1939 Section 6
                    self.transport.write(b"+OK" + POP3_LINE_TERM)
                else:
                    self.transport.write(b"-ERR Unknown command in TRANSACTION state" + POP3_LINE_TERM)
        except Exception as e:
            print(f"[SERVER] Error processing command: {e}")
            traceback.print_exc()
            # Try to send an error response if transport is still open
            try:
                if self.transport and not self.transport.is_closing():
                    self.transport.write(b"-ERR Server internal error" + POP3_LINE_TERM)
            except:
                pass # Ignore errors when trying to send error response

    async def send_mail_data(self, mail_data):
        """
        Asynchronously send the full mail data according to RFC 1939.
        This includes the "+OK size" line and the data terminated by ".".
        """
        try:
            # 1. Send initial response "+OK octets"
            response_line = f"+OK {len(mail_data)} octets"
            self.transport.write(response_line.encode('utf-8') + POP3_LINE_TERM)
            
            # 2. Send the actual mail data
            await self._send_data_chunks(mail_data)
            
            # 3. Send the End-of-Block (EOB) marker as per RFC 1939
            print("[SERVER] (RETR) Finished sending mail data stream.")
            
            # 4. After successful send, optionally delete the file
            if self.delete_after_send and self._current_mail_file_path and os.path.exists(self._current_mail_file_path):
                try:
                    os.remove(self._current_mail_file_path)
                    print(f"[SERVER] (RETR) Deleted mail file '{self._current_mail_file_path}'")
                except OSError as e:
                    print(f"[SERVER] (RETR) Failed to delete mail file '{self._current_mail_file_path}': {e}")
            
        except Exception as e:
            print(f"[SERVER] (RETR) Error sending mail: {e}")
            traceback.print_exc()
        finally:
            # Reset the current file path regardless of success or failure
            # to avoid trying to delete it again or on QUIT
            self._current_mail_file_path = None
        # The transport/connection lifecycle is managed by the main command loop (QUIT).

    async def send_top_data(self, mail_data, num_lines):
        """
        Asynchronously send the headers and top 'num_lines' of body.
        """
        try:
            # Find header/body separator
            header_end = mail_data.find(b"\r\n\r\n")
            if header_end == -1:
                # No clear separator, treat whole thing as headers for simplicity in fuzz context
                headers_part = mail_data
                body_lines = []
            else:
                headers_part = mail_data[:header_end + 4] # Include \r\n\r\n
                body_part = mail_data[header_end + 4:]
                body_lines = body_part.split(b'\r\n')
                # Remove trailing empty line if it exists (from final \r\n before .\r\n)
                if body_lines and body_lines[-1] == b'':
                    body_lines.pop()
            
            # Select lines
            selected_body_lines = body_lines[:num_lines]
            
            # Reconstruct data to send
            data_to_send_lines = [headers_part] + selected_body_lines
            data_to_send = b'\r\n'.join(data_to_send_lines)
            # Add final \r\n before the .
            data_to_send += b'\r\n'
            
            # 1. Send initial response "+OK top data follows"
            self.transport.write(b"+OK top data follows" + POP3_LINE_TERM)
            
            # 2. Send the constructed data
            await self._send_data_chunks(data_to_send)
            
            print(f"[SERVER] (TOP) Finished sending top data ({num_lines} lines).")
            
        except Exception as e:
            print(f"[SERVER] (TOP) Error sending top data: {e}")
            traceback.print_exc()
        # Note: TOP does not trigger file deletion

    async def _send_data_chunks(self, data_to_send):
        """Helper to send data in chunks with optional delay."""
        if self.chunk_size is None or self.chunk_size <= 0 or self.chunk_size >= len(data_to_send):
            # Send all at once
            print(f"[SERVER] Sending data in one chunk of {len(data_to_send)} bytes.")
            self.transport.write(data_to_send)
        else:
            # Send in chunks
            print(f"[SERVER] Sending data in chunks of {self.chunk_size} bytes.")
            for i in range(0, len(data_to_send), self.chunk_size):
                if not self.transport or self.transport.is_closing():
                    print("[SERVER] Transport closed during chunked send, aborting.")
                    break
                chunk = data_to_send[i:i+self.chunk_size]
                print(f"[SERVER] Sending chunk {i//self.chunk_size + 1} ({len(chunk)} bytes)")
                self.transport.write(chunk)
                # Await the delay only if it's not the last chunk and delay is set
                if self.delay and i + self.chunk_size < len(data_to_send):
                    print(f"[SERVER] Waiting {self.delay} seconds before next chunk...")
                    await asyncio.sleep(self.delay)
        
        # Always end multi-line data responses with the POP3 terminator
        self.transport.write(b"." + POP3_LINE_TERM)


    def connection_lost(self, exc):
        """Called when the connection is lost."""
        print("[SERVER] Connection lost")
        # Do not delete file on connection loss, only on successful RETR send
        self._current_mail_file_path = None

async def main(mail_dir_path, port, chunk_size=None, delay=None, delete_after_send=False):
    """Main function to start the server."""
    # Validate mail directory path
    if not os.path.isdir(mail_dir_path):
        print(f"[MAIN] Error: Path '{mail_dir_path}' is not a valid directory.")
        sys.exit(1)
        
    # Validate chunk_size and delay
    if chunk_size is not None and chunk_size <= 0:
        print("[MAIN] Warning: Invalid chunk_size, sending in one piece.")
        chunk_size = None
    if delay is not None and delay < 0:
        print("[MAIN] Warning: Invalid delay, setting to 0.")
        delay = 0

    # Start server
    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: POP3FuzzServerProtocol(mail_dir_path, chunk_size, delay, delete_after_send),
        '127.0.0.1', port)
    
    action = "served and deleted" if delete_after_send else "served"
    print(f"[MAIN] POP3 Fuzz Server listening on 127.0.0.1:{port}")
    print(f"[MAIN] Serving mails from directory '{mail_dir_path}'")
    print(f"[MAIN] Mails will be {action} one by one.")
    if chunk_size:
        print(f"[MAIN] Data will be sent in chunks of {chunk_size} bytes.")
    if delay:
        print(f"[MAIN] Delay of {delay} seconds between chunks.")
    print("[MAIN] Press Ctrl-C to stop.")
    
    try:
        async with server:
            await server.serve_forever()
    except KeyboardInterrupt:
        print("\n[MAIN] Server stopped by user.")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python fuzz_pop3_server.py <mail_directory> <port> [chunk_size] [delay_seconds] [--delete]")
        print("    mail_directory    : Path to the directory containing .eml files to serve.")
        print("    port              : Port number for the server to listen on (e.g., 8110).")
        print("    chunk_size        : (Optional) Size of data chunks to send. If omitted, sends all at once.")
        print("    delay_seconds     : (Optional) Delay in seconds between sending chunks.")
        print("    --delete          : (Optional) Delete each .eml file from the directory after it's sent.")
        print("\nExample: python fuzz_pop3_server.py ./fuzz_mails 8110 100 0.1 --delete")
        sys.exit(1)

    mail_dir_path = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print("[MAIN] Error: Port must be an integer.")
        sys.exit(1)
    
    chunk_size = None
    delay = None
    delete_after_send = False
    
    # Parse optional arguments
    for i in range(3, len(sys.argv)):
        arg = sys.argv[i]
        if arg == "--delete":
            delete_after_send = True
        elif chunk_size is None:
            try:
                chunk_size = int(arg)
            except ValueError:
                print(f"[MAIN] Warning: Argument '{arg}' is not a valid integer for chunk_size, ignoring.")
        elif delay is None:
            try:
                delay = float(arg)
            except ValueError:
                print(f"[MAIN] Warning: Argument '{arg}' is not a valid number for delay_seconds, ignoring.")
        else:
            print(f"[MAIN] Warning: Ignoring extra argument '{arg}'.")

    asyncio.run(main(mail_dir_path, port, chunk_size, delay, delete_after_send))