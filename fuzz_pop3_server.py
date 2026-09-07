import asyncio
import sys
import os
import traceback
import glob
import base64
import shutil

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
        self._buffer = b""  # 行缓冲: 累积TCP分段数据，按完整行处理
        self.mail_dir_path = mail_dir_path # Store the path to the directory of .eml files
        self.chunk_size = chunk_size
        self.delay = delay # Delay in seconds between chunks
        self.delete_after_send = delete_after_send # Whether to delete the file after sending
        self._current_mail_file_path = None # Path of the mail file currently being served
        # For handling SASL AUTH command flow
        self._awaiting_auth_response_for_mechanism = None
        # To ensure data is fully sent before closing connection on QUIT
        self._current_send_task = None
        self.target_directory = "./fuzzed_pop3_mails_bak"
        os.makedirs(self.target_directory, exist_ok=True)

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
        """Called when data is received from the client.

        TCP 可能将一条命令分段送达，因此先把数据累积到缓冲区，
        只有收到以 \\n 结尾的完整行才解析，残余部分留在缓冲区。
        """
        self._buffer += data
        while True:
            newline_idx = self._buffer.find(b"\n")
            if newline_idx == -1:
                break  # 尚无完整行，等待更多数据
            line = self._buffer[:newline_idx].rstrip(b"\r")  # 兼容 \r\n 和 \n 结尾
            self._buffer = self._buffer[newline_idx + 1:]
            self._process_line(line)

    def _process_line(self, line):
        """处理一条完整的POP3命令行（保留原有命令解析逻辑）。"""
        try:
            # Decode command
            message = line.decode('utf-8', errors='ignore')
            print(f"[SERVER] Received: {message}")
            parts = message.split(' ')
            command = parts[0].upper() if parts else ""

            # --- Handle Awaiting AUTH Response ---
            if self._awaiting_auth_response_for_mechanism:
                # We were waiting for the Base64 encoded initial response line
                mechanism = self._awaiting_auth_response_for_mechanism
                # Clear the flag first
                self._awaiting_auth_response_for_mechanism = None
                
                # 'message' contains the Base64 encoded initial response
                # For fuzzing, we don't need to decode or verify it
                print(f"[SERVER] (AUTH) Received response line for {mechanism}: {message}")
                
                # Simplified: assume authentication is successful for fuzzing
                self.state = "TRANSACTION"
                self.transport.write(b"+OK Logged in." + POP3_LINE_TERM)
                return # Crucial: stop processing this line as a regular command
            # --- End Handle Awaiting AUTH Response ---

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
                elif command == "AUTH":
                    # AUTH mechanism [initial-response]: RFC 1734 / RFC 2595 / RFC 4616 (PLAIN)
                    # parts = ['AUTH', 'MECHANISM', 'optional_base64_initial_response']
                    if len(parts) < 2:
                        self.transport.write(b"-ERR Invalid AUTH command" + POP3_LINE_TERM)
                        return
                        
                    mechanism = parts[1].upper()
                    
                    if mechanism != "PLAIN":
                        self.transport.write(f"-ERR Unsupported authentication mechanism: {mechanism}".encode('utf-8') + POP3_LINE_TERM)
                        return

                    # Check if initial response is provided
                    if len(parts) >= 3 and parts[2]:
                        # Initial response provided in the same line (e.g., AUTH PLAIN <base64>)
                        # For fuzzing, we can just accept it.
                        print(f"[SERVER] (AUTH) Received initial response for {mechanism}")
                        # For fuzzing, assume success
                        self.state = "TRANSACTION"
                        self.transport.write(b"+OK Logged in." + POP3_LINE_TERM)
                    else:
                        # No initial response provided. RFC requires server to send "+ " 
                        # and then read the response from the client.
                        print(f"[SERVER] (AUTH) Waiting for initial response for {mechanism}")
                        # Set flag and send continuation request
                        self._awaiting_auth_response_for_mechanism = mechanism
                        self.transport.write(b"+ " + POP3_LINE_TERM)
                elif command == "QUIT":
                    # QUIT: RFC 1939 Section 6
                    self.transport.write(b"+OK Bye" + POP3_LINE_TERM)
                    self.transport.close()
                elif command == "CAPA":
                    # Optional CAPA command for extended capabilities (RFC 2449)
                    self.transport.write(b"+OK" + POP3_LINE_TERM)
                    # Advertise capabilities we (partially) support or are common
                    # Note: Our AUTH is USER/PASS and simplified AUTH PLAIN, not full SASL AUTH command advertisement.
                    self.transport.write(b"TOP" + POP3_LINE_TERM)
                    self.transport.write(b"UIDL" + POP3_LINE_TERM)
                    # Indicate we support USER command authentication
                    self.transport.write(b"USER" + POP3_LINE_TERM)
                    # Indicate we support simplified AUTH PLAIN
                    self.transport.write(b"SASL PLAIN" + POP3_LINE_TERM)
                    # End of capability list
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
                        if self.delete_after_send and self._current_mail_file_path and os.path.exists(self._current_mail_file_path):
                            try:
                                # os.remove(self._current_mail_file_path)
                                target_path = os.path.join(self.target_directory, os.path.basename(self._current_mail_file_path))
                                shutil.move(self._current_mail_file_path, target_path)

                                print(f"[SERVER] (RETR) Deleted mail file '{self._current_mail_file_path}'")
                            except OSError as e:
                                print(f"[SERVER] (RETR) Failed to delete mail file '{self._current_mail_file_path}': {e}")
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
                    # Store the task to allow QUIT to wait for its completion
                    self._current_send_task = asyncio.create_task(self.send_mail_data(mail_data))
                    
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
                    
                     # Send the email data asynchronously
                     # Store the task to allow QUIT to wait for its completion
                     self._current_send_task = asyncio.create_task(self.send_top_data(mail_data, lines))
                     
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
                    # Schedule a task to handle the QUIT logic asynchronously
                    # This allows awaiting the send task event if necessary.
                    asyncio.create_task(self._handle_quit())
                elif command == "CAPA":
                    # Optional CAPA command for extended capabilities (RFC 2449)
                    self.transport.write(b"+OK" + POP3_LINE_TERM)
                    # Advertise common capabilities available in TRANSACTION state
                    self.transport.write(b"TOP" + POP3_LINE_TERM)
                    self.transport.write(b"UIDL" + POP3_LINE_TERM)
                    # End of capability list
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
        Implements byte-stuffing as per RFC 1939 Section 3.
        """
        try:
            # 1. Apply byte-stuffing: prepend '.' to lines starting with '.'
            stuffed_mail_data = self._apply_byte_stuffing(mail_data)
            
            # 2. Send initial response "+OK octets" (report original size)
            # Note: Reporting original size is common practice, though size on wire is larger.
            response_line = f"+OK {len(mail_data)} octets"
            self.transport.write(response_line.encode('utf-8') + POP3_LINE_TERM)
            
            # 3. Send the stuffed mail data
            await self._send_data_chunks(stuffed_mail_data)
            
            # 4. Send the End-of-Block (EOB) marker as per RFC 1939
            print("[SERVER] (RETR) Finished sending mail data stream.")
            
            # 5. After successful send, optionally delete the file
            if self.delete_after_send and self._current_mail_file_path and os.path.exists(self._current_mail_file_path):
                try:
                    #os.remove(self._current_mail_file_path)
                    target_path = os.path.join(self.target_directory, os.path.basename(self._current_mail_file_path))
                    shutil.move(self._current_mail_file_path, target_path)
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
            # Note: Do not clear _current_send_task here to ensure _handle_quit waits
            # for the entire coroutine to finish, including this finally block.
            
        # Clear the reference to the finished task AFTER the coroutine is truly done.
        # This ensures _handle_quit's 'await self._current_send_task' waits for
        # absolutely everything in this function to complete.
        # --- TEST DELAY TO ENSURE DATA IS FLUSHED ---
        # await asyncio.sleep(0.1) # Uncomment this line for testing
        # --- TEST DELAY TO ENSURE DATA IS FLUSHED ---
        self._current_send_task = None
        # The transport/connection lifecycle is managed by the main command loop (QUIT).

    async def send_top_data(self, mail_data, num_lines):
        """
        Asynchronously send the headers and top 'num_lines' of body.
        Implements byte-stuffing as per RFC 1939 Section 3.
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
            
            # 1. Apply byte-stuffing to the data to be sent
            stuffed_data_to_send = self._apply_byte_stuffing(data_to_send)

            # 2. Send initial response "+OK top data follows"
            self.transport.write(b"+OK top data follows" + POP3_LINE_TERM)
            
            # 3. Send the stuffed constructed data
            await self._send_data_chunks(stuffed_data_to_send)
            
            print(f"[SERVER] (TOP) Finished sending top data ({num_lines} lines).")
            
        except Exception as e:
            print(f"[SERVER] (TOP) Error sending top data: {e}")
            traceback.print_exc()
        finally:
            # Note: Do not clear _current_send_task here to ensure _handle_quit waits
            # for the entire coroutine to finish, including this finally block.
            pass # Explicit pass for clarity if the finally block is empty otherwise
            
        # Clear the reference to the finished task AFTER the coroutine is truly done.
        # This ensures _handle_quit's 'await self._current_send_task' waits for
        # absolutely everything in this function to complete.
        self._current_send_task = None
        # Note: TOP does not trigger file deletion

    async def _send_data_chunks(self, data_to_send):
        """Helper to send data in chunks with optional delay."""
        if self.chunk_size is None or self.chunk_size <= 0 or self.chunk_size >= len(data_to_send):
            # Send all at once
            print(f"[SERVER] Sending data in one chunk of {len(data_to_send)} bytes.")
            self.transport.write(data_to_send)
            # Yield control to allow the event loop to flush the write buffer
            await asyncio.sleep(0)
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
                # Yield control to allow the event loop to flush the write buffer
                await asyncio.sleep(0)
                # Await the delay only if it's not the last chunk and delay is set
                if self.delay and i + self.chunk_size < len(data_to_send):
                    print(f"[SERVER] Waiting {self.delay} seconds before next chunk...")
                    await asyncio.sleep(self.delay)
        
        # Always end multi-line data responses with the POP3 terminator
        print("[SERVER] (RETR) About to send EOB marker.")
        self.transport.write(b"." + POP3_LINE_TERM)
        print("[SERVER] (RETR) EOB marker sent.")



    def connection_lost(self, exc):
        """Called when the connection is lost."""
        print("[SERVER] Connection lost")
        # Do not delete file on connection loss, only on successful RETR send
        self._current_mail_file_path = None
        # Clear send task reference
        self._current_send_task = None

    def _apply_byte_stuffing(self, data):
        """
        Applies byte-stuffing to the data as per RFC 1939 Section 3.
        Any line beginning with a '.' (0x2E) character MUST be "stuffed"
        with an additional '.' (0x2E) character at the beginning of the line.
        This function takes bytes and returns bytes.
        """
        if not data:
            return data
            
        # Split into lines, preserving line endings
        lines = data.splitlines(True) 
        stuffed_lines = []
        for line in lines:
            # Check if the line starts with '.' (0x2E)
            # line could be '...\r\n' or '...\n' or just '...'
            if line.startswith(b'.'):
                # Prepend an additional '.'
                stuffed_lines.append(b'.' + line)
            else:
                stuffed_lines.append(line)
                
        # Join the stuffed lines back together
        stuffed_data = b''.join(stuffed_lines)
        return stuffed_data

    async def _handle_quit(self):
        """Asynchronously handle the QUIT command, ensuring data is sent first."""
        try:
            # Capture the task reference atomically
            send_task_to_wait = self._current_send_task
            
            # Ensure any ongoing send task (RETR/TOP) finishes before closing
            if send_task_to_wait is not None and not send_task_to_wait.done():
                print("[SERVER] (QUIT) Waiting for ongoing send task to finish...")
                # Wait for the send task to complete
                await send_task_to_wait
                print("[SERVER] (QUIT) Ongoing send task finished.")
            elif send_task_to_wait is not None:
                 print("[SERVER] (QUIT) Send task was already finished.")
            else:
                 print("[SERVER] (QUIT) No send task was in progress.")

            # --- Small delay to potentially force event loop flush ---
            # This is a workaround attempt for data not appearing to send immediately.
            # It's not a standard solution but might help in some environments.
            # await asyncio.sleep(0.01) 
            
            self.state = "AUTHORIZATION" # Reset state for potential new connection
            # Do not delete file on QUIT, only on successful RETR send
            self._current_mail_file_path = None
            # Clear send task reference
            self._current_send_task = None
            if self.transport and not self.transport.is_closing():
                self.transport.write(b"+OK Bye" + POP3_LINE_TERM)
                print("[SERVER] (QUIT) Sent +OK Bye.")
                # Revert to close for now to see if write_eof was the issue
                self.transport.close()
                print("[SERVER] (QUIT) Connection closed.")
            else:
                print("[SERVER] (QUIT) Transport was already closing.")
        except Exception as e:
            print(f"[SERVER] Error in _handle_quit: {e}")
            traceback.print_exc()
            # Attempt to close transport if an error occurs
            if self.transport and not self.transport.is_closing():
                 self.transport.close()

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