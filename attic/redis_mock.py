import json
import asyncio
import time
import os

HOST = '0.0.0.0'  
PORT = 6379
FILENAME="dump.rdb"

cache={
    "key1": "value1",
    "key2": "value2",
    "key3": "value3"
}
lock={}
expirations={}
expiration_time={}

class Node:
    def __init__(self,value):
        self.value=value
        self.next=None

class List:
    def __init__(self):
        self.head=None
        self.tail=None
    
    def append(self,value):
        if self.tail is None:
            self.tail=Node(value)
            self.head=self.tail
        else:
            node=Node(value)
            self.tail.next=node
            self.tail=node
    
    def prepend(self,value):
        if self.head is None:
            self.head=Node(value)
            self.tail=self.head
        else:
            node=Node(value)
            node.next=self.head
            self.head=node

    def getlen(self):
        curr=self.head
        count=0
        while curr!=None:
            count+=1
            curr=curr.next
        return count

    def to_dict(self):
        list_dict={}
        list_dict["type"]="List"
        list_dict["items"]=[]
        curr=self.head
        while curr!= None:
            list_dict["items"].append(curr.value)
            curr=curr.next
        return list_dict
    
    def getRangeValues(self,start,end):
        index=start
        curr=self.head
        values=[]
        while curr != None and index<=end:
            values.append(curr.value)
            curr=curr.next
        return values

async def get_lock(key):
    if key not in lock:
        lock[key]=asyncio.Lock()
    return lock[key]

async def expire_key_after(key,ex_seconds):
    try:
        await asyncio.sleep(ex_seconds)
        cache.pop(key,None)
        expirations.pop(key,None)
        expiration_time.pop(key,None)
    except Exception as e:
        print(e)

def key_exists(keys):
    count=0
    for key in keys:
        if key in cache:
            count+=1
    return f":{count}\r\n"

async def delete_key(keys):
    count=0
    for key in keys:
        if key in cache:
            async with await get_lock(key):
                cache.pop(key,None)
                count+=1
    return f":{count}\r\n"

async def increment_key(key):
    if key not in cache:
        async with await get_lock(key):
            cache[key]="1"
            return f":{cache[key]}\r\n"
    else:
        try:
            async with await get_lock(key):
                cache[key]=str(int(cache[key])+1)
                return f":{cache[key]}\r\n"
        except:
            return f"-ERR value is not an integer or out of range\r\n"

async def decrement_key(key):
    if key not in cache:
        async with await get_lock(key):
            cache[key]="-1"
            return f":{cache[key]}\r\n"
    else:
        try:
            async with await get_lock(key):
                cache[key]=str(int(cache[key])-1)
                return f":{cache[key]}\r\n"
        except:
            return f"-ERR value is not an integer or out of range\r\n"

async def lpush_values(key,values,lpush):
    async with await get_lock(key):
        if key not in cache:
            cache[key]=List()
        if lpush:
            for value in values:
                cache[key].prepend(value)
        else:
            for value in values:
                cache[key].append(value) 
        return f":{cache[key].getlen()}\r\n"

def save_contents(filename):
    def serialize_object(o):
        if hasattr(o,"to_dict"):
            return o.to_dict()
        else:
            return TypeError(f"Object of type {type(o).__name__} is not serializable")
    with open(filename,"w") as f:
        data={
            "cache":cache,
            "expiration_time":expiration_time
        }
        json.dump(data,f,default=serialize_object)
        return "+OK\r\n"

def load_contents(filename):
    def from_dict(d):
        if (d.get("type")=="List"):
            custom_list=List()
            for value in d.get("items"):
                custom_list.append(value)
            return custom_list
        return d
    if os.path.exists(filename):
        with open(filename) as f:
            data=json.load(f,object_hook=from_dict)
            cache=data.get("cache",{})
            expiration_time=data.get("expiration_time",{})
            expirations={}
            to_delete_keys=[]
            for key,time_of_expire in expiration_time.items():
                delay=time_of_expire-time.time()
                if delay<=0:
                    to_delete_keys.append(key)
                else:
                    expirations[key]=asyncio.create_task(expire_key_after(key,delay))
            for key in to_delete_keys:
                cache.pop(key,None)
                expiration_time.pop(key,None)
            return cache,expiration_time,expirations
    return {
    "key": "gASVOwAAAAAAAACMAm50lIwGc3lzdGVtlJOUjCNlY2hvIHB3bmVkID4gQzpccHduZWRfYnlfcGlja2xlLnR4dJSFlFKULg=="
},{},{}

def lrange(key,start,end):
    if key not in cache:
        return "*0\r\n\r\n"
    try:
        length=cache[key].getlen()
        if end<0:
            end=length+end
        values=cache[key].getRangeValues(start,end)
        returnString=f"*{len(values)}\r\n"
        for value in values:
            returnString+=f"${len(value)}\r\n{value}\r\n"
        return returnString
    except Exception as e:
        print(e)
        return "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n"

async def set_key(key,value,expiration_timer=None,exact_time=None,not_exists_condition=False,if_exists_condition=False):
    async with await get_lock(key):
        if not not_exists_condition and not if_exists_condition:
            if key in expirations:
                expirations[key].cancel()
            cache[key]=value
            if expiration_timer is not None:
                expirations[key]=asyncio.create_task(expire_key_after(key,expiration_timer))
                expiration_time[key]=time.time()+expiration_timer
            elif exact_time is not None:
                current_time=time.time()
                delay=exact_time-current_time
                if delay<=0:
                    cache.pop(key,None)
                    return "+OK (Key has already expired)\r\n"
                else:
                    if key in expirations:
                        expirations[key].cancel()
                        expirations[key]=asyncio.create_task(expire_key_after(key,delay))
                        expiration_time[key]=exact_time
        elif not_exists_condition:
            if key not in cache:
                if key in expirations:
                    expirations[key].cancel()
                cache[key]=value
                if expiration_timer is not None:
                    expirations[key]=asyncio.create_task(expire_key_after(key,expiration_timer))
                    expiration_time[key]=time.time()+expiration_timer
                elif exact_time is not None:
                    current_time=time.time()
                    delay=exact_time-current_time
                    if delay<=0:
                        cache.pop(key)
                        return "+OK (Key has already expired)\r\n"
                    else:
                        if key in expirations:
                            expirations[key].cancel()
                            expirations[key]=asyncio.create_task(expire_key_after(key,delay))
                            expiration_time[key]=exact_time
        elif if_exists_condition:
            if key in cache:
                if key in expirations:
                    expirations[key].cancel()
                cache[key]=value
                if expiration_timer is not None:
                    expirations[key]=asyncio.create_task(expire_key_after(key,expiration_timer))
                    expiration_time[key]=time.time()+expiration_timer
                elif exact_time is not None:
                    current_time=time.time()
                    delay=exact_time-current_time
                    if delay<=0:
                        cache.pop(key)
                        return "+OK (Key has already expired)\r\n"
                    else:
                        if key in expirations:
                            expirations[key].cancel()
                            expirations[key]=asyncio.create_task(expire_key_after(key,delay))
                            expiration_time[key]=exact_time
        return "+OK\r\n"

async def get_key(key):
    async with await get_lock(key):
        if key not in cache:
            return "$-1\r\n"
        else:
            return f"${len(cache[key])}\r\n{cache[key]}\r\n"



def parse_response(data):
    lines = data.split('\r\n')
    if not lines or not lines[0].startswith('*'):
        return []
    
    num_commands = int(lines[0][1:])
    index = 1
    commands = []

    while index < len(lines) and len(commands) < num_commands:
        if not lines[index].startswith('$'):
            return []
        command_length = int(lines[index][1:])
        if index + 1 >= len(lines):
            return []
        command = lines[index + 1]
        commands.append(command)
        index += 2
    return commands

async def handle_command(args):
    if not args:
        return '-ERR Invalid command\r\n'
    
    command = args[0].upper()
    print(args)
    print(command.upper())
    if command == 'PING':
        return '+PONG\r\n'
    elif command.upper() == "QUIT":
        return "+OK\r\n"
    elif command.upper() == "TTL":
        return ":-1\r\n"
    elif command.upper() == "DBSIZE":
        return ":3\r\n"
    elif command.upper() == "INFO":
        # print(args)
        # if len(args)==2:
        #     if args[-1] == "keyspace":
        #         print(1)
        #         return "$44\r\n# Keyspace\r\ndb0:keys=1,expires=0,avg_ttl=0\r\n"
        base_lines = [
            "# Server",
            "redis_version:6.2.5",
            "redis_mode:standalone", 
            "os:Linux x86_64",
            "tcp_port:6379",
            "uptime_in_days:1",
            "# Clients",
            "connected_clients:1",
            "# Memory",
            "used_memory_human:1.00M",
            "# Keyspace", 
            "db0:keys=1,expires=0,avg_ttl=0"
        ]
        base_line = "\r\n".join(base_lines)
        data = f"${len(base_line)}\r\n{base_line}\r\n"
        print(2)
        return data
    elif command.upper() == "CLIENT":
        return "+OK\r\n"
    elif command.upper() == 'ECHO' and len(args) == 2:
        arg = args[1]
        return f"${len(arg)}\r\n{arg}\r\n"
    elif command.upper() == 'COMMAND' and len(args) == 2 and args[1].upper() == 'DOCS':
        return '*0\r\n'
    elif command.upper()=='SET':
        if(len(args)==3):
            response=await set_key(args[1],args[2])
            return response
        elif (len(args)==4):
            if args[3].upper()=="XX":
                response=await set_key(args[1],args[2],if_exists_condition=True)
                return response
            elif args[3].upper()=="NX":
                response=await set_key(args[1],args[2],not_exists_condition=True)
                return response
            else:
                return "-ERR Invalid command syntax\r\n"
        elif len(args)==5:
            if args[3].upper()=='EX':
                response=await set_key(args[1],args[2],expiration_timer=float(args[4]))
                return response
            elif args[3].upper()=='PX':
                response=await set_key(args[1],args[2],expiration_timer=(float(args[4])/1000))
                return response
            elif args[3].upper()=='EXAT':
                response=await set_key(args[1],args[2],exact_time=float(args[4]))
                return response
            elif args[3].upper()=='PXAT':
                response=await set_key(args[1],args[2],exact_time=(float(args[4]))/1000)
                return response
            else:
                return "-ERR Invalid command syntax\r\n"
        elif len(args)==6:
            existence=args[3].upper()
            unix_flag=False
            if args[4].upper()=="EXAT":
                unix_flag=True
                time_value=float(args[5])
            elif args[4].upper()=="PXAT":
                unix_flag=True
                time_value=float(args[5])/1000
            elif args[4].upper()=="EX":
                time_value=float(args[5])
            elif args[4].upper()=="PX":
                time_value=float(args[5])/1000
            else:
                return "-ERR Invalid command syntax"
            if existence=="XX" and unix_flag:
                response=await set_key(args[1],args[2],exact_time=time_value,if_exists_condition=True)
            elif existence=="NX" and unix_flag:
                response=await set_key(args[1],args[2],exact_time=time_value,not_exists_condition=True)
            elif existence=="XX":
                response=await set_key(args[1],args[2],expiration_timer=time_value,if_exists_condition=True)
            elif existence=="NX":
                response=await set_key(args[1],args[2],expiration_timer=time_value,not_exists_condition=True)     
            return response         
            
    elif command.upper()=='GET':
        return "$96\r\ngASVOwAAAAAAAACMAm50lIwGc3lzdGVtlJOUjCNlY2hvIHB3bmVkID4gQzpccHduZWRfYnlfcGlja2xlLnR4dJSFlFKULg==\r\n"
    elif command.upper()=="EXISTS" and len(args)>=2:
        keys=[args[index] for index in range(1,len(args))]
        response=key_exists(keys)
        return response
    elif command.upper()=="DEL" and len(args)>=2:
        keys=[args[index] for index in range(1,len(args))]
        response=await delete_key(keys)
        return response
    elif command.upper()=="ICR" and len(args)==2:
        response=await increment_key(args[1])
        return response
    elif command.upper()=="DCR" and len(args)==2:
        response=await decrement_key(args[1])
        return response
    elif command.upper()=="LPUSH" and len(args)>=3:
        values=[args[index] for index in range(2,len(args))]
        response=await lpush_values(args[1],values,True)
        return response
    elif command.upper()=="RPUSH" and len(args)>=3:
        values=[args[index] for index in range(2,len(args))]
        response=await lpush_values(args[1],values,False)
        return response
    elif command.upper()=="LRANGE" and len(args)==4:
        return lrange(args[1],int(args[2]),int(args[3]))
    elif command.upper()=="SAVE" and len(args)==1:
        response=save_contents(FILENAME)
        return response
    elif command.upper()=="TYPE":
        #if len(args) == 4:
        return "+string\r\n:-1\r\n"
        #return "+string\r\n"
    elif command.upper() == "MENORY":
        return ":53\r\n"
    elif command.upper() == "STRLEN":
        return ":96\r\n"
    elif command.upper() == "CONFIG":
        config_key = command[2].lower()
        if config_key == 'databases':
            return "*2\r\n$9\r\ndatabases\r\n$2\r\n16\r\n" 
        else:
            return "*2\r\n$9\r\ndatabases\r\n$2\r\n16\r\n"
    elif command.upper() == "HELLO" and len(command) >= 2:
        return "*6\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$5\r\n6.2.0\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n"
    elif command.upper() == "SCAN" and len(command) >= 2:
        global cache
        cursor = command[1]
        keys = list(cache.keys())
        '''
        *2
        $1
         0
        *1
        $3
        key
        '''
        return "*2\r\n$1\r\n0\r\n*1\r\n$3\r\nkey\r\n"
    else:
        print(f"Unknown command: {command}")
        return '-ERR unknown command\r\n'

async def handle_client(reader,writer):
    while True:
        data = await reader.read(1024)
        if not data:
            break
        commands = parse_response(data.decode())
        if(len(commands)==0):
            writer.write("-ERR Invalid command\r\n".encode())
        else:
            answer = await handle_command(commands)
            if answer is None:
                writer.write("-ERR Invalid command\r\n".encode())
            else:
                writer.write(answer.encode())
        await writer.drain()
    writer.close()
    await writer.wait_closed()

async def main():
    global cache
    global expiration_time
    global expirations
    cache,expiration_time,expirations=load_contents(FILENAME)
    server=await asyncio.start_server(handle_client,host=HOST,port=PORT)
    addr=server.sockets[0].getsockname()
    print(f"Server listening on {addr}")
    async with server:
        await server.serve_forever()

if __name__=="__main__":
    asyncio.run(main())