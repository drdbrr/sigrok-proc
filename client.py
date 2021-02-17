#!/usr/bin/env python
import asyncio
import json
import sys
import functools

loop = asyncio.get_event_loop()

async def main():
    reader, writer = await asyncio.open_unix_connection('/home/drjacka/tst.sock')
    isRun = False
    sz = int(4096)    
    while True:
        x = input()
        if x:
            if x == 'a':
                tx_data = {'get':['drivers']}
                msg = json.dumps(tx_data)
                writer.write(msg.encode())
                await writer.drain()
                resp = await reader.read(sz)
                if resp[0] == 16:
                    dd = json.loads(resp[1:])
                    print(dd)
                
            if x == 'b':
                tx_data = {'set':{'driver':'fx2lafw'}}
                msg = json.dumps(tx_data)
                writer.write(msg.encode())
                await writer.drain()
                resp = await reader.read(sz)
                if resp[0] == 16:
                    dd = json.loads(resp[1:])
                    print("Driver set:", dd)
                
            if x == 'c':
                tx_data = {'get':['scan']}
                msg = json.dumps(tx_data)
                writer.write(msg.encode())
                await writer.drain()
                resp = await reader.read(sz)
                if resp[0] == 16:
                    dd = json.loads(resp[1:])
                    print("Scan:", dd)
                
            if x == 'd':
                tx_data = {'set':{'dev_num':0}}
                msg = json.dumps(tx_data)
                writer.write(msg.encode())
                await writer.drain()
                resp = await reader.read(sz)
                if resp[0] == 16:
                    dd = json.loads(resp[1:])
                    print("Set devnum:", dd)
                
                            
            if x == 'e':
                isRun = not isRun
                tx_data = {'set':{'run_session':int(isRun)}}
                msg = json.dumps(tx_data)
                writer.write(msg.encode())
                await writer.drain()
                resp = await reader.read(sz)
                if resp[0] == 16:
                    dd = json.loads(resp[1:])
                    print("Session run:", dd)
                
            if x == 'g':
                isRun = not isRun
                tx_data = {'get':['samplerates', 'sample']}
                msg = json.dumps(tx_data)
                writer.write(msg.encode())
                await writer.drain()
                resp = await reader.read(sz)
                if resp[0] == 16:
                    dd = json.loads(resp[1:])
                    print("get samplerates:", dd)
                
            if x == 'f':
                resp = await reader.read(sz)
                dd = json.loads(resp)
                
                if dd['sampling'] == 'end':
                    isRun = False
                print("Read:", dd)
                
        else:
            break


asyncio.run(main())

