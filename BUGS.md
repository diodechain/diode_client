INFO Retry to connect (1/3), waiting 5s server=us2.prenet.diode.io:41046 
==================
WARNING: DATA RACE
Write at 0x00c000792420 by goroutine 14:
  github.com/diodechain/diode_client/rpc.(*Client).SubmitNewTicket.func1()
      /home/runner/work/diode_client/diode_client/rpc/client.go:554 +0x77
  github.com/dominicletz/genserver.(*GenServer).loop()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:78 +0x53
  github.com/dominicletz/genserver.New·dwrap·4()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:49 +0x39
Previous read at 0x00c000792420 by goroutine 372:
  github.com/diodechain/diode_client/rpc.(*Client).SubmitNewTicket()
      /home/runner/work/diode_client/diode_client/rpc/client.go:564 +0x104
  github.com/diodechain/diode_client/rpc.(*ClientManager).doSortTopClients·dwrap·24()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:312 +0x39
Goroutine 14 (running) created at:
  github.com/dominicletz/genserver.New()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:49 +0x3a4
  github.com/diodechain/diode_client/rpc.NewClient()
      /home/runner/work/diode_client/diode_client/rpc/client.go:86 +0x6b
  github.com/diodechain/diode_client/rpc.(*ClientManager).startClient()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:111 +0x1cd
  github.com/diodechain/diode_client/rpc.(*ClientManager).doAddClient()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:101 +0x3e
  github.com/diodechain/diode_client/rpc.(*ClientManager).Start.func1()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:61 +0x2f
  github.com/dominicletz/genserver.(*GenServer).CallTimeout.func1()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:165 +0x30
  github.com/dominicletz/genserver.(*Reply).ReRun()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:115 +0x63
  github.com/dominicletz/genserver.(*GenServer).Call2Timeout.func1()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:134 +0x30
  github.com/dominicletz/genserver.(*GenServer).loop()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:78 +0x53
  github.com/dominicletz/genserver.New·dwrap·4()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:49 +0x39
Goroutine 372 (finished) created at:
  github.com/diodechain/diode_client/rpc.(*ClientManager).doSortTopClients()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:312 +0x4a6
  github.com/diodechain/diode_client/rpc.(*ClientManager).topClient()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:278 +0xd1
  github.com/diodechain/diode_client/rpc.(*ClientManager).GetNearestClient.func1()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:248 +0x18a
  github.com/dominicletz/genserver.(*Reply).ReRun()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:115 +0x63
  github.com/diodechain/diode_client/rpc.(*ClientManager).startClient.func1.1()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:117 +0x137
  github.com/dominicletz/genserver.(*GenServer).loop()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:78 +0x53
  github.com/dominicletz/genserver.New·dwrap·4()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:49 +0x39
==================
INFO Network is validated, last valid block: 3802917 0x00001a2b70c26c4486ec73efb1821e2cfc03ed1b36968237a9e137267473f119
INFO Client connection closed: EOF server=us1.prenet.diode.io:41046 
==================
WARNING: DATA RACE
Read at 0x00c00016e250 by goroutine 8:
  github.com/diodechain/diode_client/rpc.(*Client).averageLatency()
      /home/runner/work/diode_client/diode_client/rpc/client.go:114 +0xad
  github.com/diodechain/diode_client/rpc.ByLatency.Less()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:271 +0x69
  github.com/diodechain/diode_client/rpc.(*ByLatency).Less()
      <autogenerated>:1 +0x29
  sort.insertionSort()
      /opt/hostedtoolcache/go/1.17.11/x64/src/sort/sort.go:40 +0xd0
  sort.quickSort()
      /opt/hostedtoolcache/go/1.17.11/x64/src/sort/sort.go:222 +0x1d4
  sort.Sort()
      /opt/hostedtoolcache/go/1.17.11/x64/src/sort/sort.go:231 +0x64
  github.com/diodechain/diode_client/rpc.(*ClientManager).doSortTopClients()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:299 +0x258
  github.com/diodechain/diode_client/rpc.(*ClientManager).startClient.func2.1()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:159 +0x54b
  github.com/dominicletz/genserver.(*GenServer).loop()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:78 +0x53
  github.com/dominicletz/genserver.New·dwrap·4()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:49 +0x39
Previous write at 0x00c00016e250 by goroutine 11:
  github.com/diodechain/diode_client/rpc.(*Client).addLatencyMeasurement()
      /home/runner/work/diode_client/diode_client/rpc/client.go:118 +0x84
  github.com/diodechain/diode_client/rpc.(*Client).doWatchLatestBlock.func2()
      /home/runner/work/diode_client/diode_client/rpc/client.go:1123 +0x18
  github.com/dominicletz/genserver.(*GenServer).loop()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:78 +0x53
  github.com/dominicletz/genserver.New·dwrap·4()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:49 +0x39
Goroutine 8 (running) created at:
  github.com/dominicletz/genserver.New()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:49 +0x3a4
  github.com/diodechain/diode_client/rpc.NewClientManager()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:45 +0xd8
  main.NewDiode()
      /home/runner/work/diode_client/diode_client/cmd/diode/app.go:194 +0x5f8
  main.prepareDiode()
      /home/runner/work/diode_client/diode_client/cmd/diode/app.go:156 +0x60f
  github.com/diodechain/diode_client/command.run()
      /home/runner/work/diode_client/diode_client/command/command.go:140 +0x6e
  github.com/diodechain/diode_client/command.(*Command).Execute()
      /home/runner/work/diode_client/diode_client/command/command.go:130 +0x40d
  main.main()
      /home/runner/work/diode_client/diode_client/cmd/diode/diode.go:25 +0x48
Goroutine 11 (running) created at:
  github.com/dominicletz/genserver.New()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:49 +0x3a4
  github.com/diodechain/diode_client/rpc.NewClient()
      /home/runner/work/diode_client/diode_client/rpc/client.go:86 +0x6b
  github.com/diodechain/diode_client/rpc.(*ClientManager).startClient()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:111 +0x1cd
  github.com/diodechain/diode_client/rpc.(*ClientManager).doAddClient()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:101 +0x3e
  github.com/diodechain/diode_client/rpc.(*ClientManager).Start.func1()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:61 +0x2f
  github.com/dominicletz/genserver.(*GenServer).CallTimeout.func1()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:165 +0x30
  github.com/dominicletz/genserver.(*Reply).ReRun()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:115 +0x63
  github.com/dominicletz/genserver.(*GenServer).Call2Timeout.func1()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:134 +0x30
  github.com/dominicletz/genserver.(*GenServer).loop()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:78 +0x53
  github.com/dominicletz/genserver.New·dwrap·4()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:49 +0x39
==================
==================
WARNING: DATA RACE
Read at 0x00c00016e258 by goroutine 8:
  github.com/diodechain/diode_client/rpc.(*Client).averageLatency()
      /home/runner/work/diode_client/diode_client/rpc/client.go:114 +0xca
  github.com/diodechain/diode_client/rpc.ByLatency.Less()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:271 +0x69
  github.com/diodechain/diode_client/rpc.(*ByLatency).Less()
      <autogenerated>:1 +0x29
  sort.insertionSort()
      /opt/hostedtoolcache/go/1.17.11/x64/src/sort/sort.go:40 +0xd0
  sort.quickSort()
      /opt/hostedtoolcache/go/1.17.11/x64/src/sort/sort.go:222 +0x1d4
  sort.Sort()
      /opt/hostedtoolcache/go/1.17.11/x64/src/sort/sort.go:231 +0x64
  github.com/diodechain/diode_client/rpc.(*ClientManager).doSortTopClients()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:299 +0x258
  github.com/diodechain/diode_client/rpc.(*ClientManager).startClient.func2.1()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:159 +0x54b
  github.com/dominicletz/genserver.(*GenServer).loop()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:78 +0x53
  github.com/dominicletz/genserver.New·dwrap·4()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:49 +0x39
Previous write at 0x00c00016e258 by goroutine 11:
  github.com/diodechain/diode_client/rpc.(*Client).addLatencyMeasurement()
      /home/runner/work/diode_client/diode_client/rpc/client.go:119 +0xc4
  github.com/diodechain/diode_client/rpc.(*Client).doWatchLatestBlock.func2()
      /home/runner/work/diode_client/diode_client/rpc/client.go:1123 +0x18
  github.com/dominicletz/genserver.(*GenServer).loop()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:78 +0x53
  github.com/dominicletz/genserver.New·dwrap·4()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:49 +0x39
Goroutine 8 (running) created at:
  github.com/dominicletz/genserver.New()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:49 +0x3a4
  github.com/diodechain/diode_client/rpc.NewClientManager()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:45 +0xd8
  main.NewDiode()
      /home/runner/work/diode_client/diode_client/cmd/diode/app.go:194 +0x5f8
  main.prepareDiode()
      /home/runner/work/diode_client/diode_client/cmd/diode/app.go:156 +0x60f
  github.com/diodechain/diode_client/command.run()
      /home/runner/work/diode_client/diode_client/command/command.go:140 +0x6e
  github.com/diodechain/diode_client/command.(*Command).Execute()
      /home/runner/work/diode_client/diode_client/command/command.go:130 +0x40d
  main.main()
      /home/runner/work/diode_client/diode_client/cmd/diode/diode.go:25 +0x48
Goroutine 11 (running) created at:
  github.com/dominicletz/genserver.New()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:49 +0x3a4
  github.com/diodechain/diode_client/rpc.NewClient()
      /home/runner/work/diode_client/diode_client/rpc/client.go:86 +0x6b
  github.com/diodechain/diode_client/rpc.(*ClientManager).startClient()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:111 +0x1cd
  github.com/diodechain/diode_client/rpc.(*ClientManager).doAddClient()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:101 +0x3e
  github.com/diodechain/diode_client/rpc.(*ClientManager).Start.func1()
      /home/runner/work/diode_client/diode_client/rpc/client_manager.go:61 +0x2f
  github.com/dominicletz/genserver.(*GenServer).CallTimeout.func1()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:165 +0x30
  github.com/dominicletz/genserver.(*Reply).ReRun()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:115 +0x63
  github.com/dominicletz/genserver.(*GenServer).Call2Timeout.func1()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:134 +0x30
  github.com/dominicletz/genserver.(*GenServer).loop()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:78 +0x53
  github.com/dominicletz/genserver.New·dwrap·4()
      /home/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:49 +0x39
==================

### connectedport.go:103
06/13/2022 19:45:48 DEBUG 0: Open port 0xc0030003c0 via=eu2.prenet.diode.io:41046 dst=0x84c485c62cdd878ce795aa90f269f84b5ae4fa0e
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x50 pc=0x44e0653]

goroutine 30193027 [running]:
github.com/diodechain/diode_client/rpc.(*ConnectedPort).bufferRunner(0xc0008d40f0)
        /Users/runner/work/diode_client/diode_client/rpc/connectedport.go:103 +0x2d3
created by github.com/diodechain/diode_client/rpc.(*ConnectedPort).SendLocal.func1
        /Users/runner/work/diode_client/diode_client/rpc/connectedport.go:211 +0xb3


### client.go:218

05/31/2022 14:18:00 INFO Retry to connect (2/3), waiting 6.432317078s server=us2.prenet.diode.io:41046
GenServer WARNING timeout in Client:541595
GenServer couldn't find Server stacktrace
Client Stacktrace:
goroutine 541712 [running]:
github.com/dominicletz/genserver.defaultErrorMessage(0xc005438440, {0x0, 0x722f746e65696c63})
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:65 +0x53
github.com/dominicletz/genserver.DefaultDeadlockCallback(0xc005438440, {0x0, 0x0})
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:56 +0x1e
github.com/dominicletz/genserver.(*GenServer).handleTimeout(0xc005438440)
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:208 +0x165
github.com/dominicletz/genserver.(*GenServer).Call2Timeout(0xc005438440, 0xc00dcaa660, 0x6fc23ac00)
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:144 +0x1c5
github.com/dominicletz/genserver.(*GenServer).CallTimeout(0xc005438440, 0xc00d1b8ce0, 0x4881da0)
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:164 +0x97
github.com/diodechain/diode_client/rpc.(*Client).callTimeout(...)
        /Users/runner/work/diode_client/diode_client/rpc/client.go:218
github.com/diodechain/diode_client/rpc.(*Client).insertCall(0xc0082d5180, 0xc00dc24d70)
        /Users/runner/work/diode_client/diode_client/rpc/client.go:243 +0xb5
github.com/diodechain/diode_client/rpc.(*Client).CastContext(0x1010000048a5160, 0x0, {0x48b4750, 0x8}, {0xc010b1fc78, 0x1, 0x1})
        /Users/runner/work/diode_client/diode_client/rpc/client.go:238 +0x197
github.com/diodechain/diode_client/rpc.(*Client).CallContext(0xc0082d5180, {0x48b4750, 0x0}

### Memory Leak

When connecting using two same public keys, they get kicked out forever and for some reason cause a memory leak



### client.go:218

        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:65 +0x53
github.com/dominicletz/genserver.DefaultDeadlockCallback(0xc0065a5c40, {0x0, 0x0})
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:56 +0x1e
github.com/dominicletz/genserver.(*GenServer).handleTimeout(0xc0065a5c40)
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:208 +0x165
github.com/dominicletz/genserver.(*GenServer).Call2Timeout(0xc0065a5c40, 0xc0024958e0, 0x6fc23ac00)
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:144 +0x1c5
github.com/dominicletz/genserver.(*GenServer).CallTimeout(0xc0065a5c40, 0xc00035dec0, 0x4881da0)
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:164 +0x97
github.com/diodechain/diode_client/rpc.(*Client).callTimeout(...)
        /Users/runner/work/diode_client/diode_client/rpc/client.go:218
github.com/diodechain/diode_client/rpc.(*Client).insertCall(0xc006222380, 0xc00219c0f0)
        /Users/runner/work/diode_client/diode_client/rpc/client.go:243 +0xb5
github.com/diodechain/diode_client/rpc.(*Client).CastContext(0x10100000411955e, 0x0, {0x48b4750, 0x8}, {0xc00779ec78, 0x1, 0x1})
        /Users/runner/work/diode_client/diode_client/rpc/client.go:238 +0x197
github.com/diodechain/diode_client/rpc.(*Client).CallContext(0xc006222380, {0x48b4750, 0x3062e5b0}, {0xc003cfc478, 0xc003cfc4b0, 0x401856f})
        /Users/runner/work/diode_client/diode_client/rpc/client.go:261 +0x46
github.com/diodechain/diode_client/rpc.(*Client).GetBlockHeaderUnsafe(0xc001bef950, 0x0)
        /Users/runner/work/diode_client/diode_client/rpc/client.go:429 +0x99
github.com/diodechain/diode_client/rpc.(*Client).GetBlockHeadersUnsafe2.func1(0x38ab2a)
        /Users/runner/work/diode_client/diode_client/rpc/client.go:452 +0xde
created by github.com/diodechain/diode_client/rpc.(*Client).GetBlockHeadersUnsafe2
        /Users/runner/work/diode_client/diode_client/rpc/client.go:450 +0xac



### client.go:218

GenServer WARNING timeout in Client:34100724
GenServer couldn't find Server stacktrace
Client Stacktrace:
goroutine 34100769 [running]:
github.com/dominicletz/genserver.defaultErrorMessage(0xc0043c3280, {0x0, 0xc005e13978})
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:65 +0x53
github.com/dominicletz/genserver.DefaultDeadlockCallback(0x48b37f2, {0x0, 0xc005e13a00})
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:56 +0x1e
github.com/dominicletz/genserver.(*GenServer).handleTimeout(0xc0043c3280)
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:208 +0x165
github.com/dominicletz/genserver.(*GenServer).Call2Timeout(0xc0043c3280, 0xc0003f41b0, 0x6fc23ac00)
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:144 +0x1c5
github.com/dominicletz/genserver.(*GenServer).CallTimeout(0xc0043c3280, 0xc003a832a0, 0x4881da0)
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:164 +0x97
github.com/diodechain/diode_client/rpc.(*Client).callTimeout(...)
        /Users/runner/work/diode_client/diode_client/rpc/client.go:218
github.com/diodechain/diode_client/rpc.(*Client).insertCall(0xc00101d420, 0xc006205270)
        /Users/runner/work/diode_client/diode_client/rpc/client.go:243 +0xb5
github.com/diodechain/diode_client/rpc.(*Client).CastContext(0x101000031e93be8, 0x0, {0x48b4750, 0x8}, {0xc005e13c78, 0x1, 0x1})
        /Users/runner/work/diode_client/diode_client/rpc/client.go:238 +0x197
github.com/diodechain/diode_client/rpc.(*Client).CallContext(0xc00101d420, {0x48b4750, 0x43cf900}, {0xc0056a0c78, 0x4, 0x0})
        /Users/runner/work/diode_client/diode_client/rpc/client.go:261 +0x46
github.com/diodechain/diode_client/rpc.(*Client).GetBlockHeaderUnsafe(0x43e572c, 0x4068940)
        /Users/runner/work/diode_client/diode_client/rpc/client.go:429 +0x99
github.com/diodechain/diode_client/rpc.(*Client).GetBlockHeadersUnsafe2.func1(0x388516)
        /Users/runner/work/diode_client/diode_client/rpc/client.go:452 +0xde
created by github.com/diodechain/diode_client/rpc.(*Client).GetBlockHeadersUnsafe2
        /Users/runner/work/diode_client/diode_client/rpc/client.go:450 +0xac

GenServer WARNING timeout in Client:34101864
GenServer stuck in
goroutine 34101864 [runnable]:
github.com/dominicletz/genserver.(*GenServer).handleTimeout(0xc0003db400)
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:195 +0x6b
github.com/dominicletz/genserver.(*GenServer).Call2Timeout(0xc0003db400, 0xc0010906f0, 0x0)
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:144 +0x1c5
github.com/dominicletz/genserver.(*GenServer).CallTimeout(0xc0003db400, 0xc00546a030, 0x628e38b5)
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:164 +0x97
github.com/dominicletz/genserver.(*GenServer).Call(...)
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:172
github.com/diodechain/diode_client/rpc.(*DataPool).GetContext(0xc000373380)
        /Users/runner/work/diode_client/diode_client/rpc/datapool.go:280 +0x9a
github.com/diodechain/diode_client/rpc.(*Client).doDial(0xc00101dea0)
        /Users/runner/work/diode_client/diode_client/rpc/client.go:148 +0x45
github.com/diodechain/diode_client/rpc.(*Client).doConnect(0xc00101dea0)
        /Users/runner/work/diode_client/diode_client/rpc/client.go:132 +0x25f
github.com/diodechain/diode_client/rpc.(*Client).doStart(0xc00101dea0)
        /Users/runner/work/diode_client/diode_client/rpc/client.go:1092 +0x25
github.com/diodechain/diode_client/rpc.(*Client).Start.func1()
        /Users/runner/work/diode_client/diode_client/rpc/client.go:1073 +0x26
github.com/dominicletz/genserver.(*GenServer).loop(0xc004a3aa00)
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:78 +0x2f
created by github.com/dominicletz/genserver.New
        /Users/runner/go/pkg/mod/github.com/dominicletz/genserver@v1.3.1/genserver.go:49 +0x170


### connectedport.go:242

Crash reported in connectedport.go:242

```
port.isCopying = true
go func() {
	io.Copy(&remoteWriter{port}, port.Conn) <---
	port.Close()
	done <- struct{}{}
}()
```


### client.go:218

ver=207.180.237.112:41046
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0xd0 pc=0x9268f9]

goroutine 1522557 [running]:
github.com/diodechain/diode_client/rpc.(*Client).callTimeout(...)
        /root/diode_client/rpc/client.go:218
github.com/diodechain/diode_client/rpc.(*Client).insertCall(0x0, 0xc00231fb80)
        /root/diode_client/rpc/client.go:243 +0x99
github.com/diodechain/diode_client/rpc.(*Client).CastContext(0x10000c0019fe6d8, 0x0, {0xcfc659, 0x10}, {0xc001e1ee70, 0x3, 0x3})
        /root/diode_client/rpc/client.go:238 +0x197
github.com/diodechain/diode_client/rpc.(*Client).CallContext(0x0, {0xcfc659, 0x14}, {0xc001e1ee70, 0xc001e1ee10, 0xc00022a460})
        /root/diode_client/rpc/client.go:261 +0x46
github.com/diodechain/diode_client/rpc.(*Client).PortOpen(0x3db4d31057848943, {0x37, 0x47, 0x0, 0x68, 0x95, 0x45, 0x25, 0x93, 0x6f, ...}, ...)
        /root/diode_client/rpc/client.go:672 +0x108
github.com/diodechain/diode_client/rpc.(*Server).doConnectDevice.func1({0x37, 0x47, 0x0, 0x68, 0x95, 0x45, 0x25, 0x93, 0x6f, 0x4d, ...}, ...)
        /root/diode_client/rpc/socks.go:369 +0x22f
created by github.com/diodechain/diode_client/rpc.(*Server).doConnectDevice
        /root/diode_client/rpc/socks.go:354 +0x1106


