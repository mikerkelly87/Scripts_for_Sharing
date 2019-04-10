Weights


-----------------
|  Greenfields  |
-----------------
|-----------|--------------------------------------------------|-----------------|
|Difficulty | Type                                             | Number of Nodes |
|-----------|--------------------------------------------------|-----------------|
|   17      | RPC-R Custom (Storage)                           |        N        |
|   15      | RPC-R                                            |        N        |
|   12      | RPC-O Custom (Storage)                           |        N        |
|   10      | RPC-O                                            |        N        |
|   8       | New Ceph Cluster                                 |        N        |
|-----------|--------------------------------------------------|-----------------|
------------------
| Node Additions |
------------------
|-----------|--------------------------------------------------|-----------------|
|Difficulty | Type                                             | Number of Nodes |
|-----------|--------------------------------------------------|-----------------|
|    6      | Swift Addition                                   |        N        |
|    5      | RPC-O Custom (ie: CAS Cobbler) Compute Addition  |        N        |
|    4      | RPC-O Compute Addition                           |        N        |
|    3      | RPC-O Ceph Node Addition                         |        N        |
|    2      | RPC-R Ceph Node Addition                         |        N        |
|    1      | RPC-R Compute Addition                           |        N        |
|-----------|--------------------------------------------------|-----------------|


Some Examples


|--------------------------------------|
| Difficulty = 80%                     |
| Number of nodes = 20%                |
|                                      |
| (D x .8) + (N x .2)                  |
|                                      |
| 14.6 RPC-R Custom Storage 5 nodes    |
| 14.2 RPC-R 11 nodes                  |
| 10.2 RPC-O Greenfield 10 nodes       |
| 13.2 RPC-O Compute Addition 50 nodes |
| 4.2 RPC-O Compute Addition 5 nodes   |
|--------------------------------------|


|--------------------------------------|
| Difficulty = 90%                     |
| Number of nodes = 10%                |
|                                      |
| (D x .9) + (N x .1)                  |
|                                      |
| 15.8 RPC-R Custom Storage 5 nodes    |
| 14.6 RPC-R 11 nodes                  |
| 10 RPC-O Greenfield 10 nodes         |
| 8.6 RPC-O Compute Addition 50 nodes  |
| 4.1 RPC-O Compute Addition 5 nodes   |
|--------------------------------------|


|--------------------------------------|
| Difficulty = 95%                     |
| Number of nodes = 5%                 |
|                                      |
| (D x .95) + (N x .05)                |
|                                      |
| 16.4 RPC-R Custom Storage 5 nodes    |
| 14.8 RPC-R 11 nodes                  |
| 9.75 RPC-O Greenfield 10 nodes       |
| 6.3 RPC-O Compute Addition 50 nodes  |
| 4.05 RPC-O Compute Addition 5 nodes  |
|--------------------------------------|

