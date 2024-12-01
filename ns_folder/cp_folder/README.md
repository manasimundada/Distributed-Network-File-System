[![Review Assignment Due Date](https://web.iiit.ac.in/~siddharth.mago/images/sweets.png)](https://www.youtube.com/watch?v=bAN3KmTSy2Q&list=PLl4fleEI17jedKXDFRfk0z3KNb6MDpKMG&index=10)

## Assumptions Made

- Any file must have a . extension and folders do not have a '.' in their name
- Assuming maximum cache size is 100, this can be changed by changing the BUFFER_SIZE
- Commands are of a maximum length of 1024 characters, this can be changed by changing the MAX_LENGTH
- A maximum of 100 storage servers can be present at any given moment, this can be changed by changing the MAX_STORAGE_SERVERS
- Each storage server can have a maximum of 1000 paths corresponding to it, this can be changed by changing the MAX_PATH_ENTRIES
- Write is done asynchronously by default if the number of characters is greater than 1024, this can be changed by changing the WRITE_PACKET_SIZE
- 