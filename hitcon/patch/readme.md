# Patch script

**This is in development, if you have suggestions. Try contact wtih me**

I used AI to gen this script so it may unstable

- Try command:
```
 ./patch.sh ./binary_file ./libs 
```
- Output 
```
patched:     /home/ctf/challenge
loader:      /home/ctf/libs/ld-2.27.so <ld_version>
RPATH:       /home/ctf/libs
```

Usage:
Automatically patch a given **binary_file** with existed folder **libs** that contain all neccessary files to patch

You can get libs folder by copy from container to local and rename it as **libs**

- In my case, copy all files in folder **/lib/x86_64-linux-gnu**

Use this script when pwninit got errors with library files
