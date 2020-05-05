# s8_2019_2215_poc
PoC 2019-2215 exploit for S8/S8 active with DAC + SELinux + Knox/RKP bypass

Tested on S8/S8 active Snapdragon device running vulnerable Oreo firmware. 
Needs modification (see `kernel_defs.h`) to run on other vulnerable Samsung devices. 
Let me know if you do this and it works for you! 

`usage: s8_poc [options]`

`-s        | pop a privileged shell`

`-p <path> | path of sepolicy to inject. if none, default policy is created`

`-r <path> | remount rootfs as r/w and copy file at <path>, execute as root`


Example usage:

`./s8_poc -s`

You will be dropped into a shell with all DAC permissions (NOT USER ROOT). A new SEpolicy is injected to give some permissions I needed to debug + the ability to load a new SEPolicy. From what I can tell, permissive policies/contexts aren't honored on these devices, so you do need to add a custom SEPolicy for specific permissions. A tool like `sepolicy-inject` is perfect for this, and is easy to use. Find it here: https://github.com/xmikos/setools-android. See pictures below for example use. Alternatively, recompile the POC with the needed permissions added to the function `add_rules_to_sepolicy` in `poc/selinux_bypass.c`. You can do pretty much anything with this shell. 

`./s8_poc -s -r <path>`

Drops into a privileged shell, remounts rootfs as r/w, copies the file over, and executes the file at `<path>` as root, in the kernel SELinux context. Keep in mind, you WILL kernel panic if you try to execute anything out of the `/data/` partition as root. This part of the "Real Kernel Proctection" component of Samsung Knox. So if the ELF is a reverse shell type thing, and you choose to execute something out of `/data`, bad times will incur. Stick to the privileged shell to execute out of `/data`, or copy what you need over to rootfs. 

`./s8_poc -p <path>`

Inject selinux policy at `<path>`. Note, you don't need to do this if you're already in a privileged shell using the default SELinux setting, as you will already have the permissions needed to do this. Just write your policy to `/sys/fs/selinux/load`, or use a tool like `sepolicy-inject` to create a policy with the permissions you need and load it.


Known issues:

The kallsyms code is kind of slow. If you run the exploit and it seems like it's hanging, just give it a second, as it is probably just searching for a symbol. In a small percentage of test cases, there is a failure in finding the kallsyms table. If that's the case, just reboot the phone and try again. 

It's pretty safe to run this, as the worst that can happen is a kernel panic and your phone reboots. But if your phone catchse fire, I am not responsible. Use this at your own risk. 

The KNOX/RKP bypass can be repurposed to remount any r/o partitions mounted with `MNT_LOCK_READONLY`. It would be an interesting experiment to see what can be done with this and how far this temp root can be taken. If you do something cool, let me know! If you do try this, you had better know what you are doing. You CAN brick your phone if you're not careful, and again, I am not resposible! All in the name of research, right? ;)

Shown in action:


![Alt text](images/example_usage.png?raw=true "Title")
![Alt text](images/root_lol.png?raw=true "Title")
![Alt text](images/selinux_load.png?raw=true "Title")