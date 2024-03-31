# raminspect: Take control of your machine!

`raminspect` is a reverse engineering framework that allows for the inspection and manipulation of the memory and code of a running process on a Linux system. In other words, it gives its users fully unrestricted access to the RAM of their machine, hence the name. 

It provides functions for finding and replacing search terms in a processes' memory, functions for allocating new memory belonging to a process without said process noticing, and an interface that allows for the injection of arbitrary shellcode running in a processes' context. All of this requires root privileges, for obvious reasons. You can find the documentation on [docs.rs](https://docs.rs/raminspect/latest/raminspect).

## Demonstration of Functionality

![262029237-7c55e611-93ff-47cc-8a72-a00840991270](https://github.com/ljgermain/raminspect/assets/154016542/22d59c32-163f-4ba6-8860-89545b64c93e)

### Running an Example

You should be able to run the `firefox_search` example if you have Firefox installed. To do so, start by opening an instance of Firefox and typing "Old search text" in the search bar. If all goes well, when you run the example as root using the command `sudo cargo run --example firefox_search --release`, it should be replaced with "New search text", although you will probably have to click on the search bar again in order for it to render the new text.

## A Note about Memory Allocation and Shellcode Injection

The find and replace functionality is available with or without the kernel module, but if you want to inject shellcode or allocate new buffers you must build and load the prerequisite kernel module first. You can do this by installing your distros' kernel headers package, performing a `git clone` and then running the following commands in the `kern_module` subfolder of the repository (if the build fails for some reason please file an issue):

```bash
make all
sudo insmod raminspect.ko
```

Also note that the shellcode injection is currently designed to work on any architecture, but arbitrary memory allocation is currently limited to x86-64. PRs to add support for arbitrary allocation on more CPU architectures are welcome.

Link to old repository statistics: https://rustrepo.com/repo/a-library-that-allows-for-the-arbitrary-inspection-and-manipulation-of-the-memory-and-code-of-a-process-on-a-linux-system
