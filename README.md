# Bluebomb

Bluebomb is an exploit for Broadcom's Bluetooth stack used in the Nintendo Wii.

# How do I run it?

__You will need a Linux computer to do this!__
Download the pre-built binaries from the releases page and follow these instructions.
1. Download BlueZ from [here](http://www.bluez.org/download/), you just need the user space package.
2. Extract it and run build it with `./configure --enable-deprecated && make` (If you are using Ubuntu, you might need to install some needed packages with `sudo apt install libglib2.0-dev libdbus-1-dev libudev-dev libical-dev libreadline-dev` before this works)
3. Enter the `tools` directory and run `sudo systemctl disable --now bluetooth`
4. Run `sudo ./btmgmt`
5. Run the following commands in the managment prompt
    `select 0`
    `info`
    If you get an error about `Invalid index` then Linux can't find a Bluetooth device on your computer, if one real hardware make sure you have firmware for your bluetooth adapater, __if in a VM make sure you have passed through the device.__
    Assuming the above does not happen then you can continue.
    `power on`
    `connectable on`
    `bondable on`
    `discov on`
    `info`
    You should now look at the `info` results and check the `current settings` line for the following:
    `powered connectable discoverable bondable br/edr`
    If you don't have one of the above settings in your list, make sure you executed all the above commands.
    You can now `exit` out of the managment prompt.
6. Run `sudo ./hciconfig hci0 iac liac`
7. Run bluebomb with the arguments to the app-specific payload and the stage1 you would like to run.
    Ex. `sudo ./bluebomb ./stage0/MINI_SM_NTSC.bin stage1.bin` for a NTSC Wii Mini's System Menu.
    You can also specify which hci device to use with bluebomb by adding before the `stage0` and `stage1` arguments.
    Ex. `sudo ./bluebomb 1 ./stage0/MINI_SM_NTSC.bin stage1.bin` to use HCI1.
8. Start you Wii and navigate to the app that you are exploiting, for the System Menu you only need to turn on the Wii, you can leave it sitting on the Health and Safety screen.
9. __Turn OFF your wiimote at this point, do not let anything be connected to the console via bluetooth.__
10. Make sure you console is close to your bluetooth adapater, you may have to move it closer to get it in range, this will depend on your adapater.
11. Click the SYNC button on your console, you may have to click is several times in a row before it sees the computer.
    You will know it is connected when bluebomb prints "Got connection handle: #"
    Stop pushing the SYNC button and wait for bluebomb to run, what happens will depend on what `stage1.bin` you are using.
    The one from this repo will load `boot.elf` off the root of a FAT32 formatted usb drive and run it. You can use the HackMii Installer's boot.elf from [here](https://bootmii.org/download/) to get the Homebrew Channel.

__IMPORTANT__: The steps above will have disabled the bluetooth service on your machine to run the exploit. To enable the bluetooth service again run `sudo systemctl enable --now bluetooth`.

# How do I build it?

1. Run `make` in the main folder to generate `bluebomb`.
2. Run `make` in the `stage0` folder to generate the app-specific payloads.
3. `stage1.bin` is not yet user buildable, this repo will be updated with instructions on how to build it when it is done.

# How do I create an app-specific stage0?

You will need to locate several addresses in memory from the app, dolphin is very helpful here.
Create a copy of one of the existing app lds files and name it something identifiying like `GAMEID.lds`
Open up the app in dolphin and choose Symbols->Generate Symbols From->Signature Database.
Locate the `sdp_init`, `l2c_init`, and `process_l2cap_cmd` functions (use the Filter Symbols field)
Open up your app in some RE tool (ghidra works well).
For `sdp_init` the first function call to `memset` the first argument is the `sdp_cb` address that you need.
Next go to `l2c_init` and just like before the first function call is `memset` and the first argument is `l2cb`.
The `switch_address` is slightly more complicated. Go to the `process_l2cap_cmd` function and find the `switch` statement. Right before the `mtspr CTR,rx ; btr` instructions there will be a `lwzx rx, rx, rx` instruction, if your RE tool knows the location of the switch addresses it might show it, if not you will have to track the registers and find the address list that this `lwzx` instruction is pulling from. Once you find the list, go to the last address in it, it should be right before a string "L2CAP HOLD CONTINUE", the *address* of this *address* in the list is what you want. Not the address of the code that the switch statement is jumping to. This address is your `switch_address`.
Finally you need the `switch_break` address, this is address of the call to `l2cu_reject_connection` in case 2 of the switch statment from `process_l2cap_cmd`. There are two calls to it in case 2, you may use either one, simply get the address of the `bl l2cu_reject_connection` instruction and that is your `switch_break`.

After placing all these values into the lds file you can also choose a `payload_addr`. This field is where the `stage1.bin` will be read into when the exploit runs, you __WILL__ have to adjust this to a memory region that isn't in use by your app when the exploit is running. If unsure you can try something like 512kb before the end of mem1 (0x81780000). Please note the addresses used in the System Menu lds files will not work for any other app, so don't try to copy this address and paste it another app.
