# Bluebomb

Bluebomb is an exploit for Broadcom's Bluetooth stack used in the Nintendo Wii.

# How do I run it?

__You will need a Linux computer to do this!__
Download the pre-built binaries from the releases page and follow these instructions.
1. Run bluebomb with the arguments to the app-specific payload and the stage1 you would like to run.
    Ex. `sudo ./bluebomb ./stage0/MINI_SM_NTSC.bin stage1.bin` for a NTSC Wii Mini's System Menu.
    You can also specify which hci device to use with bluebomb by adding before the `stage0` and `stage1` arguments.
    Ex. `sudo ./bluebomb 1 ./stage0/MINI_SM_NTSC.bin stage1.bin` to use HCI1.
2. Start your Wii and navigate to the app that you are exploiting, for the System Menu you only need to turn on the Wii, you can leave it sitting on the Health and Safety screen.
3. __Turn OFF your wiimote at this point, do not let anything be connected to the console via bluetooth.__
4. Make sure you console is close to your bluetooth adapter, you may have to move it closer to get it in range, this will depend on your adapter.
5. Click the SYNC button on your console, you may have to click is several times in a row before it sees the computer.
    You will know it is connected when bluebomb prints "Got connection handle: #"
    Stop pushing the SYNC button and wait for bluebomb to run, what happens will depend on what `stage1.bin` you are using.
    The one from this repo will load `boot.elf` off the root of a FAT32 formatted usb drive and run it. You can use the HackMii Installer's boot.elf from [here](https://bootmii.org/download/) to get the Homebrew Channel.

__IMPORTANT__: The steps above will have disabled the bluetooth service on your machine to run the exploit. To enable the bluetooth service again run `sudo systemctl enable --now bluetooth`.

# How do I build it?

1. Run `make` in the `stage0` folder to build stage0.
2. Run `make` in the main folder to generate `bluebomb`.
