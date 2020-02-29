# BlueBomb

BlueBomb is an exploit for Broadcom's Bluetooth stack used in the Nintendo Wii.

# How do I run it?

__You will need a Linux computer to do this!__
Download the pre-built binaries from the releases page and follow these instructions.
1. Disable your bluetooth service by running `sudo systemctl disable --now bluetooth`
2. Run bluebomb with the arguments to the app-specific payload and the stage1 you would like to run.
    Ex. `sudo ./bluebomb ./stage0/MINI_SM_NTSC.bin stage1.bin` for a NTSC Wii Mini's System Menu.
    You can also specify which hci device to use with bluebomb by adding before the `stage0` and `stage1` arguments.
    Ex. `sudo ./bluebomb 1 ./stage0/MINI_SM_NTSC.bin stage1.bin` to use HCI1.
3. Start your Wii and navigate to the app that you are exploiting, for the System Menu you only need to turn on the Wii, you can leave it sitting on the Health and Safety screen.
4. __Turn OFF your wiimote at this point. DO NOT let anything else connect to the console via bluetooth.__
5. Make sure you console is close to your bluetooth adapter, you may have to move it closer to get it in range, this will depend on your adapter.
6. Click the SYNC button on your console. You may have to click it several times in a row before it sees the computer.
    You will know it is connected when bluebomb prints "Got connection handle: #"
    Stop pushing the SYNC button and wait for bluebomb to run, what happens will depend on what `stage1.bin` you are using.
    The one from this repo will load `boot.elf` off the root of a FAT32 formatted USB drive and run it. You can use the HackMii Installer's boot.elf from [here](https://bootmii.org/download/) to get the Homebrew Channel.

__IMPORTANT__: The steps above will have disabled the bluetooth service on your machine to run the exploit. To enable the bluetooth service again run `sudo systemctl enable --now bluetooth`.

# How do I build it?

1. Run `make` in the `stage0` folder to build stage0.
2. Run `make` in the main folder to generate `bluebomb`.

# Support
You can open an issue on this repo, or join the [Wii Mini Hacking Discord](https://discord.gg/MYm9kB7)
