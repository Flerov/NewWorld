# NewWorld
New World User / Kernel </br>
Uses Shared Memory Section to supply pdb info from user to kernel space </br>
Driver translates virtual to physical </br>
This example is a slightly modified run, where the Base address of the memory mapped section of the user-part is translated </br>
![Alt text](UserPic.png)
![Alt text](WinDbgPic.png)
</br>Command for reference when using the code as-is, to compare the DbgPrint results of translating KeServiceDescriptorTable to !vtop </br>
![Alt text](vtop.png)
