# Talk to your Mifare Classic card

The description will follow



## Mifare Classic family

Some tag facts: 7-byte UID or 4-byte NUID identifier, Individual set of two keys per sector to support multi-application with key hierarchy,
the data is organized in sectors with of 4 blocks each (last / 4th block contains the keys and access rights); each block is 16 bytes long.

Classic mini: 5 sectors with each 4 blocks and 16 bytes block length = 5 * 4 * 16 = 320 bytes user memory, 
usable (1 * 2 * 16) + (4 * 3 * 16) = 224 bytes free memory

Classic 1K:  16 sectors with each 4 blocks and 16 bytes block length = 16 * 4 * 16 = 1024 bytes user memory, 
usable (1 * 2 * 16) + (15 * 3 * 16) = 752 bytes free memory

Classic 4K:  (32 sectors with each 4 blocks + 8 sectors with each 16 blocks) and 16 bytes block length = 4096 bytes user memory, 
usable (1 * 2 * 16) + (31 * 3 * 16) + (8 * 15 * 16) = 3440 bytes free memory 

## Access Control Tool

The complete code of this activity was taken from a library and project called **MIFARE Classic Tool (MCT)** and I 
just changed the layout a little bit. This library is a "swiss knife" for all tasks around Mifare Classic tags and is 
programmed by **Gerhard Klostermeier**, so all credits regarding this activity goes to him. Although it is a very old 
project (created in 2012) it is still under maintenance. The code in the GitHub repository is licensed using the 
**GNU General Public License v3.0** and you can read the full license text using this link:
https://github.com/ikarus23/MifareClassicTool/blob/master/LICENSE.txt

The full library is available here: https://github.com/ikarus23/MifareClassicTool/tree/master

The reason why I'm using this activity is simple: after studying the datasheets regarding this functionality (e.g. 
"Mifare Classic EV1 4K", pages 10 to 13) I got more question than answers and I decided to use a well known library 
for encoding the access conditions. The reason is very simple: *With each memory access the internal logic verifies 
the format of the access conditions. If it detects a format violation the **whole sector is irreversibly blocked**.*.
 
## Additional material

// for details see: https://android.googlesource.com/platform/frameworks/base/+/48a5ed5/core/java/android/nfc/tech/MifareClassic.java
// size could be 320 / SIZE_MINI, 1024 / SIZE_1K, 2048 / SIZE_2K or 4096 / SIZE_4K

Mifare Classic mini: Total memory 320 bytes, MF1ICS20 datasheet: http://www.orangetags.com/wp-content/downloads/datasheet/NXP/MF1ICS20.pdf

Mifare Classic 1K: Total memory 1024 bytes. MF1S50yyX datasheet: https://www.datasheetarchive.com/pdf/download.php?id=bee960138d6124d3df95eb5fbf45fb736c3438&type=P&term=MIFARE%2520Classic%2520Command

Mifare Classic 1K + 4K: Total memory 1024 and 4096 bytes. datasheet: https://shop.sonmicro.com/Downloads/MIFARECLASSIC-UM.pdf

Mifare Classic EV1 1K: Total memory MF1S50YYX_V1 datasheet: https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf

Mifare Classic EV1 4K: Total memory. MF1S70YYX_V1 here: https://www.nxp.com/docs/en/data-sheet/MF1S70YYX_V1.pdf

https://android.googlesource.com/platform/frameworks/base/+/48a5ed5/core/java/android/nfc/tech/MifareClassic.java

