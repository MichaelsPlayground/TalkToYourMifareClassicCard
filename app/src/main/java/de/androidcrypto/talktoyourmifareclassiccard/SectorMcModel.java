package de.androidcrypto.talktoyourmifareclassiccard;

import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class SectorMcModel {

    /**
     * this class is for usage with Mifare Classic tags only
     */

    private int sectorNumber;
    private boolean isSector0;
    private boolean isReadableSector;
    private byte[] sectorRead; // complete data, sector 0 first 16 bytes are UID & manufacture info, last 16 bytes is access block, between is blockData
    private byte[] uidData; // contains the UID & manufacture info, only if isSector0 = true
    private byte[] blockData; // contains 2 (if sector 0) or 3 blocks of 16 bytes of data or 15 blocks of 16 bytes data
    private byte[] accessBlock = new byte[16]; // complete block, sections see below. key A and B are nulled as they can't read out
    private byte[] keyA = new byte[6]; // access key A
    private byte[] accessBits = new byte[3]; // 3 access bytes for access to the data elements
    private byte[] unusedByte = new byte[1]; // unused byte, can be used for data
    private byte[] keyB = new byte[6]; // access key B
    private String keyType;
    private boolean dataIsValid = false;
    private byte[] ACCESS_BITS_DEFAULT = Utils.hexStringToByteArray("FF0780");
    private String[] accessConditionsString; // takes the access conditions string for each block
    private boolean isClassicMini = false;
    private boolean isClassic1K = false;
    private boolean isClassic4K = false;
    private boolean isRegularSectorSize = false; // 64 bytes length
    private boolean isExtendedSectorSize = false; // 256 bytes length


    public SectorMcModel(int sectorNumber, boolean isReadableSector, byte[] sectorRead, byte[] uidData, byte[] blockData, byte[] accessBlock, byte[] keyA, byte[] accessBits, byte[] unused, byte[] keyB) {
        dataIsValid = false;
        this.sectorNumber = sectorNumber;
        if (sectorNumber == 0) {
            this.isSector0 = true;
        } else {
            this.isSector0 = false;
        }
        this.isReadableSector = isReadableSector;
        this.sectorRead = sectorRead;
        this.uidData = uidData;
        this.blockData = blockData;
        this.accessBlock = accessBlock;
        this.keyA = keyA;
        this.accessBits = accessBits;
        this.unusedByte = unused;
        this.keyB = keyB;
    }
/*
memory organisation
Classic mini: 5 sectors with each 4 blocks and 16 bytes block length = 5 * 4 * 16 = 320 bytes user memory,
usable (1 * 2 * 16) + (4 * 3 * 16) = 224 bytes free memory

Classic 1K:  16 sectors with each 4 blocks and 16 bytes block length = 16 * 4 * 16 = 1024 bytes user memory,
usable (1 * 2 * 16) + (15 * 3 * 16) = 752 bytes free memory

Classic 4K:  (32 sectors with each 4 blocks + 8 sectors with each 16 blocks) and 16 bytes block length = 4096 bytes user memory,
usable (1 * 2 * 16) + (31 * 3 * 16) + (8 * 15 * 16) = 3440 bytes free memory
 */
    public SectorMcModel(int sectorNumber, byte[] sectorRead, String keyType, byte[] key) {
        dataIsValid = false;
        // sanity checks
        this.sectorNumber = sectorNumber;
        if (sectorNumber == 0) {
            this.isSector0 = true;
        } else {
            this.isSector0 = false;
        }
        if (sectorNumber > 39) {
            return;
        }
        if (sectorRead != null) {
            this.isReadableSector = true;
        } else {
            this.isReadableSector = false;
            return;
        }
        this.keyType = keyType;
        if (keyType.equals(Classic.KEY_TYPE_A)) {
            this.keyA = key.clone();
        } else {
            this.keyB = key.clone();
        }
        // sectorRead length can be (mini 320 bytes) 5 * 4 * 16 bytes, (1k 1024 bytes) 16 * 4 * 16 bytes or (4k 4096 bytes) (16 * 4 * 16) + (8 * 16 * 16 bytes)
        int sectorReadLength = sectorRead.length;
        /*
        if (sectorReadLength == 320) {
            isClassicMini = true;
        } else if (sectorReadLength == 1024) {
            isClassic1K = true;
        } else if (sectorReadLength == 4096) {
            isClassic4K = true;
        } else {
            // undefined or unknown tag type, aborting
            return;
        }

         */
        // a sector can be 4 * 16 bytes = 64 byte (mini or 1K)  or 16 * 16 bytes = 256 bytes (4K)
        if (sectorReadLength == 64) {
            isRegularSectorSize = true;
        } else if (sectorReadLength == 256) {
            isExtendedSectorSize = true;
        } else {
            // undefined sector length, aborting
            return;
        }

        // get the uid + manufacture data
        if (isSector0) {
            uidData = Arrays.copyOf(sectorRead, 16);
            blockData = Arrays.copyOfRange(sectorRead, 16, (sectorReadLength - 16));
            accessBlock = Arrays.copyOfRange(sectorRead, (sectorReadLength - 16), sectorReadLength);
        } else {
            if (sectorNumber < 32) {
                // 1k
                blockData = Arrays.copyOfRange(sectorRead, 0, (sectorReadLength - 16));
                accessBlock = Arrays.copyOfRange(sectorRead, (sectorReadLength - 16), sectorReadLength);
            } else {
                // 4k
                blockData = Arrays.copyOfRange(sectorRead, 0, (sectorReadLength - 16));
                accessBlock = Arrays.copyOfRange(sectorRead, (sectorReadLength - 16), sectorReadLength);
            }
        }
        // analyze the accessBlock
        accessBits = Arrays.copyOfRange(accessBlock, 6, 10); // the accessBits include the unused data
        unusedByte = Arrays.copyOfRange(accessBlock, 9, 10);
        accessConditionsString = new String[16];
        // get the access conditions for each block in the sector
        System.out.println("=== get the access conditions for each block in the sector ===");
        byte[][] GetAccessBitsArray = AccessConditions.GetAccessBitsArray(accessBits);
        for (int blockIndex = 0; blockIndex < 4; blockIndex++) {
            System.out.println("blockIndex: " + blockIndex);
            for (int j = 0; j < 2; j++) {
                System.out.println("j: " + j + Utils.printData(" C", GetAccessBitsArray[j]));
            }
            System.out.println("blockIndex end");

            String acString;
            if (blockIndex == 3) {
                acString = AccessConditions.GetAccessConditionsDescription(GetAccessBitsArray, blockIndex, true);
            } else {
                acString = AccessConditions.GetAccessConditionsDescription(GetAccessBitsArray, blockIndex, false);
            }
            System.out.println("blockIndex: " + blockIndex + " ac: " + acString);
            /*
            if (isSector0) {
                String acString = AccessConditions.GetAccessConditionsDescription(GetAccessBitsArray)
            }

             */
        }

    }

    public String dump() {
        StringBuilder sb = new StringBuilder();
        sb.append("MifareClassic sector: ").append(sectorNumber).append("\n");
        sb.append("isSector0: ").append(isSector0).append("\n");
        sb.append("isReadableSector: ").append(isReadableSector).append("\n");
        if (sectorRead != null) {
            sb.append("sectorRead length: ").append(sectorRead.length).append(" data: ").append(bytesToHexNpe(sectorRead)).append("\n");
        } else {
            sb.append("sectorRead is NULL").append("\n");
        }
        if (uidData != null) {
            sb.append("uidData length: ").append(uidData.length).append(" data: ").append(bytesToHexNpe(uidData)).append("\n");
        } else {
            sb.append("uidData is NULL").append("\n");
        }
        if (blockData != null) {
            sb.append("blockData length: ").append(blockData.length).append(" data: ").append(bytesToHexNpe(blockData)).append("\n");
            sb.append("blockData UTF-8: " + new String(blockData, StandardCharsets.UTF_8)).append("\n");
        } else {
            sb.append("blockData is NULL").append("\n");
        }
        if (accessBlock != null) {
            sb.append("accessBlock length: ").append(accessBlock.length).append(" data: ").append(bytesToHexNpe(accessBlock)).append("\n");
        } else {
            sb.append("accessBlock is NULL").append("\n");
        }
        if (keyA != null) {
            sb.append("keyA length: ").append(keyA.length).append(" data: ").append(bytesToHexNpe(keyA)).append("\n");
        } else {
            sb.append("keyA is NULL").append("\n");
        }
        if (accessBits != null) {
            sb.append("accessBits: ").append(accessBits.length).append(" data: ").append(bytesToHexNpe(accessBits)).append("\n");
        } else {
            sb.append("accessBits is NULL").append("\n");
        }
        if (unusedByte != null) {
            sb.append("unusedByte: ").append(unusedByte.length).append(" data: ").append(bytesToHexNpe(unusedByte)).append("\n");
        } else {
            sb.append("unusedByte is NULL").append("\n");
        }
        if (keyB != null) {
            sb.append("keyB length: ").append(keyB.length).append(" data: ").append(bytesToHexNpe(keyB));
        } else {
            sb.append("keyB is NULL");
        }
        return sb.toString();
    }


    /**
     * converts a byte array to a hex encoded string
     * This method is Null Pointer Exception (NPE) safe
     *
     * @param bytes
     * @return hex encoded string
     */
    private static String bytesToHexNpe(byte[] bytes) {
        if (bytes != null) {
            StringBuffer result = new StringBuffer();
            for (byte b : bytes)
                result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
            return result.toString();
        } else {
            return "";
        }
    }
}
