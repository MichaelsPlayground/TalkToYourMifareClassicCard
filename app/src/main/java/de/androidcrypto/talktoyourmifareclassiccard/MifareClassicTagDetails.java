package de.androidcrypto.talktoyourmifareclassiccard;

// stores the  details of a Mifare Classic tag

import android.nfc.tech.MifareClassic;
import android.util.Log;

import java.util.Arrays;

public class MifareClassicTagDetails {
    private static final String TAG = MifareClassicTagDetails.class.getName();

    private final MifareClassic mfc;
    private int tagType;
    private int tagSize; // size could be 320 / SIZE_MINI, 1024 / SIZE_1K, 2048 / SIZE_2K or 4096 / SIZE_4K
    // for details on size see: https://android.googlesource.com/platform/frameworks/base/+/48a5ed5/core/java/android/nfc/tech/MifareClassic.java
    private int sectorCount;
    private int blockCount;
    private byte[] uid;
    private String[] techlist;
    private String dump;

    public MifareClassicTagDetails(MifareClassic mfc) {
        this.mfc = mfc;
        if (mfc == null) {
            Log.e(TAG, "mfc is NULL, aborted");
            return;
        }
        analyze();
    }

    private void analyze() {
        // get card details
        tagType = mfc.getType();
        tagSize = mfc.getSize();
        sectorCount = mfc.getSectorCount();
        blockCount = mfc.getBlockCount();
        uid = mfc.getTag().getId();
        techlist = mfc.getTag().getTechList();

        StringBuilder sb = new StringBuilder();
        sb.append("MifareClassic type: ").append(tagType).append("\n");
           sb.append("MifareClassic size: ").append(tagSize).append("\n");

        sb.append("MifareClassic sector count: ").append(sectorCount).append("\n");
        sb.append("MifareClassic block count: ").append(blockCount).append("\n");
        sb.append("Tag UID: ").append(bytesToHexNpe(uid)).append("\n");
        sb.append("Tag Techlist: ").append(Arrays.toString(techlist));
        dump = sb.toString();
    }

    public MifareClassic getMfc() {
        return mfc;
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

    /**
     * section for getters
     */

    public int getTagType() {
        return tagType;
    }

    public int getTagSize() {
        return tagSize;
    }

    public int getSectorCount() {
        return sectorCount;
    }

    public int getBlockCount() {
        return blockCount;
    }

    public byte[] getUid() {
        return uid;
    }

    public String[] getTechlist() {
        return techlist;
    }

    public String getDump() {
        return dump;
    }

}
