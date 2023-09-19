package de.androidcrypto.talktoyourmifareclassiccard;

import android.content.Context;

public class AccessConditions {
    // code taken from https://github.com/maxieds/MifareClassicToolLibrary
    // https://github.com/maxieds/MifareClassicToolLibrary/blob/master/MifareClassicToolLibrary/src/main/java/com/maxieds/MifareClassicToolLibrary/MifareClassicToolLibrary.java

    public static Context context; // don't forget to manually set the  context !!

    /**
     * Convert the Access Condition bytes to a matrix containing the
     * resolved C1, C2 and C3 for each block.
     * @param acBytes The Access Condition bytes (3 byte).
     * @return Matrix of access conditions bits (C1-C3) where the first
     * dimension is the "C" parameter (C1-C3, Index 0-2) and the second
     * dimension is the block number (Index 0-3). If the ACs are incorrect
     * null will be returned.
     */

    private static byte[][] ACBytesToACMatrix(byte[] acBytes) {
        // ACs correct?
        // C1 (Byte 7, 4-7) == ~C1 (Byte 6, 0-3) and
        // C2 (Byte 8, 0-3) == ~C2 (Byte 6, 4-7) and
        // C3 (Byte 8, 4-7) == ~C3 (Byte 7, 0-3)
        byte[][] acMatrix = new byte[3][4];
        if (acBytes.length > 2 &&
                (byte)((acBytes[1]>>>4)&0x0F)  ==
                        (byte)((acBytes[0]^0xFF)&0x0F) &&
                (byte)(acBytes[2]&0x0F) ==
                        (byte)(((acBytes[0]^0xFF)>>>4)&0x0F) &&
                (byte)((acBytes[2]>>>4)&0x0F)  ==
                        (byte)((acBytes[1]^0xFF)&0x0F)) {
            // C1, Block 0-3
            for (int i = 0; i < 4; i++) {
                acMatrix[0][i] = (byte)((acBytes[1]>>>4+i)&0x01);
            }
            // C2, Block 0-3
            for (int i = 0; i < 4; i++) {
                acMatrix[1][i] = (byte)((acBytes[2]>>>i)&0x01);
            }
            // C3, Block 0-3
            for (int i = 0; i < 4; i++) {
                acMatrix[2][i] = (byte)((acBytes[2]>>>4+i)&0x01);
            }
            return acMatrix;
        }
        return null;
    }

    public static byte[][] GetAccessBitsArray(byte[] accessBytes) {
        if(accessBytes.length != 4) {
            return null;
        }
        return ACBytesToACMatrix(accessBytes);
    }

    public static String GetAccessConditionsDescription(byte[][] sectorAccessBits, int blockIndex, boolean isSectorTrailer) {
        if(sectorAccessBits == null || blockIndex < 0 || blockIndex >= sectorAccessBits[0].length) {
            return "";
        }
        int accessBitsNumber = (sectorAccessBits[0][blockIndex] << 2) | (sectorAccessBits[1][blockIndex] << 1) | sectorAccessBits[0][blockIndex];
        String resAccessCondsPrefix = isSectorTrailer ? "ac_sector_trailer_" : "ac_data_block_";
        String accessCondsResIdStr = resAccessCondsPrefix + accessBitsNumber;
        //Context appContext = getApplicationContext();
        try {
            int accessCondsResId = R.string.class.getField(accessCondsResIdStr).getInt(null);
            return context.getResources().getString(accessCondsResId);
        } catch(Exception nsfe) {
            return "";
        }
    }
}
